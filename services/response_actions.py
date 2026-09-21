import json
import os
from datetime import datetime, timezone

import requests

from database.db import get_connection
from services.incident_analyzer import get_incident


ALLOWED_ACTIONS = {"block_ip", "disable_user", "isolate_endpoint", "create_ticket"}


def _now():
    return datetime.now(timezone.utc).isoformat()


def request_action(incident_id, action_type, target, requested_by="analyst", details=None):
    if not get_incident(incident_id):
        return None
    action_type = str(action_type or "").lower()
    if action_type not in ALLOWED_ACTIONS:
        raise ValueError(f"action_type must be one of: {', '.join(sorted(ALLOWED_ACTIONS))}")
    target = str(target or "").strip()[:255]
    if not target:
        raise ValueError("target is required")
    conn = get_connection()
    cursor = conn.execute(
        "INSERT INTO response_actions (incident_id, action_type, target, status, requested_by, details, created_at) VALUES (?, ?, ?, 'pending_approval', ?, ?, ?)",
        (incident_id, action_type, target, str(requested_by or "analyst")[:120], json.dumps(details or {}), _now()),
    )
    conn.execute("INSERT INTO incident_timeline (incident_id, event_type, message, actor, created_at) VALUES (?, ?, ?, ?, ?)", (incident_id, "response_requested", f"Response action requested: {action_type} for {target}.", requested_by, _now()))
    conn.commit()
    row = conn.execute("SELECT * FROM response_actions WHERE id = ?", (cursor.lastrowid,)).fetchone()
    conn.close()
    return dict(row)


def list_actions(incident_id):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM response_actions WHERE incident_id = ? ORDER BY id DESC", (incident_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def approve_action(action_id, approved_by="analyst"):
    conn = get_connection()
    row = conn.execute("SELECT * FROM response_actions WHERE id = ?", (action_id,)).fetchone()
    if not row:
        conn.close()
        return None
    if row["status"] != "pending_approval":
        conn.close()
        raise ValueError("only pending actions can be approved")
    now = _now()
    executor = os.environ.get("RESPONSE_ACTION_WEBHOOK_URL")
    status = "approved_pending_executor"
    message = "Approved; no response executor is configured."
    if executor:
        try:
            response = requests.post(executor, json={"action": dict(row), "approved_by": approved_by}, timeout=8)
            response.raise_for_status()
            status, message = "executed", "Response executor accepted the action."
        except requests.RequestException as error:
            status, message = "execution_failed", str(error)
    conn.execute("UPDATE response_actions SET status=?, approved_by=?, approved_at=?, executed_at=? WHERE id=?", (status, approved_by[:120], now, now if status == "executed" else None, action_id))
    conn.execute("INSERT INTO incident_timeline (incident_id, event_type, message, actor, created_at) VALUES (?, ?, ?, ?, ?)", (row["incident_id"], "response_approved", message, approved_by, now))
    conn.commit()
    updated = conn.execute("SELECT * FROM response_actions WHERE id = ?", (action_id,)).fetchone()
    conn.close()
    return dict(updated)
