import json
from datetime import datetime, timezone

from database.db import get_connection


def record(actor, action, resource=None, details=None, ip_address=None):
    conn = get_connection()
    conn.execute(
        "INSERT INTO audit_logs (actor, action, resource, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (str(actor or "system")[:120], str(action)[:120], str(resource or "")[:255], json.dumps(details or {}), ip_address, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()


def recent(limit=100):
    conn = get_connection()
    rows = conn.execute("SELECT actor, action, resource, details, ip_address, created_at FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]
