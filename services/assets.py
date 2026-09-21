import ipaddress
import json
from datetime import datetime, timezone

from database.db import get_connection


ASSET_TYPES = {"server", "laptop", "domain", "public_ip", "cloud", "application", "user", "network_device", "business_system"}
CRITICALITIES = {"low", "medium", "high", "critical"}
STATUSES = {"active", "inactive", "unknown"}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _clean_ip(value):
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as error:
        raise ValueError("ip_address must be a valid IPv4 or IPv6 address") from error


def _normalize(payload, existing=None):
    existing = existing or {}
    name = str(payload.get("name", existing.get("name", ""))).strip()
    if not name:
        raise ValueError("name is required")
    asset_type = str(payload.get("asset_type", existing.get("asset_type", "server"))).lower()
    criticality = str(payload.get("criticality", existing.get("criticality", "medium"))).lower()
    status = str(payload.get("status", existing.get("status", "active"))).lower()
    if asset_type not in ASSET_TYPES:
        raise ValueError(f"asset_type must be one of: {', '.join(sorted(ASSET_TYPES))}")
    if criticality not in CRITICALITIES:
        raise ValueError(f"criticality must be one of: {', '.join(sorted(CRITICALITIES))}")
    if status not in STATUSES:
        raise ValueError(f"status must be one of: {', '.join(sorted(STATUSES))}")
    tags = payload.get("tags", existing.get("tags", []))
    if isinstance(tags, str):
        tags = [item.strip() for item in tags.split(",") if item.strip()]
    if not isinstance(tags, list):
        raise ValueError("tags must be an array or comma-separated string")
    return {
        "name": name[:160],
        "asset_type": asset_type,
        "hostname": str(payload.get("hostname", existing.get("hostname") or ""))[:160] or None,
        "ip_address": _clean_ip(payload.get("ip_address", existing.get("ip_address"))),
        "domain": str(payload.get("domain", existing.get("domain") or ""))[:255] or None,
        "environment": str(payload.get("environment", existing.get("environment", "production")))[:40],
        "criticality": criticality,
        "owner": str(payload.get("owner", existing.get("owner") or ""))[:120] or None,
        "status": status,
        "last_seen": payload.get("last_seen", existing.get("last_seen")),
        "tags": json.dumps([str(item)[:40] for item in tags]),
    }


def list_assets():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM assets ORDER BY CASE criticality WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, name").fetchall()
    conn.close()
    result = []
    for row in rows:
        item = dict(row)
        try:
            item["tags"] = json.loads(item.get("tags") or "[]")
        except json.JSONDecodeError:
            item["tags"] = []
        result.append(item)
    return result


def create_asset(payload):
    asset = _normalize(payload)
    now = _now()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO assets
        (name, asset_type, hostname, ip_address, domain, environment, criticality, owner, status, last_seen, tags, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (*[asset[key] for key in ("name", "asset_type", "hostname", "ip_address", "domain", "environment", "criticality", "owner", "status", "last_seen", "tags")], now, now),
    )
    asset_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return get_asset(asset_id)


def get_asset(asset_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
    conn.close()
    if not row:
        return None
    item = dict(row)
    try:
        item["tags"] = json.loads(item.get("tags") or "[]")
    except json.JSONDecodeError:
        item["tags"] = []
    return item


def update_asset(asset_id, payload):
    current = get_asset(asset_id)
    if not current:
        return None
    asset = _normalize(payload, current)
    now = _now()
    conn = get_connection()
    conn.execute(
        """
        UPDATE assets SET name=?, asset_type=?, hostname=?, ip_address=?, domain=?, environment=?, criticality=?, owner=?, status=?, last_seen=?, tags=?, updated_at=?
        WHERE id=?
        """,
        (*[asset[key] for key in ("name", "asset_type", "hostname", "ip_address", "domain", "environment", "criticality", "owner", "status", "last_seen", "tags")], now, asset_id),
    )
    conn.commit()
    conn.close()
    return get_asset(asset_id)


def delete_asset(asset_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    return deleted


def find_asset_by_ip(ip_address):
    if not ip_address:
        return None
    conn = get_connection()
    row = conn.execute("SELECT * FROM assets WHERE ip_address = ? AND status = 'active' LIMIT 1", (ip_address,)).fetchone()
    conn.close()
    return dict(row) if row else None
