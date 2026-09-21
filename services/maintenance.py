import os
from datetime import datetime, timedelta, timezone

from database.db import get_connection


def apply_retention():
    days = max(1, int(os.environ.get("RETENTION_DAYS", "90")))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    conn = get_connection()
    deleted = {}
    for table, column in (("events", "created_at"), ("attacks", "created_at"), ("audit_logs", "created_at"), ("alert_deliveries", "created_at")):
        cursor = conn.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff,))
        deleted[table] = cursor.rowcount
    conn.commit()
    conn.close()
    return {"retentionDays": days, "deleted": deleted, "cutoff": cutoff}
