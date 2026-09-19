from database.db import get_connection


def _ensure_columns(cursor, table, columns):
    cursor.execute(f"PRAGMA table_info({table})")
    existing = {row["name"] for row in cursor.fetchall()}
    for name, definition in columns.items():
        if name not in existing:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'UNKNOWN',
            cvss REAL NOT NULL DEFAULT 0,
            vendor TEXT NOT NULL DEFAULT 'Unknown',
            product TEXT NOT NULL DEFAULT 'Unknown',
            published TEXT,
            exploited INTEGER NOT NULL DEFAULT 0,
            added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    _ensure_columns(cursor, "cves", {
        "severity": "TEXT NOT NULL DEFAULT 'UNKNOWN'",
        "cvss": "REAL NOT NULL DEFAULT 0",
        "vendor": "TEXT NOT NULL DEFAULT 'Unknown'",
        "product": "TEXT NOT NULL DEFAULT 'Unknown'",
        "published": "TEXT",
        "exploited": "INTEGER NOT NULL DEFAULT 0",
        "added_at": "TEXT NOT NULL DEFAULT ''",
    })

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ransomware (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            victim TEXT NOT NULL,
            group_name TEXT NOT NULL,
            country TEXT NOT NULL DEFAULT 'Unknown',
            sector TEXT NOT NULL DEFAULT 'Unknown',
            discovered TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    _ensure_columns(cursor, "ransomware", {
        "id": "INTEGER",
        "country": "TEXT NOT NULL DEFAULT 'Unknown'",
        "sector": "TEXT NOT NULL DEFAULT 'Unknown'",
        "discovered": "TEXT NOT NULL DEFAULT ''",
    })

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            source TEXT NOT NULL DEFAULT 'Cyberwatch',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_country TEXT NOT NULL,
            target_country TEXT NOT NULL,
            source_lat REAL NOT NULL,
            source_lng REAL NOT NULL,
            target_lat REAL NOT NULL,
            target_lng REAL NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
