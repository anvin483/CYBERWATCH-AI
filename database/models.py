from database.db import get_connection, is_postgres


def _ensure_columns(cursor, table, columns):
    if is_postgres():
        cursor.execute("SELECT column_name AS name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = %s", (table,))
    else:
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

    _ensure_columns(cursor, "attacks", {
        "created_at": "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP",
        "asset_id": "INTEGER",
        "source_ip": "TEXT",
        "target_ip": "TEXT",
        "signature": "TEXT",
        "enrichment": "TEXT",
        "dedupe_key": "TEXT",
    })

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fingerprint TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'medium',
            confidence INTEGER NOT NULL DEFAULT 50,
            technique_id TEXT,
            technique_name TEXT,
            status TEXT NOT NULL DEFAULT 'new',
            source_ip TEXT,
            target_ip TEXT,
            asset_id INTEGER,
            event_count INTEGER NOT NULL DEFAULT 1,
            evidence TEXT NOT NULL DEFAULT '[]',
            recommendations TEXT NOT NULL DEFAULT '[]',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    _ensure_columns(cursor, "incidents", {
        "assigned_to": "TEXT",
        "notes": "TEXT",
        "closure_reason": "TEXT",
        "enrichment": "TEXT NOT NULL DEFAULT '{}'",
        "ai_analysis": "TEXT NOT NULL DEFAULT '{}'",
    })
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            author TEXT NOT NULL DEFAULT 'analyst',
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            message TEXT NOT NULL,
            actor TEXT NOT NULL DEFAULT 'system',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents(last_seen)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attacks_created_at ON attacks(created_at)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attacks_source_ip ON attacks(source_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attacks_target_ip ON attacks(target_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attacks_asset_id ON attacks(asset_id)")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER,
            channel TEXT NOT NULL,
            status TEXT NOT NULL,
            message TEXT,
            response_code INTEGER,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS response_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            target TEXT,
            status TEXT NOT NULL DEFAULT 'pending_approval',
            requested_by TEXT NOT NULL DEFAULT 'analyst',
            approved_by TEXT,
            details TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            approved_at TEXT,
            executed_at TEXT
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alert_deliveries_incident ON alert_deliveries(incident_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_response_actions_incident ON response_actions(incident_id)")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sensor_heartbeats (
            sensor_id TEXT PRIMARY KEY,
            last_seen TEXT NOT NULL,
            event_count INTEGER NOT NULL DEFAULT 0,
            source TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT,
            details TEXT NOT NULL DEFAULT '{}',
            ip_address TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)")
    cursor.execute("INSERT OR IGNORE INTO schema_version (version) VALUES (1)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at)")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            asset_type TEXT NOT NULL DEFAULT 'server',
            hostname TEXT,
            ip_address TEXT,
            domain TEXT,
            environment TEXT NOT NULL DEFAULT 'production',
            criticality TEXT NOT NULL DEFAULT 'medium',
            owner TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            last_seen TEXT,
            tags TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status)")

    conn.commit()
    conn.close()
