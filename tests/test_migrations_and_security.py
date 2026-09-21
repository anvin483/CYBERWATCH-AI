def test_schema_is_idempotent(isolated_db):
    from database.models import create_tables
    create_tables()
    import sqlite3
    connection = sqlite3.connect(isolated_db)
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    connection.close()
    assert {"schema_version", "audit_logs", "sensor_heartbeats", "response_actions"}.issubset(tables)


def test_sensor_token_rejects_invalid_value(isolated_db):
    from services.sensor_ingest import sensor_token_valid
    assert sensor_token_valid("test-sensor-token")
    assert not sensor_token_valid("wrong-token")
