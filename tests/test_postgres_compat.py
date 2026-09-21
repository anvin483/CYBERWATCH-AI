from database.db import _postgres_sql


def test_postgres_sql_translation_handles_schema_and_parameters():
    sql = _postgres_sql("CREATE TABLE x (id INTEGER PRIMARY KEY AUTOINCREMENT); INSERT OR IGNORE INTO schema_version (version) VALUES (?)")
    assert "SERIAL PRIMARY KEY" in sql
    assert "INSERT INTO schema_version" in sql
    assert "%s" in sql
    assert "ON CONFLICT DO NOTHING" in sql
