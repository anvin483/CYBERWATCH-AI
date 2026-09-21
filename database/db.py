import sqlite3
import os
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_NAME = BASE_DIR / "cyberwatch.db"


def is_postgres():
    return os.environ.get("DATABASE_URL", "").startswith(("postgres://", "postgresql://"))


def _postgres_sql(sql):
    sql = re.sub(r"\bINTEGER PRIMARY KEY AUTOINCREMENT\b", "SERIAL PRIMARY KEY", sql, flags=re.IGNORECASE)
    sql = re.sub(r"\bINSERT\s+OR\s+IGNORE\s+INTO\b", "INSERT INTO", sql, flags=re.IGNORECASE)
    if re.search(r"INSERT INTO\s+schema_version", sql, flags=re.IGNORECASE):
        sql = sql.rstrip().rstrip(";") + " ON CONFLICT DO NOTHING"
    return sql.replace("?", "%s")


class _Cursor:
    def __init__(self, cursor, postgres=False):
        self._cursor = cursor
        self._postgres = postgres

    def execute(self, sql, params=()):
        return self._cursor.execute(_postgres_sql(sql) if self._postgres else sql, params)

    def executemany(self, sql, params):
        return self._cursor.executemany(_postgres_sql(sql) if self._postgres else sql, params)

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class _Connection:
    def __init__(self, connection, postgres=False):
        self._connection = connection
        self._postgres = postgres

    def cursor(self):
        return _Cursor(self._connection.cursor(), self._postgres)

    def execute(self, sql, params=()):
        return _Cursor(self._connection.cursor(), self._postgres).execute(sql, params)

    def __getattr__(self, name):
        return getattr(self._connection, name)


def get_connection():
    if is_postgres():
        try:
            from psycopg import connect
            from psycopg.rows import dict_row
        except ImportError as error:
            raise RuntimeError("DATABASE_URL is PostgreSQL but psycopg is not installed") from error
        return _Connection(connect(os.environ["DATABASE_URL"], row_factory=dict_row), postgres=True)
    conn = sqlite3.connect(DB_NAME)
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("PRAGMA synchronous=OFF")

    conn.row_factory = sqlite3.Row

    return _Connection(conn)
