import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_NAME = BASE_DIR / "cyberwatch.db"


def get_connection():

    conn = sqlite3.connect(DB_NAME)
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("PRAGMA synchronous=OFF")

    conn.row_factory = sqlite3.Row

    return conn
