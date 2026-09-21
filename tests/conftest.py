import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from database import db


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_NAME", tmp_path / "test.db")
    monkeypatch.setenv("SENSOR_INGEST_TOKEN", "test-sensor-token")
    from database.models import create_tables
    create_tables()
    return db.DB_NAME
