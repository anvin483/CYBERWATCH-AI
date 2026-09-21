import json
from datetime import datetime, timezone

from services.feed_manager import get_attacks_from_db
from services.incident_analyzer import get_incident, get_incidents
from services.sensor_adapters import adapt_event
from services.sensor_ingest import ingest_events


def test_suricata_replay_becomes_incident_and_marker(isolated_db):
    raw = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "alert",
        "src_ip": "198.51.100.44",
        "dest_ip": "192.0.2.44",
        "src_port": 44321,
        "dest_port": 22,
        "alert": {"signature": "ET SCAN SSH Brute Force", "severity": 1},
        "sensor": "suricata-replay",
    }
    event = adapt_event(raw)
    result = ingest_events({"events": [event]})
    assert result["accepted"] == 1
    assert result["deduplicated"] == 0

    duplicate = ingest_events({"events": [event]})
    assert duplicate["accepted"] == 0
    assert duplicate["deduplicated"] == 1

    incidents = get_incidents()
    assert len(incidents) == 1
    incident = get_incident(incidents[0]["id"])
    assert incident["technique_id"] == "T1110"
    assert incident["event_count"] == 1
    assert incident["evidence"]
    assert get_attacks_from_db()[0]["sourceKind"] == "local_sensor"
    assert get_attacks_from_db()[0]["scope"] == "local detection"
