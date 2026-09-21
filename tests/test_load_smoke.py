import time

from services.sensor_ingest import ingest_events


def test_batch_sensor_replay_stays_bounded(isolated_db):
    events = [{
        "event_type": "intrusion",
        "signature": f"Replay detection {index}",
        "severity": "low",
        "src_ip": f"198.51.100.{index + 1}",
        "dest_ip": "192.0.2.50",
        "source": "load-replay",
        "timestamp": f"2026-09-20T10:00:{index:02d}Z",
    } for index in range(50)]
    started = time.perf_counter()
    result = ingest_events({"events": events})
    elapsed = time.perf_counter() - started
    assert result["accepted"] == 50
    assert elapsed < 10
