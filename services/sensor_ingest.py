import ipaddress
import hmac
import json
import os
import hashlib
from datetime import datetime, timezone

from database.db import get_connection
from services.feed_manager import COUNTRY_COORDS, _coords, insert_event
from services.sensor_adapters import adapt_event
from services.assets import find_asset_by_ip
from services.enrichment import enrich_ip


SEVERITIES = {"info", "low", "medium", "high", "critical"}


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _country(value, default="Unknown"):
    return str(value or default)[:80]


def _safe_ip(value):
    try:
        ipaddress.ip_address(str(value))
        return str(value)
    except (ValueError, TypeError):
        return None


def _normalize(item):
    source_ip = _safe_ip(item.get("src_ip") or item.get("source_ip") or item.get("sourceIp"))
    target_ip = _safe_ip(item.get("dest_ip") or item.get("dst_ip") or item.get("target_ip") or item.get("targetIp"))
    source_enrichment = enrich_ip(source_ip)
    target_enrichment = enrich_ip(target_ip)
    source_enrichment.update({
        "threatActor": item.get("threat_actor") or item.get("threatActor"),
        "malwareFamily": item.get("malware_family") or item.get("malwareFamily"),
        "relatedCves": item.get("related_cves") or item.get("relatedCves") or [],
    })
    source_country = _country(item.get("src_country") or item.get("source_country") or source_enrichment.get("country"), "Unknown")
    target_country = _country(item.get("dest_country") or item.get("target_country") or target_enrichment.get("country"), "Unknown")
    category = str(item.get("category") or item.get("event_type") or "sensor").lower()[:40]
    severity = str(item.get("severity") or "medium").lower()
    if severity not in SEVERITIES:
        severity = "medium"

    signature = item.get("signature") or item.get("alert") or item.get("title") or "Network detection"
    source = item.get("source") or item.get("sensor") or "Cyberwatch Sensor"
    created_at = item.get("timestamp") or item.get("created_at") or _utc_now()
    source_lat = item.get("src_lat") or source_enrichment.get("latitude")
    source_lng = item.get("src_lng") or source_enrichment.get("longitude")
    target_lat = item.get("dest_lat") or target_enrichment.get("latitude")
    target_lng = item.get("dest_lng") or target_enrichment.get("longitude")
    if source_lat is None or source_lng is None:
        source_lat, source_lng = _coords(source_country)
    if target_lat is None or target_lng is None:
        target_lat, target_lng = _coords(target_country)

    return {
        "title": str(signature)[:240],
        "event_type": category,
        "severity": severity,
        "source": str(source)[:80],
        "created_at": str(created_at),
        "source_ip": source_ip,
        "target_ip": target_ip,
        "source_country": source_country,
        "target_country": target_country,
        "source_lat": float(source_lat),
        "source_lng": float(source_lng),
        "target_lat": float(target_lat),
        "target_lng": float(target_lng),
        "enrichment": {"source": source_enrichment, "target": target_enrichment},
    }


def ingest_events(payload):
    raw_events = payload.get("events") if isinstance(payload, dict) else None
    if raw_events is None:
        raw_events = [payload]
    if not isinstance(raw_events, list) or len(raw_events) > 100:
        raise ValueError("events must be an array with at most 100 items")

    accepted = []
    for raw in raw_events:
        if not isinstance(raw, dict):
            continue
        event = _normalize(adapt_event(raw))
        insert_event(
            event["event_type"],
            event["title"],
            event["severity"],
            event["source"],
            event["created_at"],
        )
        accepted.append(event)

    if not accepted:
        raise ValueError("at least one valid event is required")

    conn = get_connection()
    cursor = conn.cursor()
    matched_assets = 0
    deduplicated = 0
    sensor_ids = set()
    for event in accepted:
        sensor_id = str(event["source"] or "unknown")[:120]
        sensor_ids.add(sensor_id)
        asset = find_asset_by_ip(event["target_ip"])
        if asset:
            matched_assets += 1
        dedupe_key = hashlib.sha256(json.dumps({key: event.get(key) for key in ("source_ip", "target_ip", "title", "created_at")}, sort_keys=True).encode()).hexdigest()
        existing = cursor.execute("SELECT id FROM attacks WHERE dedupe_key = ?", (dedupe_key,)).fetchone()
        if existing:
            deduplicated += 1
            continue
        cursor.execute(
            """
            INSERT INTO attacks
            (source_country, target_country, source_lat, source_lng,
             target_lat, target_lng, category, severity, created_at, asset_id,
             source_ip, target_ip, signature, enrichment, dedupe_key)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["source_country"], event["target_country"],
                event["source_lat"], event["source_lng"],
                event["target_lat"], event["target_lng"],
                event["event_type"], event["severity"], event["created_at"],
                asset["id"] if asset else None,
                event["source_ip"], event["target_ip"], event["title"],
                json.dumps(event["enrichment"]),
                dedupe_key,
            ),
        )
        cursor.execute(
            "INSERT INTO sensor_heartbeats (sensor_id, last_seen, event_count, source) VALUES (?, ?, 1, ?) ON CONFLICT(sensor_id) DO UPDATE SET last_seen=excluded.last_seen, event_count=sensor_heartbeats.event_count + 1, source=excluded.source",
            (sensor_id, _utc_now(), event["source"]),
        )
    conn.commit()
    conn.close()
    return {"accepted": len(accepted) - deduplicated, "deduplicated": deduplicated, "assetsMatched": matched_assets, "receivedAt": _utc_now()}


def sensor_token_valid(token):
    expected = os.environ.get("SENSOR_INGEST_TOKEN")
    if not expected or not token:
        return False
    return hmac.compare_digest(token, expected)
