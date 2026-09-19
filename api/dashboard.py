import json
import time

from flask import Blueprint, Response, jsonify, stream_with_context

from services.feed_manager import (
    get_ai_summary,
    get_alert_rules,
    get_attacks_from_db,
    get_cves_from_db,
    get_events,
    get_feed_status,
    get_ransomware_from_db,
    get_summary,
    get_threat_trend,
    get_top_industries,
    refresh_feeds,
)

dashboard_bp = Blueprint(
    "dashboard",
    __name__
)


@dashboard_bp.route("/api/health")
def health():
    return jsonify({"status": "online", "service": "cyberwatch-ai"})


@dashboard_bp.route("/api/summary")
def summary():
    return jsonify(get_summary())


@dashboard_bp.route("/api/ai-summary")
def ai_summary():
    return jsonify(get_ai_summary())


@dashboard_bp.route("/api/feed-status")
def feed_status():
    return jsonify(get_feed_status())


@dashboard_bp.route("/api/alerts")
def alerts():
    return jsonify(get_alert_rules())


@dashboard_bp.route("/api/threat-trend")
def threat_trend():
    return jsonify(get_threat_trend())


@dashboard_bp.route("/api/cves")
def cves():
    return jsonify(get_cves_from_db())


@dashboard_bp.route("/api/ransomware")
def ransomware():
    return jsonify(get_ransomware_from_db())


@dashboard_bp.route("/api/attacks")
def attacks():
    return jsonify(get_attacks_from_db())


@dashboard_bp.route("/api/events")
def events():
    return jsonify(get_events())


@dashboard_bp.route("/api/events/stream")
def events_stream():
    def generate():
        last_payload = None
        while True:
            payload = json.dumps(get_events(12))
            if payload != last_payload:
                yield f"event: events\ndata: {payload}\n\n"
                last_payload = payload
            else:
                yield "event: heartbeat\ndata: {}\n\n"
            time.sleep(5)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@dashboard_bp.route("/api/industries")
def industries():
    return jsonify(get_top_industries())


@dashboard_bp.route("/api/refresh", methods=["POST"])
def refresh():
    return jsonify({"updated": refresh_feeds()})
