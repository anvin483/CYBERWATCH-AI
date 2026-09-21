import json
import time

from flask import Blueprint, Response, jsonify, request, session, stream_with_context

from services.feed_manager import (
    get_ai_summary,
    get_alert_rules,
    get_attacks_from_db,
    get_cves_from_db,
    get_events,
    get_feed_status,
    get_live_feeds,
    get_ransomware_from_db,
    get_summary,
    get_threat_trend,
    get_top_industries,
    refresh_feeds,
)
from services.sensor_ingest import ingest_events, sensor_token_valid
from services.assets import create_asset, delete_asset, list_assets, update_asset
from services.incident_analyzer import add_comment, get_incident, get_incidents, update_incident
from services.alerting import dispatch_incident
from services.response_actions import approve_action, list_actions, request_action
from services.ai_analyst import analyze_incident

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


@dashboard_bp.route("/api/live-feeds")
def live_feeds():
    return jsonify(get_live_feeds())


@dashboard_bp.route("/api/solar")
def solar():
    return jsonify(get_live_feeds()["solar"])


@dashboard_bp.route("/api/bgp")
def bgp():
    return jsonify(get_live_feeds()["bgp"])


@dashboard_bp.route("/api/outages")
def outages():
    return jsonify(get_live_feeds()["outages"])


@dashboard_bp.route("/api/cves")
def cves():
    return jsonify(get_cves_from_db())


@dashboard_bp.route("/api/ransomware")
def ransomware():
    return jsonify(get_ransomware_from_db())


@dashboard_bp.route("/api/assets", methods=["GET", "POST"])
def assets():
    if request.method == "GET":
        return jsonify(list_assets())
    try:
        return jsonify(create_asset(request.get_json(silent=True) or {})), 201
    except (TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400


@dashboard_bp.route("/api/assets/<int:asset_id>", methods=["PATCH", "DELETE"])
def asset_detail(asset_id):
    if request.method == "DELETE":
        if not delete_asset(asset_id):
            return jsonify({"error": "asset not found"}), 404
        return jsonify({"deleted": True})
    try:
        updated = update_asset(asset_id, request.get_json(silent=True) or {})
        if not updated:
            return jsonify({"error": "asset not found"}), 404
        return jsonify(updated)
    except (TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400


@dashboard_bp.route("/api/incidents")
def incidents():
    return jsonify(get_incidents())


@dashboard_bp.route("/api/incidents/<int:incident_id>", methods=["GET", "PATCH"])
def incident_detail(incident_id):
    if request.method == "GET":
        incident = get_incident(incident_id)
        return jsonify(incident) if incident else (jsonify({"error": "incident not found"}), 404)
    try:
        incident = update_incident(incident_id, request.get_json(silent=True) or {})
        return jsonify(incident) if incident else (jsonify({"error": "incident not found"}), 404)
    except (TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400


@dashboard_bp.route("/api/incidents/<int:incident_id>/comments", methods=["POST"])
def incident_comment(incident_id):
    payload = request.get_json(silent=True) or {}
    try:
        incident = add_comment(incident_id, payload.get("body"), payload.get("author", "analyst"))
        return jsonify(incident) if incident else (jsonify({"error": "incident not found"}), 404)
    except (TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400


@dashboard_bp.route("/api/incidents/<int:incident_id>/notify", methods=["POST"])
def incident_notify(incident_id):
    incident = get_incident(incident_id)
    if not incident:
        return jsonify({"error": "incident not found"}), 404
    return jsonify(dispatch_incident(incident))


@dashboard_bp.route("/api/incidents/<int:incident_id>/ai-analysis", methods=["POST"])
def incident_ai_analysis(incident_id):
    incident = get_incident(incident_id)
    if not incident:
        return jsonify({"error": "incident not found"}), 404
    return jsonify(analyze_incident(incident))


@dashboard_bp.route("/api/incidents/<int:incident_id>/response-actions", methods=["GET", "POST"])
def incident_response_actions(incident_id):
    if not get_incident(incident_id):
        return jsonify({"error": "incident not found"}), 404
    if request.method == "GET":
        return jsonify(list_actions(incident_id))
    payload = request.get_json(silent=True) or {}
    try:
        return jsonify(request_action(incident_id, payload.get("action_type"), payload.get("target"), payload.get("requested_by", "analyst"), payload.get("details"))), 201
    except (TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400


@dashboard_bp.route("/api/response-actions/<int:action_id>/approve", methods=["POST"])
def approve_response_action(action_id):
    if session.get("role", "admin") != "admin":
        return jsonify({"error": "admin approval required"}), 403
    payload = request.get_json(silent=True) or {}
    try:
        action = approve_action(action_id, payload.get("approved_by", "analyst"))
        return jsonify(action) if action else (jsonify({"error": "action not found"}), 404)
    except (TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400


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


@dashboard_bp.route("/api/sensor/ingest", methods=["POST"])
def sensor_ingest():
    authorization = request.headers.get("Authorization", "")
    token = authorization.removeprefix("Bearer ").strip()
    if not sensor_token_valid(token):
        return jsonify({"error": "invalid sensor token"}), 401
    if not request.is_json:
        return jsonify({"error": "JSON body required"}), 415
    try:
        return jsonify(ingest_events(request.get_json(silent=True) or {})), 202
    except (TypeError, ValueError) as error:
        return jsonify({"error": str(error)}), 400
