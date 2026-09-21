import json
import os
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage

import requests

from database.db import get_connection


def _now():
    return datetime.now(timezone.utc).isoformat()


def _record(incident_id, channel, status, message, response_code=None):
    conn = get_connection()
    conn.execute(
        "INSERT INTO alert_deliveries (incident_id, channel, status, message, response_code, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (incident_id, channel, status, message[:1000], response_code, _now()),
    )
    conn.commit()
    conn.close()


def _post_json(url, payload, headers=None):
    response = requests.post(url, json=payload, headers=headers or {}, timeout=8)
    response.raise_for_status()
    return response.status_code


def _send_email(subject, body):
    host = os.environ.get("SMTP_HOST")
    recipient = os.environ.get("ALERT_EMAIL_TO")
    if not host or not recipient:
        return "not_configured", None
    message = EmailMessage()
    message["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", "cyberwatch@localhost"))
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587")), timeout=8) as server:
        server.starttls()
        if os.environ.get("SMTP_USER"):
            server.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
        server.send_message(message)
    return "sent", 250


def _send_sms(body):
    sid = os.environ.get("TWILIO_ACCOUNT_SID")
    token = os.environ.get("TWILIO_AUTH_TOKEN")
    sender = os.environ.get("TWILIO_FROM_NUMBER")
    recipient = os.environ.get("ALERT_SMS_TO")
    if not all((sid, token, sender, recipient)):
        return "not_configured", None
    response = requests.post(
        f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
        auth=(sid, token),
        data={"From": sender, "To": recipient, "Body": body[:1500]},
        timeout=8,
    )
    response.raise_for_status()
    return "sent", response.status_code


def dispatch_incident(incident):
    """Deliver configured notifications; unconfigured channels are audited, never simulated."""
    severity = str(incident.get("severity", "medium")).lower()
    minimum = os.environ.get("ALERT_MIN_SEVERITY", "high").lower()
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if rank.get(severity, 2) < rank.get(minimum, 3):
        return {"status": "below_threshold", "deliveries": []}

    subject = f"Cyberwatch {severity.upper()}: {incident.get('title', 'Incident')}"
    body = "\n".join([
        subject,
        f"Incident ID: {incident.get('id')}",
        f"Confidence: {incident.get('confidence', 'n/a')}%",
        f"Technique: {incident.get('technique_id', 'n/a')} {incident.get('technique_name', '')}",
        f"Summary: {incident.get('summary', '')}",
        "Evidence:",
        *[f"- {item}" for item in incident.get("evidence", [])],
    ])
    deliveries = []
    channels = [
        ("slack", os.environ.get("SLACK_WEBHOOK_URL"), lambda url: _post_json(url, {"text": body})),
        ("teams", os.environ.get("TEAMS_WEBHOOK_URL"), lambda url: _post_json(url, {"text": body})),
        ("webhook", os.environ.get("ALERT_WEBHOOK_URL"), lambda url: _post_json(url, {"event": "incident", "incident": incident})),
    ]
    for channel, url, sender in channels:
        if not url:
            status, code, message = "not_configured", None, "channel is not configured"
        else:
            try:
                code = sender(url)
                status, message = "sent", "delivery accepted"
            except requests.RequestException as error:
                status, code, message = "failed", None, str(error)
        _record(incident.get("id"), channel, status, message, code)
        deliveries.append({"channel": channel, "status": status})

    try:
        status, code = _send_email(subject, body)
        message = "delivery accepted" if status == "sent" else "channel is not configured"
    except (OSError, smtplib.SMTPException) as error:
        status, code, message = "failed", None, str(error)
    _record(incident.get("id"), "email", status, message, code)
    deliveries.append({"channel": "email", "status": status})

    pager_key = os.environ.get("PAGERDUTY_ROUTING_KEY")
    if pager_key and severity in {"high", "critical"}:
        payload = {"routing_key": pager_key, "event_action": "trigger", "payload": {"summary": subject, "severity": severity, "source": "cyberwatch-ai", "custom_details": incident}}
        try:
            code = _post_json("https://events.pagerduty.com/v2/enqueue", payload)
            status, message = "sent", "delivery accepted"
        except requests.RequestException as error:
            status, code, message = "failed", None, str(error)
    else:
        status, code, message = "not_configured", None, "channel is not configured or below PagerDuty threshold"
    _record(incident.get("id"), "pagerduty", status, message, code)
    deliveries.append({"channel": "pagerduty", "status": status})
    if severity == "critical":
        try:
            status, code = _send_sms(subject + " - analyst approval required")
            message = "delivery accepted" if status == "sent" else "channel is not configured"
        except requests.RequestException as error:
            status, code, message = "failed", None, str(error)
        _record(incident.get("id"), "sms", status, message, code)
        deliveries.append({"channel": "sms", "status": status})
    return {"status": "completed", "deliveries": deliveries}


def get_delivery_history(incident_id):
    conn = get_connection()
    rows = conn.execute("SELECT channel, status, message, response_code, created_at FROM alert_deliveries WHERE incident_id = ? ORDER BY id DESC", (incident_id,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]
