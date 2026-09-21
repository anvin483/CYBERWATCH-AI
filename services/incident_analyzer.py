import hashlib
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from database.db import get_connection


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
INCIDENT_STATUSES = {"new", "investigating", "contained", "resolved", "false_positive"}


def _now():
    return datetime.now(timezone.utc)


def _parse_time(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return _now()


def _technique(category, signature):
    text = f"{category} {signature}".lower()
    if any(word in text for word in ("brute", "login", "password", "authentication")):
        return "T1110", "Brute Force"
    if any(word in text for word in ("scan", "probe", "recon")):
        return "T1595", "Active Scanning"
    if any(word in text for word in ("exploit", "intrusion", "cve", "vulnerability")):
        return "T1190", "Exploit Public-Facing Application"
    if any(word in text for word in ("dns", "domain")):
        return "T1016", "System Network Configuration Discovery"
    if any(word in text for word in ("malware", "payload", "shell")):
        return "T1059", "Command and Scripting Interpreter"
    return "T1046", "Network Service Scanning"


def _fingerprint(source_ip, target_ip, asset_id, technique_id):
    raw = "|".join(str(value or "-") for value in (source_ip, target_ip, asset_id, technique_id))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _recommendations(technique_id):
    return {
        "T1110": ["Rate-limit or block the source IP.", "Review successful logins for targeted accounts.", "Require MFA and reset exposed credentials."],
        "T1595": ["Check exposed services on the target asset.", "Review scan volume and block abusive sources.", "Confirm internet-facing inventory is intentional."],
        "T1190": ["Identify the affected application and patch level.", "Review process, web, and authentication logs.", "Contain the asset if exploitation is confirmed."],
        "T1016": ["Review DNS and network changes for the affected asset.", "Validate the domain or resolver against threat intelligence."],
        "T1059": ["Isolate the endpoint if execution is confirmed.", "Collect process, command-line, and user evidence."],
    }.get(technique_id, ["Validate the detection against the affected asset.", "Correlate related network and endpoint events."])


def _decode(row):
    item = dict(row)
    for key in ("evidence", "recommendations", "enrichment", "ai_analysis"):
        try:
            item[key] = json.loads(item[key] or ("{}" if key == "enrichment" else "[]"))
        except json.JSONDecodeError:
            item[key] = {} if key in {"enrichment", "ai_analysis"} else []
    return item


def analyze_incidents():
    cutoff = (_now() - timedelta(hours=24)).isoformat()
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT a.source_ip, a.target_ip, a.category, a.severity, a.signature,
               a.created_at, a.asset_id, a.enrichment, assets.name AS asset_name,
               assets.criticality AS asset_criticality
        FROM attacks a
        LEFT JOIN assets ON assets.id = a.asset_id
        WHERE a.source_ip IS NOT NULL AND a.created_at >= ?
        ORDER BY a.created_at ASC
        LIMIT 1000
        """,
        (cutoff,),
    ).fetchall()

    groups = defaultdict(list)
    for row in rows:
        technique_id, _ = _technique(row["category"], row["signature"] or "")
        key = _fingerprint(row["source_ip"], row["target_ip"], row["asset_id"], technique_id)
        groups[key].append(row)

    for fingerprint, events in groups.items():
        first = events[0]
        last = events[-1]
        technique_id, technique_name = _technique(first["category"], first["signature"] or "")
        max_severity = max((event["severity"] or "medium" for event in events), key=lambda value: SEVERITY_RANK.get(value, 2))
        asset_criticality = first["asset_criticality"] or "medium"
        confidence = min(98, 55 + min(len(events) * 6, 30) + (10 if asset_criticality in {"high", "critical"} else 0))
        title = f"Possible {technique_name.lower()} activity"
        asset_text = first["asset_name"] or first["target_ip"] or "an observed target"
        summary = f"{len(events)} related detection(s) from {first['source_ip']} targeting {asset_text or 'an observed target'}."
        evidence = [
            f"{len(events)} detection(s) observed between {first['created_at']} and {last['created_at']}.",
            f"Source: {first['source_ip']}.",
            f"Target: {asset_text}.",
        ]
        if first["signature"]:
            evidence.append(f"Detection signature: {first['signature']}.")
        if first["asset_name"]:
            evidence.append(f"Matched protected asset: {first['asset_name']} ({asset_criticality} criticality).")
        enrichment = json.loads(first["enrichment"] or "{}") if first["enrichment"] else {}
        source_context = enrichment.get("source") or {}
        if source_context.get("asn") or source_context.get("isp"):
            evidence.append(f"Network context: AS{source_context.get('asn') or '?'} {source_context.get('isp') or 'unknown ISP'}.")
        if source_context.get("reverseDns"):
            evidence.append(f"Reverse DNS: {source_context['reverseDns']}.")
        if source_context.get("abuse", {}).get("status") == "checked":
            evidence.append(f"Abuse reputation score: {source_context['abuse'].get('score', 0)} / 100.")

        conn.execute(
            """
            INSERT INTO incidents
            (fingerprint, title, summary, severity, confidence, technique_id,
             technique_name, source_ip, target_ip, asset_id, event_count,
             evidence, recommendations, enrichment, first_seen, last_seen, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(fingerprint) DO UPDATE SET
                title=excluded.title, summary=excluded.summary, severity=excluded.severity,
                confidence=excluded.confidence, technique_id=excluded.technique_id,
                technique_name=excluded.technique_name, event_count=excluded.event_count,
                evidence=excluded.evidence, recommendations=excluded.recommendations,
                enrichment=excluded.enrichment,
                first_seen=excluded.first_seen, last_seen=excluded.last_seen,
                updated_at=excluded.updated_at
            """,
            (
                fingerprint, title, summary, max_severity, confidence,
                technique_id, technique_name, first["source_ip"], first["target_ip"],
                first["asset_id"], len(events), json.dumps(evidence),
                json.dumps(_recommendations(technique_id)), json.dumps(enrichment), first["created_at"],
                last["created_at"], _now().isoformat(),
            ),
        )
    conn.commit()
    conn.close()
    return len(groups)


def get_incidents(limit=30):
    analyze_incidents()
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM incidents ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, last_seen DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return [_decode(row) for row in rows]


def get_incident(incident_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    if not row:
        conn.close()
        return None
    item = _decode(row)
    comments = conn.execute("SELECT id, author, body, created_at AS createdAt FROM incident_comments WHERE incident_id = ? ORDER BY id DESC", (incident_id,)).fetchall()
    timeline = conn.execute("SELECT event_type AS type, message, actor, created_at AS createdAt FROM incident_timeline WHERE incident_id = ? ORDER BY id DESC", (incident_id,)).fetchall()
    deliveries = conn.execute("SELECT channel, status, message, response_code, created_at FROM alert_deliveries WHERE incident_id = ? ORDER BY id DESC", (incident_id,)).fetchall()
    actions = conn.execute("SELECT * FROM response_actions WHERE incident_id = ? ORDER BY id DESC", (incident_id,)).fetchall()
    conn.close()
    item["comments"] = [dict(comment) for comment in comments]
    item["timeline"] = [dict(event) for event in timeline]
    item["alertDeliveries"] = [dict(delivery) for delivery in deliveries]
    item["responseActions"] = [dict(action) for action in actions]
    return item


def update_incident(incident_id, payload, actor="analyst"):
    current = get_incident(incident_id)
    if not current:
        return None
    status = str(payload.get("status", current["status"])).lower()
    if status not in INCIDENT_STATUSES:
        raise ValueError(f"status must be one of: {', '.join(sorted(INCIDENT_STATUSES))}")
    assigned_to = str(payload.get("assigned_to", current.get("assigned_to") or ""))[:120] or None
    notes = str(payload.get("notes", current.get("notes") or ""))[:4000] or None
    closure_reason = str(payload.get("closure_reason", current.get("closure_reason") or ""))[:500] or None
    now = _now().isoformat()
    conn = get_connection()
    conn.execute("UPDATE incidents SET status=?, assigned_to=?, notes=?, closure_reason=?, updated_at=? WHERE id=?", (status, assigned_to, notes, closure_reason, now, incident_id))
    if status != current["status"]:
        conn.execute("INSERT INTO incident_timeline (incident_id, event_type, message, actor, created_at) VALUES (?, ?, ?, ?, ?)", (incident_id, "status_change", f"Status changed from {current['status']} to {status}.", actor, now))
    if notes != current.get("notes"):
        conn.execute("INSERT INTO incident_timeline (incident_id, event_type, message, actor, created_at) VALUES (?, ?, ?, ?, ?)", (incident_id, "analyst_note", "Analyst notes updated.", actor, now))
    conn.commit()
    conn.close()
    return get_incident(incident_id)


def add_comment(incident_id, body, author="analyst"):
    if not get_incident(incident_id):
        return None
    body = str(body or "").strip()
    if not body:
        raise ValueError("comment body is required")
    now = _now().isoformat()
    conn = get_connection()
    conn.execute("INSERT INTO incident_comments (incident_id, author, body, created_at) VALUES (?, ?, ?, ?)", (incident_id, author[:120], body[:4000], now))
    conn.execute("INSERT INTO incident_timeline (incident_id, event_type, message, actor, created_at) VALUES (?, ?, ?, ?, ?)", (incident_id, "comment", "Analyst comment added.", author[:120], now))
    conn.commit()
    conn.close()
    return get_incident(incident_id)
