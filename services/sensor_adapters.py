from datetime import datetime, timezone


def _severity_from_suricata(value):
    return {1: "high", 2: "medium", 3: "low"}.get(int(value or 2), "medium")


def _severity_from_wazuh(value):
    level = int(value or 0)
    if level >= 13:
        return "critical"
    if level >= 10:
        return "high"
    if level >= 7:
        return "medium"
    if level >= 4:
        return "low"
    return "info"


def _iso_from_epoch(value):
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
    except (TypeError, ValueError, OSError):
        return None


def adapt_event(item):
    """Convert common sensor formats into Cyberwatch's flat event contract."""
    if not isinstance(item, dict):
        return item

    # Suricata EVE JSON alert event.
    if item.get("event_type") == "alert" and isinstance(item.get("alert"), dict):
        alert = item["alert"]
        return {
            "event_type": "intrusion",
            "signature": alert.get("signature") or "Suricata alert",
            "severity": _severity_from_suricata(alert.get("severity")),
            "src_ip": item.get("src_ip"),
            "dest_ip": item.get("dest_ip"),
            "src_port": item.get("src_port"),
            "dest_port": item.get("dest_port"),
            "proto": item.get("proto"),
            "source": f"Suricata {item.get('host', 'sensor')}"[:80],
            "timestamp": item.get("timestamp"),
        }

    # Wazuh alert JSON, including nested rule/data fields.
    if isinstance(item.get("rule"), dict) and (item.get("agent") or item.get("manager")):
        rule = item["rule"]
        data = item.get("data") or {}
        agent = item.get("agent") or {}
        agent_name = agent.get("name") if isinstance(agent, dict) else str(agent)
        return {
            "event_type": "endpoint",
            "signature": rule.get("description") or "Wazuh detection",
            "severity": _severity_from_wazuh(rule.get("level")),
            "src_ip": data.get("srcip") or data.get("src_ip"),
            "dest_ip": data.get("dstip") or data.get("dest_ip"),
            "source": f"Wazuh {agent_name or 'agent'}"[:80],
            "timestamp": item.get("timestamp"),
        }

    # Zeek JSON logs use dotted connection fields and epoch timestamps.
    if "id.orig_h" in item or "id.resp_h" in item or item.get("_path") in {"notice", "weird", "conn"}:
        path = item.get("_path") or "network"
        signature = item.get("note") or item.get("name") or item.get("msg") or f"Zeek {path} event"
        return {
            "event_type": f"zeek-{str(path).lower()}",
            "signature": signature,
            "severity": "medium" if path in {"notice", "weird"} else "low",
            "src_ip": item.get("id.orig_h"),
            "dest_ip": item.get("id.resp_h"),
            "source": "Zeek network monitor",
            "timestamp": _iso_from_epoch(item.get("ts")) or item.get("timestamp"),
        }

    # Generic syslog, Windows, firewall, DNS, proxy, and cloud events.
    normalized = dict(item)
    normalized.setdefault("signature", item.get("message") or item.get("msg") or item.get("event_name"))
    normalized.setdefault("timestamp", item.get("@timestamp") or item.get("time"))
    normalized.setdefault("source", item.get("log_source") or item.get("provider"))
    return normalized
