import os
from datetime import datetime, timezone

import requests


FALLBACK_BGP = [
    {"asn": "AS13335", "cc": "US", "isp": "Cloudflare", "prefix": "104.16/12", "ago": "token"},
    {"asn": "AS16509", "cc": "US", "isp": "Amazon AWS", "prefix": "3.0/8", "ago": "token"},
    {"asn": "AS8075", "cc": "US", "isp": "Microsoft", "prefix": "20.0/14", "ago": "token"},
    {"asn": "AS15169", "cc": "US", "isp": "Google LLC", "prefix": "8.8/24", "ago": "token"},
]

FALLBACK_OUTAGES = [
    {"cc": "UA", "cause": "conflict", "state": "active", "started": "feed"},
    {"cc": "RU", "cause": "regime", "state": "active", "started": "feed"},
    {"cc": "MM", "cause": "regime", "state": "active", "started": "feed"},
    {"cc": "IR", "cause": "regime", "state": "active", "started": "feed"},
]


def _checked_at():
    return datetime.now(timezone.utc).isoformat()


def _result(status, items):
    return {
        "status": status,
        "source": "Cloudflare Radar",
        "items": items,
        "checkedAt": _checked_at(),
        "updatedAt": _checked_at() if status == "online" else None,
    }


def _headers():
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:
        return None
    return {"Authorization": f"Bearer {token}"}


def _radar_get(path, params=None):
    headers = _headers()
    if not headers:
        return None
    response = requests.get(
        f"https://api.cloudflare.com/client/v4/radar/{path}",
        headers=headers,
        params=params or {},
        timeout=8,
    )
    response.raise_for_status()
    return response.json().get("result", {})


def get_bgp_hijacks():
    try:
        result = _radar_get("bgp/hijacks/events", {"limit": 10})
        if not result:
            return _result("token_required", FALLBACK_BGP)
        events = result.get("events") or result.get("data") or []
        asn_info = {
            str(item.get("asn")): item
            for item in result.get("asn_info", [])
            if item.get("asn") is not None
        }
        items = []
        for event in events[:10]:
            hijacker_asn = event.get("hijacker_asn")
            network = asn_info.get(str(hijacker_asn), {})
            items.append({
                "asn": f"AS{hijacker_asn}" if hijacker_asn else "AS?",
                "cc": event.get("hijacker_country") or network.get("country_code") or "--",
                "isp": network.get("org_name") or "Unknown",
                "prefix": (event.get("prefixes") or ["--"])[0],
                "ago": event.get("min_hijack_ts") or event.get("max_msg_ts") or "live",
            })
        return _result("online", items or FALLBACK_BGP)
    except requests.RequestException:
        return _result("fallback", FALLBACK_BGP)


def get_outages():
    try:
        result = _radar_get("annotations/outages", {"limit": 10})
        if not result:
            return _result("token_required", FALLBACK_OUTAGES)
        events = result.get("annotations") or result.get("events") or result.get("data") or []
        items = []
        for event in events[:10]:
            location = (event.get("locationsDetails") or [{}])[0]
            outage = event.get("outage") or {}
            items.append({
                "cc": location.get("code") or (event.get("locations") or ["--"])[0],
                "cause": outage.get("outageCause") or event.get("eventType") or "anomaly",
                "state": "resolved" if event.get("endDate") else "active",
                "started": event.get("startDate") or "live",
            })
        return _result("online", items or FALLBACK_OUTAGES)
    except requests.RequestException:
        return _result("fallback", FALLBACK_OUTAGES)
