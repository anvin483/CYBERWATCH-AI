import requests


FALLBACK_VICTIMS = [
        {
            "group": "SafePay",
            "victim": "soraris.it",
            "country": "Italy",
            "sector": "Technology",
        },
        {
            "group": "SafePay",
            "victim": "parsa-beauty.de",
            "country": "Germany",
            "sector": "Retail",
        },
        {
            "group": "Anubis",
            "victim": "Power & Tel",
            "country": "United States",
            "sector": "Telecom",
        },
        {
            "group": "Shadowserver",
            "victim": "Cropwise",
            "country": "Canada",
            "sector": "Agriculture",
        },
        {
            "group": "Qilin",
            "victim": "logismed.fr",
            "country": "France",
            "sector": "Healthcare",
        },
        {
            "group": "LockBit",
            "victim": "unitek-edu",
            "country": "United States",
            "sector": "Education",
        },
    ]


def _normalize_victim(item):
    victim = item.get("victim") or item.get("post_title") or item.get("title") or item.get("company")
    group = item.get("group") or item.get("group_name") or item.get("claim_url") or "Unknown"
    country = item.get("country") or item.get("country_name") or item.get("location") or "Unknown"
    sector = item.get("sector") or item.get("activity") or item.get("industry") or "Unknown"
    discovered = item.get("discovered") or item.get("date") or item.get("published")

    if not victim:
        return None

    return {
        "group": str(group)[:80],
        "victim": str(victim)[:160],
        "country": str(country)[:80],
        "sector": str(sector)[:80],
        "discovered": discovered,
    }


def get_victims():
    endpoints = [
        "https://api.ransomware.live/v2/recentvictims",
        "https://api.ransomware.live/recentvictims",
    ]

    for endpoint in endpoints:
        try:
            response = requests.get(endpoint, timeout=8)
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict):
                data = data.get("data") or data.get("victims") or data.get("results") or []
            victims = [_normalize_victim(item) for item in data[:25] if isinstance(item, dict)]
            victims = [item for item in victims if item]
            if victims:
                return victims
        except requests.RequestException:
            continue

    return FALLBACK_VICTIMS
