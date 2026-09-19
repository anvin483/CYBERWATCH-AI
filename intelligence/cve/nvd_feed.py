from datetime import datetime, timedelta, timezone

import requests


FALLBACK_CVES = [
    {
        "id": "CVE-2025-21333",
        "description": "Windows privilege escalation vulnerability observed in active exploitation.",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "vendor": "Microsoft",
        "product": "Windows",
        "exploited": True,
    },
    {
        "id": "CVE-2025-29824",
        "description": "Microsoft CLFS elevation of privilege vulnerability with public exploitation signals.",
        "severity": "HIGH",
        "cvss": 7.8,
        "vendor": "Microsoft",
        "product": "CLFS Driver",
        "exploited": True,
    },
    {
        "id": "CVE-2025-43461",
        "description": "Cisco IOS XE command injection vulnerability affecting network edge devices.",
        "severity": "CRITICAL",
        "cvss": 9.6,
        "vendor": "Cisco",
        "product": "IOS XE",
        "exploited": False,
    },
    {
        "id": "CVE-2024-43468",
        "description": "Configuration weakness enabling unauthorized access to exposed Microsoft services.",
        "severity": "HIGH",
        "cvss": 8.1,
        "vendor": "Microsoft",
        "product": "Configuration Manager",
        "exploited": True,
    },
    {
        "id": "CVE-2025-15556",
        "description": "Notepad++ plugin loading vulnerability allowing local code execution.",
        "severity": "MEDIUM",
        "cvss": 6.5,
        "vendor": "Notepad++",
        "product": "npp.exe",
        "exploited": False,
    },
    {
        "id": "CVE-2025-20700",
        "description": "Apple iOS and macOS memory handling issue leading to application sandbox escape.",
        "severity": "HIGH",
        "cvss": 8.4,
        "vendor": "Apple",
        "product": "iOS/macOS",
        "exploited": False,
    },
]


def _severity_from_score(score):
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def _extract_nvd_item(item):
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {})
    cvss = 0

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if values:
            cvss = values[0].get("cvssData", {}).get("baseScore", 0)
            break

    descriptions = cve.get("descriptions", [])
    description = next(
        (entry["value"] for entry in descriptions if entry.get("lang") == "en"),
        "No description available.",
    )

    weaknesses = cve.get("weaknesses", [])
    product = "General"
    if weaknesses and weaknesses[0].get("description"):
        product = weaknesses[0]["description"][0].get("value", "General")

    return {
        "id": cve.get("id", "UNKNOWN-CVE"),
        "description": description,
        "severity": _severity_from_score(float(cvss or 0)),
        "cvss": cvss,
        "vendor": "NVD",
        "product": product,
        "published": cve.get("published"),
        "exploited": False,
    }


def get_latest_cves():
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=14)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": 8,
    }

    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params,
            timeout=6,
        )
        response.raise_for_status()
        data = response.json()
        cves = [_extract_nvd_item(item) for item in data.get("vulnerabilities", [])]
        return cves or FALLBACK_CVES
    except requests.RequestException:
        now = datetime.now(timezone.utc).isoformat()
        return [{**cve, "published": now} for cve in FALLBACK_CVES]


def get_cisa_kev_cves(limit=12):
    try:
        response = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=8,
        )
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        recent = sorted(
            vulnerabilities,
            key=lambda item: item.get("dateAdded", ""),
            reverse=True,
        )[:limit]

        return [
            {
                "id": item.get("cveID", "UNKNOWN-CVE"),
                "description": item.get("shortDescription") or item.get("vulnerabilityName") or "Known exploited vulnerability.",
                "severity": "CRITICAL",
                "cvss": 9.0,
                "vendor": item.get("vendorProject", "CISA KEV"),
                "product": item.get("product", "Known Exploited Vulnerability"),
                "published": item.get("dateAdded"),
                "exploited": True,
            }
            for item in recent
        ]
    except requests.RequestException:
        return []
