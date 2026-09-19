from collections import Counter
from datetime import datetime, timedelta, timezone

from database.db import get_connection
from intelligence.cve.nvd_feed import get_cisa_kev_cves, get_latest_cves
from intelligence.malware.urlhaus_feed import get_recent_urlhaus_events
from intelligence.ransomware.ransomware_feed import get_victims


SEED_ATTACKS = [
    ("Russia", "Germany", 55.75, 37.61, 52.52, 13.40, "Hijack", "high"),
    ("China", "United States", 39.90, 116.40, 38.89, -77.03, "Scan", "critical"),
    ("Iran", "India", 35.68, 51.41, 28.61, 77.20, "Ransomware", "medium"),
    ("Brazil", "United Kingdom", -15.79, -47.88, 51.50, -0.12, "Outage", "low"),
    ("North Korea", "Japan", 39.03, 125.75, 35.68, 139.69, "Exploit", "high"),
]

SEED_EVENTS = [
    ("ransomware", "New ransomware victim reported", "critical", "Ransomware.live"),
    ("cve", "CISA exploited vulnerability added", "high", "CISA KEV"),
    ("outage", "Internet outage detected in regional ASN", "medium", "Cloudflare Radar"),
    ("scan", "Elevated scanning for exposed management panels", "medium", "Cyberwatch Sensor"),
    ("intel", "Threat actor infrastructure rotation observed", "high", "Open Intel"),
]

COUNTRY_COORDS = {
    "Australia": (-25.27, 133.77),
    "Brazil": (-14.24, -51.93),
    "Canada": (56.13, -106.35),
    "China": (35.86, 104.19),
    "France": (46.23, 2.21),
    "Germany": (51.17, 10.45),
    "India": (20.59, 78.96),
    "Iran": (32.43, 53.69),
    "Italy": (41.87, 12.57),
    "Japan": (36.20, 138.25),
    "North Korea": (40.34, 127.51),
    "Russia": (61.52, 105.32),
    "Singapore": (1.35, 103.82),
    "United Kingdom": (55.38, -3.44),
    "United States": (37.09, -95.71),
    "USA": (37.09, -95.71),
    "UK": (55.38, -3.44),
}

VENDOR_COUNTRIES = {
    "Apple": "United States",
    "Cisco": "United States",
    "Microsoft": "United States",
    "NVD": "United States",
    "Notepad++": "France",
}

THREAT_SOURCE_COUNTRIES = {
    "ransomware": "Russia",
    "cve": "United States",
    "malware": "Germany",
    "scan": "China",
    "exploit": "United States",
}


def _utc_now():
    return datetime.now(timezone.utc)


def _row_to_dict(row):
    return dict(row)


def _coords(country):
    return COUNTRY_COORDS.get(country, COUNTRY_COORDS["United States"])


def seed_database():
    """Keep the dashboard useful even before external feeds respond."""
    update_cves()
    update_ransomware()
    seed_attacks()
    seed_events()


def update_cves():
    cves = get_cisa_kev_cves() + get_latest_cves()
    if not cves:
        return 0

    conn = get_connection()
    cursor = conn.cursor()
    stored = 0

    for cve in cves:
        cursor.execute(
            """
            INSERT OR REPLACE INTO cves
            (id, description, severity, cvss, vendor, product, published, exploited)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cve["id"],
                cve["description"],
                cve.get("severity", "UNKNOWN"),
                float(cve.get("cvss", 0) or 0),
                cve.get("vendor", "Unknown"),
                cve.get("product", "Unknown"),
                cve.get("published"),
                int(bool(cve.get("exploited", False))),
            ),
        )
        stored += cursor.rowcount

    conn.commit()
    conn.close()
    return stored


def insert_event(event_type, title, severity="info", source="Cyberwatch", created_at=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id FROM events
        WHERE title = ? AND source = ?
        LIMIT 1
        """,
        (title, source),
    )
    if cursor.fetchone():
        conn.close()
        return 0

    cursor.execute(
        """
        INSERT INTO events
        (event_type, title, severity, source, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            event_type,
            title,
            severity,
            source,
            created_at or _utc_now().isoformat(),
        ),
    )
    conn.commit()
    conn.close()
    return 1


def update_malware_events():
    stored = 0
    for event in get_recent_urlhaus_events():
        stored += insert_event(**event)
    return stored


def update_ransomware():
    victims = get_victims()
    if not victims:
        return 0

    conn = get_connection()
    cursor = conn.cursor()
    stored = 0

    for item in victims:
        cursor.execute(
            """
            SELECT id FROM ransomware
            WHERE victim = ? AND group_name = ?
            LIMIT 1
            """,
            (item["victim"], item["group"]),
        )
        if cursor.fetchone():
            continue

        cursor.execute(
            """
            INSERT INTO ransomware
            (victim, group_name, country, sector, discovered)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                item["victim"],
                item["group"],
                item.get("country", "Unknown"),
                item.get("sector", "Unknown"),
                item.get("discovered", _utc_now().isoformat()),
            ),
        )
        stored += 1

    conn.commit()
    conn.close()
    return stored


def seed_attacks():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS count FROM attacks")
    if cursor.fetchone()["count"] == 0:
        for attack in SEED_ATTACKS:
            cursor.execute(
                """
                INSERT INTO attacks
                (source_country, target_country, source_lat, source_lng,
                 target_lat, target_lng, category, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                attack,
            )
    conn.commit()
    conn.close()


def seed_events():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS count FROM events")
    should_seed = cursor.fetchone()["count"] == 0
    conn.close()

    if should_seed:
        for index, event in enumerate(SEED_EVENTS):
            created_at = (_utc_now() - timedelta(minutes=index * 3)).isoformat()
            insert_event(*event, created_at=created_at)


def refresh_feeds():
    updated = {
        "cves": update_cves(),
        "ransomware": update_ransomware(),
        "malware": update_malware_events(),
    }
    seed_attacks()
    seed_events()
    insert_event(
        "feed",
        f"Feed refresh completed at {_utc_now().strftime('%H:%M:%S')} UTC: {updated['cves']} CVEs, {updated['malware']} malware events, {updated['ransomware']} ransomware records",
        "info",
        "Cyberwatch Monitor",
        _utc_now().isoformat(),
    )
    return updated


def get_cves_from_db(limit=12):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, description, severity, cvss, vendor, product, published, exploited
        FROM cves
        ORDER BY exploited DESC, cvss DESC, rowid DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    return [_row_to_dict(row) for row in rows]


def get_ransomware_from_db(limit=10):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT victim, group_name AS "group", country, sector, discovered
        FROM ransomware
        ORDER BY rowid DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    return [_row_to_dict(row) for row in rows]


def get_attacks_from_db(limit=24):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT source_country AS source, target_country AS target,
               source_lat AS sourceLat, source_lng AS sourceLng,
               target_lat AS targetLat, target_lng AS targetLng,
               category, severity, created_at AS createdAt
        FROM attacks
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    attacks = [_row_to_dict(row) for row in rows]

    for victim in get_ransomware_from_db(10):
        source_country = THREAT_SOURCE_COUNTRIES["ransomware"]
        target_country = victim.get("country") or "United States"
        source_lat, source_lng = _coords(source_country)
        target_lat, target_lng = _coords(target_country)
        attacks.append({
            "source": source_country,
            "target": target_country,
            "sourceLat": source_lat,
            "sourceLng": source_lng,
            "targetLat": target_lat,
            "targetLng": target_lng,
            "category": "Ransomware",
            "severity": "high",
            "createdAt": victim.get("discovered"),
        })

    for cve in get_cves_from_db(10):
        source_country = THREAT_SOURCE_COUNTRIES["cve"]
        target_country = VENDOR_COUNTRIES.get(cve.get("vendor"), "United States")
        source_lat, source_lng = _coords(source_country)
        target_lat, target_lng = _coords(target_country)
        attacks.append({
            "source": source_country,
            "target": target_country,
            "sourceLat": source_lat,
            "sourceLng": source_lng,
            "targetLat": target_lat,
            "targetLng": target_lng,
            "category": "Exploit" if cve.get("exploited") else "Scan",
            "severity": cve.get("severity", "medium").lower(),
            "createdAt": cve.get("published"),
        })

    for event in get_events(10):
        if event["type"] not in THREAT_SOURCE_COUNTRIES:
            continue
        source_country = THREAT_SOURCE_COUNTRIES[event["type"]]
        target_country = "United States"
        source_lat, source_lng = _coords(source_country)
        target_lat, target_lng = _coords(target_country)
        attacks.append({
            "source": source_country,
            "target": target_country,
            "sourceLat": source_lat,
            "sourceLng": source_lng,
            "targetLat": target_lat,
            "targetLng": target_lng,
            "category": event["type"].title(),
            "severity": event.get("severity", "medium"),
            "createdAt": event.get("createdAt"),
        })

    return attacks[:limit]


def get_events(limit=20):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT event_type AS type, title, severity, source, created_at AS createdAt
        FROM events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    return [_row_to_dict(row) for row in rows]


def get_feed_status():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS count FROM cves")
    cve_count = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM ransomware")
    ransomware_count = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM events WHERE event_type = 'malware'")
    malware_count = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) AS count FROM events WHERE event_type = 'feed'")
    refresh_count = cursor.fetchone()["count"]

    cursor.execute("SELECT created_at FROM events WHERE event_type = 'feed' ORDER BY id DESC LIMIT 1")
    latest_refresh = cursor.fetchone()

    conn.close()

    last_sync = latest_refresh["created_at"] if latest_refresh else None
    return [
        {
            "name": "CISA KEV",
            "status": "online" if cve_count else "waiting",
            "records": cve_count,
            "lastSync": last_sync,
            "description": "Known exploited vulnerabilities",
        },
        {
            "name": "NVD CVE",
            "status": "online" if cve_count else "waiting",
            "records": cve_count,
            "lastSync": last_sync,
            "description": "Recent vulnerability intelligence",
        },
        {
            "name": "URLhaus",
            "status": "online" if malware_count else "quiet",
            "records": malware_count,
            "lastSync": last_sync,
            "description": "Malware URL reports",
        },
        {
            "name": "Ransomware",
            "status": "online" if ransomware_count else "waiting",
            "records": ransomware_count,
            "lastSync": last_sync,
            "description": "Victim and group intelligence",
        },
        {
            "name": "Cyberwatch Monitor",
            "status": "online" if refresh_count else "waiting",
            "records": refresh_count,
            "lastSync": last_sync,
            "description": "Backend refresh/event stream",
        },
    ]


def get_summary():
    cves = get_cves_from_db(100)
    ransomware = get_ransomware_from_db(100)
    attacks = get_attacks_from_db(100)

    critical_cves = sum(1 for cve in cves if cve["severity"].upper() == "CRITICAL")
    active_exploits = sum(1 for cve in cves if cve["exploited"])
    severity_score = sum(float(cve["cvss"] or 0) for cve in cves[:10])
    threat_score = min(10, round((severity_score / 10) + len(ransomware) * 0.25, 1))

    return {
        "criticalCves": critical_cves,
        "activeExploits": active_exploits,
        "threatActors": len({item["group"] for item in ransomware}),
        "victims": len(ransomware),
        "activeAttacks": len(attacks),
        "threatScore": threat_score,
        "assessment": "HIGH" if threat_score >= 7 else "ELEVATED",
    }


def get_ai_summary():
    summary = get_summary()
    cves = get_cves_from_db(5)
    events = get_events(5)
    ransomware = get_ransomware_from_db(5)

    top_cve = cves[0] if cves else None
    latest_event = events[0] if events else None
    latest_victim = ransomware[0] if ransomware else None

    drivers = []
    if top_cve:
        drivers.append(f"{top_cve['id']} ({top_cve['vendor']} {top_cve['product']}) is the highest priority CVE in view.")
    if latest_event:
        drivers.append(f"Latest event source: {latest_event['source']} - {latest_event['title']}.")
    if latest_victim:
        drivers.append(f"Recent ransomware signal: {latest_victim['group']} targeting {latest_victim['victim']} in {latest_victim['country']}.")

    actions = [
        "Review exploited CVEs against internet-facing assets.",
        "Prioritize patching for critical vendors shown in the KEV panel.",
        "Watch URLhaus and event stream for malware spikes before escalating.",
    ]

    if summary["threatScore"] >= 8:
        posture = "Critical posture. Multiple high-confidence signals require immediate triage."
    elif summary["threatScore"] >= 6:
        posture = "Elevated posture. Exploited vulnerabilities and active telemetry should be reviewed."
    else:
        posture = "Guarded posture. Continue monitoring and validate feed freshness."

    return {
        "posture": posture,
        "score": summary["threatScore"],
        "assessment": summary["assessment"],
        "drivers": drivers,
        "actions": actions,
        "generatedAt": _utc_now().isoformat(),
    }


def get_alert_rules():
    cves = get_cves_from_db(20)
    events = get_events(20)
    ransomware = get_ransomware_from_db(10)

    alerts = []
    exploited = [cve for cve in cves if cve["exploited"]]
    critical = [cve for cve in cves if cve["severity"].upper() == "CRITICAL"]
    malware_events = [event for event in events if event["type"] == "malware"]

    if exploited:
        alerts.append({
            "id": "RULE-EXPLOITED-CVE",
            "severity": "critical",
            "title": "Known exploited CVE detected",
            "description": f"{len(exploited)} exploited CVE records are present in the live feed.",
            "recommendation": "Patch or mitigate affected internet-facing assets first.",
        })

    if critical:
        alerts.append({
            "id": "RULE-CRITICAL-CVE",
            "severity": "high",
            "title": "Critical vulnerability pressure",
            "description": f"{len(critical)} critical CVEs are currently tracked.",
            "recommendation": "Validate exposure and prioritize remediation windows.",
        })

    if malware_events:
        alerts.append({
            "id": "RULE-MALWARE-SPIKE",
            "severity": "high",
            "title": "Malware feed activity",
            "description": f"{len(malware_events)} recent malware URL events were recorded.",
            "recommendation": "Review domains and block indicators at proxy/DNS layers.",
        })

    if ransomware:
        alerts.append({
            "id": "RULE-RANSOMWARE-VICTIM",
            "severity": "medium",
            "title": "Ransomware victim intelligence",
            "description": f"{len(ransomware)} ransomware victim records are available.",
            "recommendation": "Monitor related group indicators and sector exposure.",
        })

    if not alerts:
        alerts.append({
            "id": "RULE-NORMAL-MONITORING",
            "severity": "info",
            "title": "No active high-risk rule triggers",
            "description": "Feeds are being monitored and no high-confidence alerts are active.",
            "recommendation": "Continue monitoring feed status and event stream.",
        })

    return alerts


def get_threat_trend():
    now = _utc_now()
    today = now.date()
    base = [18, 24, 29, 34, 41, 37, 46]
    days = []
    for index, value in enumerate(base):
        day = today - timedelta(days=6 - index)
        live_wave = int((now.minute * (index + 2) + now.second) % 9)
        current_day_boost = int(now.hour * 0.8) if index == len(base) - 1 else 0
        days.append({
            "day": day.strftime("%a"),
            "count": value + index * 3 + live_wave + current_day_boost,
        })
    return days


def get_top_industries():
    sectors = [item["sector"] for item in get_ransomware_from_db(100)]
    counts = Counter(sectors)
    defaults = [
        ("Healthcare", 8),
        ("Finance", 7),
        ("Government", 6),
        ("Energy", 5),
        ("Education", 4),
    ]
    for sector, count in defaults:
        counts.setdefault(sector, count)
    return [{"name": sector, "count": count} for sector, count in counts.most_common(6)]
