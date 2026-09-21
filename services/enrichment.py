import ipaddress
import os
import socket
import threading
import time

import requests


_CACHE = {}
_CACHE_LOCK = threading.Lock()
_CACHE_TTL = 3600


def _base(ip):
    return {
        "ip": ip,
        "country": "Unknown",
        "countryCode": "--",
        "organization": "Unknown",
        "asn": None,
        "isp": "Unknown",
        "latitude": None,
        "longitude": None,
        "reverseDns": None,
        "whois": {"status": "not_configured"},
        "threatActor": None,
        "malwareFamily": None,
        "relatedCves": [],
        "locationSource": "unavailable",
        "abuse": {"status": "not_configured", "score": None},
    }


def enrich_ip(value):
    if not value:
        return _base(None)
    try:
        ip = str(ipaddress.ip_address(value))
    except ValueError:
        return _base(str(value))
    with _CACHE_LOCK:
        cached = _CACHE.get(ip)
        if cached and time.time() - cached["cachedAt"] < _CACHE_TTL:
            return cached["data"]

    result = _base(ip)
    address = ipaddress.ip_address(ip)
    if address.is_private or address.is_loopback or address.is_reserved:
        result.update({"country": "Private network", "countryCode": "--", "locationSource": "private"})
    else:
        db_path = os.environ.get("GEOIP_DB_PATH")
        if db_path:
            try:
                import geoip2.database
                with geoip2.database.Reader(db_path) as reader:
                    city = reader.city(ip)
                    result.update({
                        "country": city.country.name or "Unknown",
                        "countryCode": city.country.iso_code or "--",
                        "organization": city.traits.organization or "Unknown",
                        "latitude": city.location.latitude,
                        "longitude": city.location.longitude,
                        "locationSource": "maxmind-city",
                    })
            except (ImportError, OSError, ValueError):
                pass
            try:
                import geoip2.database
                with geoip2.database.Reader(db_path) as reader:
                    asn = reader.asn(ip)
                    result.update({"asn": asn.autonomous_system_number, "isp": asn.autonomous_system_organization or "Unknown"})
            except (ImportError, OSError, ValueError):
                pass
        try:
            result["reverseDns"] = socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror, socket.gaierror):
            pass

    abuse_key = os.environ.get("ABUSEIPDB_API_KEY")
    if abuse_key and not address.is_private:
        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": abuse_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=4,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            result["abuse"] = {
                "status": "checked",
                "score": data.get("abuseConfidenceScore"),
                "reports": data.get("totalReports", 0),
                "lastReportedAt": data.get("lastReportedAt"),
            }
        except requests.RequestException:
            result["abuse"] = {"status": "unavailable", "score": None}

    with _CACHE_LOCK:
        _CACHE[ip] = {"data": result, "cachedAt": time.time()}
    return result
