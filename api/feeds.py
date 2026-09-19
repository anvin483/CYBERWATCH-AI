from flask import Blueprint, jsonify

feeds_bp = Blueprint("feeds", __name__)

@feeds_bp.route("/api/cves")
def cves():

    return jsonify([
        {
            "id": "CVE-2026-1001",
            "description": "Remote Code Execution in Apache Server"
        },
        {
            "id": "CVE-2026-1002",
            "description": "Privilege Escalation in Windows Service"
        },
        {
            "id": "CVE-2026-1003",
            "description": "SQL Injection Vulnerability"
        },
        {
            "id": "CVE-2026-1004",
            "description": "Authentication Bypass"
        },
        {
            "id": "CVE-2026-1005",
            "description": "Buffer Overflow Vulnerability"
        }
    ])

@feeds_bp.route("/api/ransomware")
def ransomware():

    return jsonify([
        {
            "group": "LockBit",
            "victim": "US Manufacturing"
        },
        {
            "group": "Akira",
            "victim": "German Healthcare"
        },
        {
            "group": "Cl0p",
            "victim": "Indian IT Company"
        },
        {
            "group": "Play",
            "victim": "UK Financial Services"
        }
    ])