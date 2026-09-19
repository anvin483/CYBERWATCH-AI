from services.feed_manager import get_cves_from_db

cves = get_cves_from_db()

for cve in cves:
    print(cve)
