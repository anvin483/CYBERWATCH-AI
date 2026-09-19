from database.db import get_connection

conn = get_connection()

cursor = conn.cursor()

cursor.execute("DELETE FROM cves")

conn.commit()

conn.close()

print("Database cleaned")
