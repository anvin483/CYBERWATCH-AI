"""Apply Cyberwatch's idempotent schema migrations."""

from dotenv import load_dotenv

load_dotenv()

from database.models import create_tables


if __name__ == "__main__":
    create_tables()
    print("Cyberwatch database schema is up to date")
