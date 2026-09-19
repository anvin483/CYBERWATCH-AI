import threading
import time

from services.feed_manager import refresh_feeds


_started = False


def _run_scheduler():
    while True:
        time.sleep(900)
        refresh_feeds()


def start_scheduler():
    global _started
    if _started:
        return

    thread = threading.Thread(target=_run_scheduler, daemon=True)
    thread.start()
    _started = True
    print("Cyberwatch scheduler started")
