import threading
import time

from services.maintenance import apply_retention
from services.queue import enqueue_refresh


_started = False


def _run_scheduler():
    cycles = 0
    while True:
        time.sleep(900)
        enqueue_refresh()
        cycles += 1
        if cycles % 16 == 0:
            apply_retention()


def start_scheduler():
    global _started
    if _started:
        return

    thread = threading.Thread(target=_run_scheduler, daemon=True)
    thread.start()
    _started = True
    print("Cyberwatch scheduler started")
