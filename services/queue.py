import os


def enqueue_refresh():
    """Use Redis/RQ in production, with a threaded fallback for local development."""
    if os.environ.get("QUEUE_BACKEND", "threaded").lower() != "redis" or not os.environ.get("REDIS_URL"):
        from services.feed_manager import refresh_feeds
        return {"queued": False, "result": refresh_feeds()}
    try:
        from redis import Redis
        from rq import Queue
        from services.feed_manager import refresh_feeds
        job = Queue("cyberwatch", connection=Redis.from_url(os.environ["REDIS_URL"])).enqueue(refresh_feeds)
        return {"queued": True, "jobId": job.id}
    except (ImportError, OSError, ValueError) as error:
        return {"queued": False, "error": str(error)}
