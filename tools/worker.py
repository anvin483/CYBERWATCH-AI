"""Run the optional Redis/RQ production worker."""

from redis import Redis
from rq import Queue, Worker

from dotenv import load_dotenv
import os


load_dotenv()
connection = Redis.from_url(os.environ["REDIS_URL"])
Worker([Queue("cyberwatch", connection=connection)], connection=connection).work()
