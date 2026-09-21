"""Forward newline-delimited sensor JSON into Cyberwatch."""

import argparse
import json
import os
import time

from dotenv import load_dotenv
import requests


load_dotenv()


def parse_args():
    parser = argparse.ArgumentParser(description="Forward Suricata, Zeek, or Wazuh JSON logs to Cyberwatch")
    parser.add_argument("--file", required=True, help="Newline-delimited JSON log file")
    parser.add_argument("--url", default="http://127.0.0.1:5050/api/sensor/ingest")
    parser.add_argument("--token", default=os.environ.get("SENSOR_INGEST_TOKEN"))
    parser.add_argument("--from-start", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    return parser.parse_args()


def main():
    args = parse_args()
    if not args.token:
        raise SystemExit("Set SENSOR_INGEST_TOKEN or pass --token")

    with open(args.file, "r", encoding="utf-8", errors="replace") as stream:
        if not args.from_start:
            stream.seek(0, 2)
        while True:
            line = stream.readline()
            if not line:
                time.sleep(args.poll_seconds)
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            response = requests.post(
                args.url,
                headers={"Authorization": f"Bearer {args.token}"},
                json={"events": [event]},
                timeout=10,
            )
            if response.status_code == 401:
                raise SystemExit(
                    "Cyberwatch rejected the sensor token. "
                    "Set SENSOR_INGEST_TOKEN in the project .env and restart Cyberwatch."
                )
            response.raise_for_status()
            print(response.json(), flush=True)


if __name__ == "__main__":
    main()
