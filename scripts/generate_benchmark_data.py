"""Generate deterministic synthetic data for local performance measurements."""

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from soc_evidence.exporting import write_new_report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, choices=(1000, 10000), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    start = datetime(2026, 10, 11, 16, 0, tzinfo=UTC)
    lines = []

    for index in range(args.events):
        event = {
            "timestamp": (start + timedelta(seconds=index)).isoformat(),
            "hostname": f"lab-server-{index % 5}",
            "username": f"user-{index % 100}",
            "source_ip": "192.0.2.10",
            "outcome": "failure" if index % 10 == 0 else "success",
        }
        lines.append(json.dumps(event) + "\n")

    write_new_report(args.output, "".join(lines))
    print(f"Generated {args.events} events.")


if __name__ == "__main__":
    main()
