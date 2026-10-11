"""Command-line interface for offline authentication analysis."""

import argparse
import json
import sys
from pathlib import Path

from soc_evidence.deduplication import deduplicate_records
from soc_evidence.detection import (
    detect_failure_bursts,
    detect_multi_account_failures,
    detect_success_after_failures,
)
from soc_evidence.reading import iter_json_events, iter_ssh_events


def main(argv: list[str] | None = None) -> int:
    """Analyze one file and print a JSON summary."""
    parser = argparse.ArgumentParser(
        description="Analyze authorized authentication logs offline."
    )
    parser.add_argument("input", type=Path, help="Input file path")
    parser.add_argument(
        "--format",
        choices=("jsonl", "ssh"),
        required=True,
        help="Input format; SSH support is limited to password messages.",
    )
    args = parser.parse_args(argv)

    reader = iter_json_events if args.format == "jsonl" else iter_ssh_events

    try:
        records = list(reader(args.input))
        unique = deduplicate_records(records)

        summary = {
            "status": "complete",
            "input_format": args.format,
            "records_read": len(records),
            "unique_records": len(unique.records),
            "duplicates_removed": unique.duplicates_removed,
            "alerts": {
                "failure_burst": len(detect_failure_bursts(unique.records)),
                "success_after_failures": len(
                    detect_success_after_failures(unique.records)
                ),
                "multi_account_failures": len(
                    detect_multi_account_failures(unique.records)
                ),
            },
        }
    except (OSError, UnicodeError, ValueError) as exc:
        print(
            f"Error: {type(exc).__name__}; input could not be analyzed.",
            file=sys.stderr,
        )
        return 1

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
