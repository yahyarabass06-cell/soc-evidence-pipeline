"""Command-line interface for offline authentication analysis."""

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

from soc_evidence.deduplication import deduplicate_records
from soc_evidence.detection import (
    detect_failure_bursts,
    detect_multi_account_failures,
    detect_success_after_failures,
)
from soc_evidence.reading import iter_json_events, iter_ssh_events


def threshold_value(value: str) -> int:
    """Accept integer thresholds of at least two."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("threshold must be an integer") from None

    if number < 2:
        raise argparse.ArgumentTypeError("threshold must be at least 2")
    return number


def window_value(value: str) -> int:
    """Accept windows between one second and one day."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("window must be an integer") from None

    if not 1 <= number <= 86400:
        raise argparse.ArgumentTypeError("window must be between 1 and 86400 seconds")
    return number


def main(argv: list[str] | None = None) -> int:
    """Analyze one file and print a configured JSON summary."""
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

    defaults = {
        "failure": (5, 120),
        "success": (3, 120),
        "account": (5, 300),
    }
    for name, (threshold, seconds) in defaults.items():
        parser.add_argument(
            f"--{name}-threshold",
            type=threshold_value,
            default=threshold,
            help=f"Minimum count for the {name} rule (default: {threshold}).",
        )
        parser.add_argument(
            f"--{name}-window",
            type=window_value,
            default=seconds,
            help=f"Window in seconds for the {name} rule (default: {seconds}).",
        )

    args = parser.parse_args(argv)
    reader = iter_json_events if args.format == "jsonl" else iter_ssh_events

    rules = {
        "failure_burst": ("failure", detect_failure_bursts),
        "success_after_failures": ("success", detect_success_after_failures),
        "multi_account_failures": ("account", detect_multi_account_failures),
    }
    configuration = {}
    for rule_name, (prefix, _) in rules.items():
        configuration[rule_name] = {
            "threshold": getattr(args, f"{prefix}_threshold"),
            "window_seconds": getattr(args, f"{prefix}_window"),
        }

    try:
        records = list(reader(args.input))
        unique = deduplicate_records(records)
        alert_counts = {}

        for rule_name, (_, detector) in rules.items():
            settings = configuration[rule_name]
            alerts = detector(
                unique.records,
                threshold=settings["threshold"],
                window=timedelta(seconds=settings["window_seconds"]),
            )
            alert_counts[rule_name] = len(alerts)

        summary = {
            "status": "complete",
            "input_format": args.format,
            "records_read": len(records),
            "unique_records": len(unique.records),
            "duplicates_removed": unique.duplicates_removed,
            "configuration": configuration,
            "alerts": alert_counts,
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
