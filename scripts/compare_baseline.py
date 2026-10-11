"""Compare failure-burst detection with counting without a time window."""

import json
from collections import Counter
from pathlib import Path

from soc_evidence.deduplication import deduplicate_records
from soc_evidence.detection import detect_failure_bursts
from soc_evidence.input_snapshot import load_input

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "data" / "evaluation"


def main():
    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))

    print("scenario | expected pattern | no-window baseline | sliding window")

    for scenario in manifest["scenarios"]:
        snapshot = load_input(CORPUS / scenario["file"], scenario["format"])
        records = deduplicate_records(snapshot.records).records

        counts = Counter(
            (
                item.event.hostname,
                item.event.source_ip,
                item.event.username,
            )
            for item in records
            if item.event.outcome == "failure"
        )
        baseline = any(count >= 5 for count in counts.values())
        sliding_window = bool(detect_failure_bursts(records))
        expected = scenario["expected_alert_counts"]["failure_burst"] > 0

        print(f"{scenario['id']} | {expected} | {baseline} | {sliding_window}")


if __name__ == "__main__":
    main()
