"""Evaluate the CLI against labeled synthetic scenarios."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from soc_evidence.exporting import write_new_report

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "data" / "evaluation"


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    rule_names = [
        "failure_burst",
        "success_after_failures",
        "multi_account_failures",
    ]
    confusion = {rule: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for rule in rule_names}
    scenarios = []
    benign_alerts = []

    for scenario in manifest["scenarios"]:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "soc_evidence.cli",
                str(CORPUS / scenario["file"]),
                "--format",
                scenario["format"],
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        report = json.loads(result.stdout)
        actual = report["alerts"]
        expected = scenario["expected_alert_counts"]

        for rule in rule_names:
            predicted = actual[rule] > 0
            labeled = expected[rule] > 0
            category = (
                "tp"
                if predicted and labeled
                else "fp"
                if predicted
                else "fn"
                if labeled
                else "tn"
            )
            confusion[rule][category] += 1

        if scenario["intent"] == "benign" and any(actual.values()):
            benign_alerts.append(scenario["id"])

        scenarios.append(
            {
                "id": scenario["id"],
                "intent": scenario["intent"],
                "explanation": scenario["explanation"],
                "expected_alert_counts": expected,
                "actual_alert_counts": actual,
                "counts_match": actual == expected,
                "input_sha256": report["input_source"]["sha256"],
                "configuration": report["configuration"],
            }
        )

    metrics = {}
    for rule, counts in confusion.items():
        tp, fp = counts["tp"], counts["fp"]
        tn, fn = counts["tn"], counts["fn"]
        metrics[rule] = {
            **counts,
            "precision": ratio(tp, tp + fp),
            "recall": ratio(tp, tp + fn),
            "false_positive_rate": ratio(fp, fp + tn),
        }

    evaluation = {
        "scope": "scenario-level synthetic pattern regression",
        "scenario_count": len(scenarios),
        "all_expected_counts_match": all(item["counts_match"] for item in scenarios),
        "pattern_metrics": metrics,
        "benign_intent_scenarios_with_alerts": benign_alerts,
        "scenarios": scenarios,
        "limitations": [
            "Small synthetic corpus; no real-world accuracy claim.",
            "Pattern labels are not malicious-intent labels.",
            "Each rule is evaluated once per scenario.",
        ],
    }

    write_new_report(
        args.output,
        json.dumps(evaluation, indent=2) + "\n",
    )
    print(f"Evaluated {len(scenarios)} scenarios.")
    print(
        "Expected alert counts match:",
        evaluation["all_expected_counts_match"],
    )
    print("Benign scenarios with alerts:", benign_alerts)
    print(f"Saved: {args.output}")


if __name__ == "__main__":
    main()
