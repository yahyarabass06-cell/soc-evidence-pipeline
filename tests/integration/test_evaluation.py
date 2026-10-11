"""Validate evaluator counts against the fixed corpus labels."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_evaluator_reports_expected_confusion_counts(tmp_path):
    output = tmp_path / "evaluation.json"
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "evaluate_detection.py"),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["scenario_count"] == 8
    assert report["all_expected_counts_match"] is True

    expected = {
        "failure_burst": (2, 6),
        "success_after_failures": (1, 7),
        "multi_account_failures": (1, 7),
    }
    for rule, (positives, negatives) in expected.items():
        metrics = report["pattern_metrics"][rule]
        assert metrics["tp"] == positives
        assert metrics["tn"] == negatives
        assert metrics["fp"] == 0
        assert metrics["fn"] == 0
        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 1.0
        assert metrics["false_positive_rate"] == 0.0

    assert report["benign_intent_scenarios_with_alerts"] == [
        "legitimate_password_mistakes"
    ]
