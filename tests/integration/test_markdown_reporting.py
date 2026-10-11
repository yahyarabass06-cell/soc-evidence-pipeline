"""Tests for Markdown rendering from actual CLI reports."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from soc_evidence.markdown_reporting import render_markdown

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def get_report(file_name, input_format="ssh"):
    path = REPOSITORY_ROOT / "data" / "synthetic" / file_name
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_evidence.cli",
            str(path),
            "--format",
            input_format,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0
    return json.loads(result.stdout)


@pytest.mark.parametrize(
    "file_name",
    [
        "ssh-failure-burst.log",
        "ssh-success-after-failures.log",
        "ssh-multi-account.log",
    ],
)
def test_markdown_contains_alert_and_every_source_line(file_name):
    report = get_report(file_name)

    markdown = render_markdown(report)

    assert "# Authentication Analysis Report" in markdown
    assert "### Alert 1:" in markdown
    assert "## Configuration" in markdown
    for item in report["alert_details"][0]["evidence"]:
        assert f"| {item['source']['line_number']} |" in markdown


def test_markdown_handles_no_alerts():
    markdown = render_markdown(get_report("auth-demo.jsonl", "jsonl"))

    assert "No alerts were produced" in markdown
    assert "### Alert 1:" not in markdown


def test_untrusted_text_is_escaped():
    report = get_report("ssh-success-after-failures.log")
    alert = report["alert_details"][0]
    alert["usernames"] = ["<script>|[click](https://example.test)"]
    alert["evidence"][0]["username"] = "name|extra\nrow"

    markdown = render_markdown(report)

    assert "<script>" not in markdown
    assert "[click](https://example.test)" not in markdown
    assert r"name\|extra row" in markdown


def test_markdown_is_deterministic():
    report = get_report("ssh-success-after-failures.log")

    assert render_markdown(report) == render_markdown(report)
