"""Integration tests for CLI output and exit codes."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def run_cli(*arguments):
    return subprocess.run(
        [sys.executable, "-m", "soc_evidence.cli", *map(str, arguments)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


@pytest.mark.parametrize(
    ("file_name", "input_format", "expected"),
    [
        ("auth-demo.jsonl", "jsonl", (0, 0, 0)),
        ("ssh-failure-burst.log", "ssh", (1, 0, 0)),
        ("ssh-success-after-failures.log", "ssh", (0, 1, 0)),
        ("ssh-multi-account.log", "ssh", (0, 0, 1)),
    ],
)
def test_cli_analyzes_versioned_scenarios(file_name, input_format, expected):
    path = REPOSITORY_ROOT / "data" / "synthetic" / file_name

    result = run_cli(path, "--format", input_format)

    assert result.returncode == 0
    assert result.stderr == ""
    summary = json.loads(result.stdout)
    assert summary["status"] == "complete"
    assert (
        summary["alerts"]["failure_burst"],
        summary["alerts"]["success_after_failures"],
        summary["alerts"]["multi_account_failures"],
    ) == expected


def test_missing_file_returns_error_without_result(tmp_path):
    result = run_cli(tmp_path / "missing.log", "--format", "ssh")

    assert result.returncode == 1
    assert result.stdout == ""
    assert "FileNotFoundError" in result.stderr
    assert "Traceback" not in result.stderr


def test_invalid_line_prevents_partial_summary(tmp_path):
    path = tmp_path / "invalid.jsonl"
    sample = REPOSITORY_ROOT / "data" / "synthetic" / "auth-demo.jsonl"
    path.write_text(
        sample.read_text(encoding="utf-8") + "INVALID_TEST_CONTENT\n",
        encoding="utf-8",
    )

    result = run_cli(path, "--format", "jsonl")

    assert result.returncode == 1
    assert result.stdout == ""
    assert "ParseError" in result.stderr
    assert "INVALID_TEST_CONTENT" not in result.stderr


def test_unsupported_format_returns_argument_error():
    result = run_cli("unused.log", "--format", "unknown")

    assert result.returncode == 2
    assert result.stdout == ""


def test_installed_command_runs_outside_repository(tmp_path):
    executable = Path(sys.executable).with_name("soc-evidence")
    input_path = REPOSITORY_ROOT / "data" / "synthetic" / "ssh-failure-burst.log"

    result = subprocess.run(
        [str(executable), str(input_path), "--format", "ssh"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    summary = json.loads(result.stdout)
    assert summary["records_read"] == 5
    assert summary["alerts"]["failure_burst"] == 1


@pytest.mark.parametrize(
    "option",
    [
        "--failure-threshold",
        "--success-threshold",
        "--account-threshold",
        "--failure-window",
        "--success-window",
        "--account-window",
    ],
)
def test_invalid_configuration_is_rejected_before_reading(option):
    result = run_cli("unused.log", "--format", "ssh", option, "0")

    assert result.returncode == 2
    assert result.stdout == ""
    assert "FileNotFoundError" not in result.stderr


@pytest.mark.parametrize(
    ("file_name", "option", "rule_name"),
    [
        (
            "ssh-failure-burst.log",
            "--failure-threshold",
            "failure_burst",
        ),
        (
            "ssh-success-after-failures.log",
            "--success-threshold",
            "success_after_failures",
        ),
        (
            "ssh-multi-account.log",
            "--account-threshold",
            "multi_account_failures",
        ),
    ],
)
def test_custom_threshold_changes_detection(file_name, option, rule_name):
    path = REPOSITORY_ROOT / "data" / "synthetic" / file_name

    result = run_cli(path, "--format", "ssh", option, "10")

    assert result.returncode == 0
    summary = json.loads(result.stdout)
    assert summary["configuration"][rule_name]["threshold"] == 10
    assert summary["alerts"][rule_name] == 0


def test_custom_window_changes_detection():
    path = REPOSITORY_ROOT / "data" / "synthetic" / "ssh-failure-burst.log"

    result = run_cli(path, "--format", "ssh", "--failure-window", "10")

    assert result.returncode == 0
    summary = json.loads(result.stdout)
    assert summary["configuration"]["failure_burst"]["window_seconds"] == 10
    assert summary["alerts"]["failure_burst"] == 0


@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("--failure-threshold", "1"),
        ("--success-window", "abc"),
        ("--account-window", "86401"),
    ],
)
def test_configuration_limits_return_argument_error(option, value):
    result = run_cli("unused.log", "--format", "ssh", option, value)

    assert result.returncode == 2
    assert result.stdout == ""
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    ("file_name", "rule_name", "outcomes"),
    [
        (
            "ssh-failure-burst.log",
            "failure_burst",
            ["failure"] * 5,
        ),
        (
            "ssh-success-after-failures.log",
            "success_after_failures",
            ["failure"] * 3 + ["success"],
        ),
        (
            "ssh-multi-account.log",
            "multi_account_failures",
            ["failure"] * 5,
        ),
    ],
)
def test_json_report_contains_detection_evidence(file_name, rule_name, outcomes):
    path = REPOSITORY_ROOT / "data" / "synthetic" / file_name

    result = run_cli(path, "--format", "ssh")

    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report["schema_version"] == 1
    assert len(report["alert_details"]) == 1
    alert = report["alert_details"][0]
    assert alert["rule"] == rule_name
    assert alert["evidence_count"] == len(outcomes)
    assert [item["outcome"] for item in alert["evidence"]] == outcomes
    assert [item["source"]["line_number"] for item in alert["evidence"]] == (
        list(range(1, len(outcomes) + 1))
    )
    assert all(item["source"]["file_name"] == str(path) for item in alert["evidence"])


def test_report_without_alerts_has_empty_details():
    path = REPOSITORY_ROOT / "data" / "synthetic" / "auth-demo.jsonl"

    result = run_cli(path, "--format", "jsonl")

    assert result.returncode == 0
    assert json.loads(result.stdout)["alert_details"] == []


def test_identical_input_and_configuration_produce_identical_json():
    path = REPOSITORY_ROOT / "data" / "synthetic" / "ssh-failure-burst.log"

    first = run_cli(path, "--format", "ssh")
    second = run_cli(path, "--format", "ssh")

    assert first.returncode == second.returncode == 0
    assert first.stdout == second.stdout


@pytest.mark.parametrize("output_format", ["json", "markdown"])
def test_cli_exports_report(tmp_path, output_format):
    path = REPOSITORY_ROOT / "data" / "synthetic" / "ssh-failure-burst.log"
    output = tmp_path / "report.txt"

    result = run_cli(
        path,
        "--format",
        "ssh",
        "--output",
        output,
        "--output-format",
        output_format,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert "Report saved." in result.stderr
    content = output.read_text(encoding="utf-8")
    if output_format == "json":
        assert json.loads(content)["alerts"]["failure_burst"] == 1
    else:
        assert "# Authentication Analysis Report" in content
        assert "### Alert 1:" in content
    assert output.stat().st_mode & 0o777 == 0o600


def test_existing_report_is_not_overwritten(tmp_path):
    path = REPOSITORY_ROOT / "data" / "synthetic" / "ssh-failure-burst.log"
    output = tmp_path / "existing.json"
    output.write_text("KEEP_THIS_CONTENT", encoding="utf-8")

    result = run_cli(path, "--format", "ssh", "--output", output)

    assert result.returncode == 1
    assert "FileExistsError" in result.stderr
    assert output.read_text(encoding="utf-8") == "KEEP_THIS_CONTENT"


def test_invalid_input_does_not_create_report(tmp_path):
    path = tmp_path / "invalid.jsonl"
    path.write_text("INVALID\n", encoding="utf-8")
    output = tmp_path / "report.json"

    result = run_cli(path, "--format", "jsonl", "--output", output)

    assert result.returncode == 1
    assert not output.exists()


def test_markdown_can_be_printed_to_stdout():
    path = REPOSITORY_ROOT / "data" / "synthetic" / "ssh-failure-burst.log"

    result = run_cli(path, "--format", "ssh", "--output-format", "markdown")

    assert result.returncode == 0
    assert result.stderr == ""
    assert "# Authentication Analysis Report" in result.stdout


def test_missing_output_directory_returns_error(tmp_path):
    path = REPOSITORY_ROOT / "data" / "synthetic" / "ssh-failure-burst.log"
    output = tmp_path / "missing-directory" / "report.json"

    result = run_cli(path, "--format", "ssh", "--output", output)

    assert result.returncode == 1
    assert "FileNotFoundError" in result.stderr
    assert not output.exists()


def test_json_report_identifies_input_bytes():
    import hashlib

    path = REPOSITORY_ROOT / "data" / "synthetic" / "ssh-failure-burst.log"
    raw = path.read_bytes()

    result = run_cli(path, "--format", "ssh")

    assert result.returncode == 0
    report = json.loads(result.stdout)
    assert report["input_source"] == {
        "file_name": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }
