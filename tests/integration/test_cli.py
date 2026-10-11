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
