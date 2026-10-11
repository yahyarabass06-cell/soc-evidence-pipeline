"""Integration test for the versioned success-after-failures scenario."""

from pathlib import Path

from soc_evidence.detection import detect_success_after_failures
from soc_evidence.reading import iter_ssh_events


def test_versioned_ssh_scenario_produces_expected_evidence():
    repository_root = Path(__file__).resolve().parents[2]
    path = repository_root / "data" / "synthetic" / "ssh-success-after-failures.log"

    alerts = detect_success_after_failures(iter_ssh_events(path))

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.hostname == "lab-server"
    assert alert.source_ip == "192.0.2.10"
    assert alert.username == "student"
    assert [item.event.outcome for item in alert.evidence] == [
        "failure",
        "failure",
        "failure",
        "success",
    ]
    assert [item.source.line_number for item in alert.evidence] == [1, 2, 3, 4]
