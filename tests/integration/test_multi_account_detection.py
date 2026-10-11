"""Integration test for multi-account failure detection."""

from pathlib import Path

from soc_evidence.detection import detect_multi_account_failures
from soc_evidence.reading import iter_ssh_events


def test_versioned_multi_account_scenario():
    repository_root = Path(__file__).resolve().parents[2]
    path = repository_root / "data" / "synthetic" / "ssh-multi-account.log"

    alerts = detect_multi_account_failures(iter_ssh_events(path))

    assert len(alerts) == 1
    assert alerts[0].hostname == "lab-server"
    assert alerts[0].source_ip == "192.0.2.10"
    assert alerts[0].usernames == ("user0", "user1", "user2", "user3", "user4")
    assert [item.source.line_number for item in alerts[0].evidence] == [1, 2, 3, 4, 5]
