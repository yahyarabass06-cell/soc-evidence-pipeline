"""Integration tests for SSH file ingestion."""

import pytest

from soc_evidence.parsing import ParseError
from soc_evidence.reading import iter_ssh_events


def test_reads_ssh_file_with_provenance(tmp_path):
    path = tmp_path / "ssh.log"
    path.write_text(
        "2026-10-11T16:00:00Z lab-server sshd[123]: "
        "Failed password for student from 192.0.2.10 port 45000 ssh2\n"
        "2026-10-11T16:01:00Z lab-server sshd[123]: "
        "Accepted password for student from 192.0.2.10 port 45001 ssh2\n",
        encoding="utf-8",
    )

    events = list(iter_ssh_events(path))

    assert [item.event.outcome for item in events] == ["failure", "success"]
    assert [item.source.line_number for item in events] == [1, 2]
    assert all(item.source.file_name == str(path) for item in events)


def test_unsupported_message_is_not_silently_ignored(tmp_path):
    path = tmp_path / "unsupported.log"
    path.write_text(
        "2026-10-11T16:00:00Z lab-server sshd[123]: Connection closed\n",
        encoding="utf-8",
    )

    with pytest.raises(ParseError, match="unsupported.log:1"):
        list(iter_ssh_events(path))
