"""Tests for the supported SSH password log format."""

import pytest

from soc_evidence.models import SourceRef
from soc_evidence.parsing import ParseError
from soc_evidence.ssh_parsing import parse_ssh_password_line


@pytest.mark.parametrize(
    ("message", "username", "source_ip", "outcome"),
    [
        (
            "Failed password for student from 192.0.2.10 port 45000 ssh2",
            "student",
            "192.0.2.10",
            "failure",
        ),
        (
            "Accepted password for student from 192.0.2.10 port 45000 ssh2",
            "student",
            "192.0.2.10",
            "success",
        ),
        (
            "Failed password for invalid user admin "
            "from 192.0.2.10 port 45000 ssh2 [preauth]",
            "admin",
            "192.0.2.10",
            "failure",
        ),
        (
            "Failed password for student from 2001:db8::1 port 45000 ssh2",
            "student",
            "2001:db8::1",
            "failure",
        ),
    ],
)
def test_supported_messages(message, username, source_ip, outcome):
    source = SourceRef(file_name="synthetic-ssh.log", line_number=2)
    line = f"2026-10-11T16:00:00Z lab-server sshd[123]: {message}\n"

    recorded = parse_ssh_password_line(line, source)

    assert recorded.event.username == username
    assert recorded.event.source_ip == source_ip
    assert recorded.event.outcome == outcome
    assert recorded.event.hostname == "lab-server"
    assert recorded.source == source


@pytest.mark.parametrize(
    "line",
    [
        "Oct 11 16:00:00 lab-server sshd[123]: "
        "Failed password for student from 192.0.2.10 port 45000 ssh2",
        "2026-10-11T16:00:00Z lab-server sshd[123]: "
        "Failed password for student from 999.1.2.3 port 45000 ssh2",
        "2026-10-11T16:00:00Z lab-server sshd[123]: "
        "Failed password for student from 192.0.2.10 port 70000 ssh2",
        "2026-10-11T16:00:00Z lab-server sshd[123]: "
        "Accepted password for invalid user admin "
        "from 192.0.2.10 port 45000 ssh2",
    ],
)
def test_invalid_or_unsupported_lines_are_rejected(line):
    source = SourceRef(file_name="synthetic-ssh.log", line_number=5)

    with pytest.raises(ParseError, match="synthetic-ssh.log:5"):
        parse_ssh_password_line(line, source)
