"""Parse a limited ISO-timestamped OpenSSH password log format."""

import re
from datetime import datetime

from soc_evidence.models import AuthEvent, RecordedEvent, SourceRef
from soc_evidence.parsing import ParseError

SSH_PASSWORD_PATTERN = re.compile(
    r"(?P<timestamp>\S+) (?P<hostname>\S+) sshd\[\d+\]: "
    r"(?P<status>Accepted|Failed) password for "
    r"(?P<invalid_user>invalid user )?"
    r"(?P<username>\S+) from (?P<source_ip>\S+) "
    r"port (?P<port>\d+) ssh2(?: \[preauth\])?"
)


def parse_ssh_password_line(line: str, source: SourceRef) -> RecordedEvent:
    """Parse one supported SSH password authentication message."""
    match = SSH_PASSWORD_PATTERN.fullmatch(line.rstrip("\r\n"))

    if match is None:
        raise ParseError(
            f"Unsupported SSH line at {source.file_name}:{source.line_number}"
        )

    fields = match.groupdict()

    try:
        port = int(fields["port"])
        if not 1 <= port <= 65535:
            raise ValueError("invalid source port")

        if fields["invalid_user"] and fields["status"] == "Accepted":
            raise ValueError("inconsistent authentication message")

        event = AuthEvent(
            timestamp=datetime.fromisoformat(fields["timestamp"]),
            hostname=fields["hostname"],
            username=fields["username"],
            source_ip=fields["source_ip"],
            outcome="success" if fields["status"] == "Accepted" else "failure",
        )
    except ValueError:
        raise ParseError(
            f"Invalid SSH event at {source.file_name}:{source.line_number}"
        ) from None

    return RecordedEvent(event=event, source=source)
