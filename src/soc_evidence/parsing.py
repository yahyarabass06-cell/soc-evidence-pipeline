"""Parse synthetic JSON authentication events."""

import json
from datetime import datetime

from soc_evidence.models import AuthEvent, RecordedEvent, SourceRef

EXPECTED_FIELDS = {
    "timestamp",
    "hostname",
    "username",
    "source_ip",
    "outcome",
}


class ParseError(ValueError):
    """An input line cannot be converted to an authentication event."""


def parse_json_line(line: str, source: SourceRef) -> RecordedEvent:
    """Parse one JSON object using a strict input schema."""
    try:
        payload = json.loads(line)

        if not isinstance(payload, dict):
            raise ValueError("expected a JSON object")

        if set(payload) != EXPECTED_FIELDS:
            raise ValueError("unexpected schema")

        if not isinstance(payload["timestamp"], str):
            raise ValueError("timestamp must be a string")

        event = AuthEvent(
            timestamp=datetime.fromisoformat(payload["timestamp"]),
            hostname=payload["hostname"],
            username=payload["username"],
            source_ip=payload["source_ip"],
            outcome=payload["outcome"],
        )
    except ValueError:
        raise ParseError(
            f"Invalid authentication event at {source.file_name}:{source.line_number}"
        ) from None

    return RecordedEvent(event=event, source=source)
