"""Tests for event provenance."""

from datetime import UTC, datetime

import pytest

from soc_evidence.models import AuthEvent, RecordedEvent, SourceRef


def test_recorded_event_preserves_source():
    event = AuthEvent(
        timestamp=datetime(2026, 10, 11, 16, 0, tzinfo=UTC),
        hostname="lab-server",
        username="student",
        source_ip="192.0.2.10",
        outcome="failure",
    )
    source = SourceRef(file_name="synthetic-auth.log", line_number=7)

    recorded = RecordedEvent(event=event, source=source)

    assert recorded.event is event
    assert recorded.source.file_name == "synthetic-auth.log"
    assert recorded.source.line_number == 7


@pytest.mark.parametrize("line_number", [0, -1, 1.5, "7", True])
def test_invalid_line_numbers_are_rejected(line_number):
    with pytest.raises(ValueError, match="line_number"):
        SourceRef(file_name="synthetic-auth.log", line_number=line_number)


@pytest.mark.parametrize("file_name", ["", "   ", None])
def test_invalid_file_names_are_rejected(file_name):
    with pytest.raises(ValueError, match="file_name"):
        SourceRef(file_name=file_name, line_number=1)


def test_invalid_event_is_rejected():
    source = SourceRef(file_name="synthetic-auth.log", line_number=1)

    with pytest.raises(ValueError, match="event must be an AuthEvent"):
        RecordedEvent(event=None, source=source)


def test_invalid_source_is_rejected():
    event = AuthEvent(
        timestamp=datetime(2026, 10, 11, 16, 0, tzinfo=UTC),
        hostname="lab-server",
        username="student",
        source_ip="192.0.2.10",
        outcome="failure",
    )

    with pytest.raises(ValueError, match="source must be a SourceRef"):
        RecordedEvent(event=event, source=None)
