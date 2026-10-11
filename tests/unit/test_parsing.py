"""Tests for synthetic JSON parsing."""

import json
from datetime import UTC, datetime

import pytest

from soc_evidence.models import SourceRef
from soc_evidence.parsing import ParseError, parse_json_line


def valid_payload():
    return {
        "timestamp": "2026-10-11T16:00:00Z",
        "hostname": "lab-server",
        "username": "student",
        "source_ip": "192.0.2.10",
        "outcome": "failure",
    }


def test_valid_line_preserves_event_and_provenance():
    source = SourceRef(file_name="synthetic.jsonl", line_number=3)

    recorded = parse_json_line(json.dumps(valid_payload()), source)

    assert recorded.event.timestamp == datetime(2026, 10, 11, 16, 0, tzinfo=UTC)
    assert recorded.event.hostname == "lab-server"
    assert recorded.event.username == "student"
    assert recorded.event.source_ip == "192.0.2.10"
    assert recorded.event.outcome == "failure"
    assert recorded.source == source


@pytest.mark.parametrize("line", ["", "{broken", "[]", "null", "{}"])
def test_invalid_json_or_schema_is_rejected(line):
    source = SourceRef(file_name="synthetic.jsonl", line_number=4)

    with pytest.raises(ParseError, match="synthetic.jsonl:4"):
        parse_json_line(line, source)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timestamp", "not-a-date"),
        ("timestamp", "2026-10-11T16:00:00"),
        ("timestamp", 123),
        ("source_ip", "999.1.2.3"),
        ("outcome", "unknown"),
        ("unexpected_field", "extra"),
    ],
)
def test_invalid_values_and_extra_fields_are_rejected(field, value):
    payload = valid_payload()
    payload[field] = value
    source = SourceRef(file_name="synthetic.jsonl", line_number=5)

    with pytest.raises(ParseError):
        parse_json_line(json.dumps(payload), source)


def test_error_does_not_expose_input_content():
    source = SourceRef(file_name="synthetic.jsonl", line_number=6)

    with pytest.raises(ParseError) as caught:
        parse_json_line("SENSITIVE_TEST_CONTENT", source)

    assert "SENSITIVE_TEST_CONTENT" not in str(caught.value)
    assert "synthetic.jsonl:6" in str(caught.value)
