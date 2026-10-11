"""Tests for authentication event validation."""

from datetime import UTC, datetime

import pytest

from soc_evidence.models import AuthEvent


def make_event(**overrides):
    values = {
        "timestamp": datetime(2026, 10, 11, 16, 0, tzinfo=UTC),
        "hostname": "lab-server",
        "username": "student",
        "source_ip": "192.0.2.10",
        "outcome": "failure",
    }
    values.update(overrides)
    return AuthEvent(**values)


def test_timestamp_is_normalized_to_utc():
    event = make_event(timestamp=datetime.fromisoformat("2026-10-11T18:00:00+02:00"))

    assert event.timestamp == datetime(2026, 10, 11, 16, 0, tzinfo=UTC)
    assert event.timestamp.tzinfo is UTC


def test_ipv6_is_normalized():
    event = make_event(source_ip="2001:0db8:0000:0000:0000:0000:0000:0001")

    assert event.source_ip == "2001:db8::1"


@pytest.mark.parametrize("outcome", ["success", "failure"])
def test_supported_outcomes_are_accepted(outcome):
    assert make_event(outcome=outcome).outcome == outcome


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("timestamp", "not-a-date", "timestamp must be a datetime"),
        (
            "timestamp",
            datetime(2026, 10, 11, 16, 0),
            "timestamp must include a timezone",
        ),
        ("hostname", "", "hostname must be a non-empty string"),
        ("username", "   ", "username must be a non-empty string"),
        ("source_ip", None, "source_ip must be a non-empty string"),
        ("outcome", "unknown", "outcome must be success or failure"),
    ],
)
def test_invalid_fields_are_rejected(field, value, message):
    with pytest.raises(ValueError, match=message):
        make_event(**{field: value})


def test_invalid_ip_is_rejected():
    with pytest.raises(ValueError):
        make_event(source_ip="999.1.2.3")
