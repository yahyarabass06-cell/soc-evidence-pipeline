"""Tests for repeated authentication failure detection."""

from datetime import UTC, datetime, timedelta

import pytest

from soc_evidence.detection import detect_failure_bursts
from soc_evidence.models import AuthEvent, RecordedEvent, SourceRef

BASE_TIME = datetime(2026, 10, 11, 16, 0, tzinfo=UTC)


def recorded_event(second, line_number, **overrides):
    values = {
        "timestamp": BASE_TIME + timedelta(seconds=second),
        "hostname": "lab-server",
        "username": "student",
        "source_ip": "192.0.2.10",
        "outcome": "failure",
    }
    values.update(overrides)
    return RecordedEvent(
        event=AuthEvent(**values),
        source=SourceRef(file_name="synthetic.log", line_number=line_number),
    )


def test_threshold_creates_one_alert_with_evidence():
    events = [recorded_event(i * 10, i + 1) for i in range(5)]

    alerts = detect_failure_bursts(events)

    assert len(alerts) == 1
    assert alerts[0].hostname == "lab-server"
    assert alerts[0].source_ip == "192.0.2.10"
    assert alerts[0].username == "student"
    assert alerts[0].evidence == tuple(events)


def test_below_threshold_produces_no_alert():
    events = [recorded_event(i * 10, i + 1) for i in range(4)]

    assert detect_failure_bursts(events) == []


@pytest.mark.parametrize(
    ("last_second", "expected_count"),
    [(120, 1), (121, 0)],
)
def test_window_boundary_is_inclusive(last_second, expected_count):
    times = [0, 30, 60, 90, last_second]
    events = [recorded_event(t, i + 1) for i, t in enumerate(times)]

    assert len(detect_failure_bursts(events)) == expected_count


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("hostname", "another-server"),
        ("username", "another-user"),
        ("source_ip", "192.0.2.20"),
    ],
)
def test_different_entities_are_not_combined(field, value):
    events = [recorded_event(i * 10, i + 1) for i in range(4)]
    events.append(recorded_event(40, 5, **{field: value}))

    assert detect_failure_bursts(events) == []


def test_successes_do_not_count_as_failures():
    events = [recorded_event(i * 10, i + 1) for i in range(4)]
    events.append(recorded_event(40, 5, outcome="success"))

    assert detect_failure_bursts(events) == []


def test_unordered_input_is_sorted():
    events = [recorded_event(i * 10, i + 1) for i in range(5)]

    assert detect_failure_bursts(reversed(events)) == detect_failure_bursts(events)


def test_continuous_burst_does_not_repeat_alerts():
    events = [recorded_event(i * 10, i + 1) for i in range(8)]

    assert len(detect_failure_bursts(events)) == 1


def test_rule_rearms_after_old_failures_expire():
    times = [0, 10, 20, 30, 40, 300, 310, 320, 330, 340]
    events = [recorded_event(t, i + 1) for i, t in enumerate(times)]

    alerts = detect_failure_bursts(events)

    assert len(alerts) == 2
    assert [item.source.line_number for item in alerts[0].evidence] == [1, 2, 3, 4, 5]
    assert [item.source.line_number for item in alerts[1].evidence] == [6, 7, 8, 9, 10]


@pytest.mark.parametrize("threshold", [0, 1, -1, True, 2.5, "5"])
def test_invalid_threshold_is_rejected(threshold):
    with pytest.raises(ValueError, match="threshold"):
        detect_failure_bursts([], threshold=threshold)


@pytest.mark.parametrize(
    "window",
    [timedelta(0), timedelta(seconds=-1), 120, None],
)
def test_invalid_window_is_rejected(window):
    with pytest.raises(ValueError, match="window"):
        detect_failure_bursts([], window=window)


def test_empty_input_produces_no_alert():
    assert detect_failure_bursts([]) == []


def test_success_does_not_erase_previous_failures():
    times = [0, 10, 20, 30, 50]
    events = [recorded_event(t, i + 1) for i, t in enumerate(times)]
    events.append(recorded_event(40, 6, outcome="success"))

    alerts = detect_failure_bursts(events)

    assert len(alerts) == 1
    assert all(item.event.outcome == "failure" for item in alerts[0].evidence)
