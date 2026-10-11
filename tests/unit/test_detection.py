"""Tests for repeated authentication failure detection."""

from datetime import UTC, datetime, timedelta

import pytest

from soc_evidence.detection import (
    detect_failure_bursts,
    detect_multi_account_failures,
    detect_success_after_failures,
)
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


def test_repeated_evidence_cannot_create_a_false_alert():
    events = [recorded_event(i * 10, i + 1) for i in range(4)]

    assert detect_failure_bursts(events + events) == []


def test_repeated_evidence_does_not_inflate_an_alert():
    events = [recorded_event(i * 10, i + 1) for i in range(5)]

    alerts = detect_failure_bursts(events + events)

    assert len(alerts) == 1
    assert len(alerts[0].evidence) == 5


def test_success_after_failures_keeps_all_evidence():
    events = [recorded_event(t, i + 1) for i, t in enumerate([0, 10, 20])]
    success = recorded_event(30, 4, outcome="success")

    alerts = detect_success_after_failures(events + [success])

    assert len(alerts) == 1
    assert alerts[0].username == "student"
    assert alerts[0].evidence == tuple(events + [success])


def test_success_with_too_few_failures_produces_no_alert():
    events = [
        recorded_event(0, 1),
        recorded_event(10, 2),
        recorded_event(20, 3, outcome="success"),
    ]

    assert detect_success_after_failures(events) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("hostname", "another-server"),
        ("username", "another-user"),
        ("source_ip", "192.0.2.20"),
    ],
)
def test_success_must_match_failure_entities(field, value):
    events = [recorded_event(t, i + 1) for i, t in enumerate([0, 10, 20])]
    events.append(recorded_event(30, 4, outcome="success", **{field: value}))

    assert detect_success_after_failures(events) == []


@pytest.mark.parametrize(
    ("success_second", "expected_count"),
    [(120, 1), (121, 0)],
)
def test_success_window_boundary(success_second, expected_count):
    events = [recorded_event(t, i + 1) for i, t in enumerate([0, 10, 20])]
    events.append(recorded_event(success_second, 4, outcome="success"))

    assert len(detect_success_after_failures(events)) == expected_count


def test_success_resets_the_failure_sequence():
    events = [
        recorded_event(0, 1),
        recorded_event(10, 2),
        recorded_event(20, 3, outcome="success"),
        recorded_event(30, 4),
        recorded_event(40, 5, outcome="success"),
    ]

    assert detect_success_after_failures(events) == []


def test_duplicate_failures_do_not_trigger_success_alert():
    failures = [recorded_event(0, 1), recorded_event(10, 2)]
    success = recorded_event(20, 3, outcome="success")

    assert detect_success_after_failures(failures + failures + [success]) == []


def test_failure_at_success_timestamp_is_not_preceding():
    events = [
        recorded_event(0, 1),
        recorded_event(10, 2),
        recorded_event(20, 3),
        recorded_event(20, 4, outcome="success"),
    ]

    assert detect_success_after_failures(events) == []


@pytest.mark.parametrize("threshold", [0, 1, True, 2.5, "3"])
def test_success_rule_rejects_invalid_threshold(threshold):
    with pytest.raises(ValueError, match="threshold"):
        detect_success_after_failures([], threshold=threshold)


@pytest.mark.parametrize(
    "window",
    [timedelta(0), timedelta(seconds=-1), 120, None],
)
def test_success_rule_rejects_invalid_window(window):
    with pytest.raises(ValueError, match="window"):
        detect_success_after_failures([], window=window)


def test_success_rule_sorts_unordered_input():
    events = [recorded_event(t, i + 1) for i, t in enumerate([0, 10, 20])]
    events.append(recorded_event(30, 4, outcome="success"))

    expected = detect_success_after_failures(events)

    assert len(expected) == 1
    assert detect_success_after_failures(reversed(events)) == expected


def test_second_success_does_not_reuse_previous_failures():
    events = [recorded_event(t, i + 1) for i, t in enumerate([0, 10, 20])]
    events.extend(
        [
            recorded_event(30, 4, outcome="success"),
            recorded_event(40, 5, outcome="success"),
        ]
    )

    assert len(detect_success_after_failures(events)) == 1


def account_failures(times):
    return [recorded_event(t, i + 1, username=f"user{i}") for i, t in enumerate(times)]


def test_multi_account_alert_keeps_users_and_evidence():
    events = account_failures([0, 10, 20, 30, 40])

    alerts = detect_multi_account_failures(events)

    assert len(alerts) == 1
    assert alerts[0].usernames == ("user0", "user1", "user2", "user3", "user4")
    assert alerts[0].evidence == tuple(events)


def test_many_failures_for_one_account_do_not_trigger_multi_account_rule():
    events = [recorded_event(i, i + 1) for i in range(10)]

    assert detect_multi_account_failures(events) == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("hostname", "another-server"),
        ("source_ip", "192.0.2.20"),
    ],
)
def test_multi_account_rule_separates_hosts_and_ips(field, value):
    events = account_failures([0, 10, 20, 30])
    events.append(recorded_event(40, 5, username="user4", **{field: value}))

    assert detect_multi_account_failures(events) == []


@pytest.mark.parametrize(
    ("last_second", "expected_count"),
    [(300, 1), (301, 0)],
)
def test_multi_account_window_boundary(last_second, expected_count):
    events = account_failures([0, 10, 20, 30, last_second])

    assert len(detect_multi_account_failures(events)) == expected_count


def test_multi_account_rule_rearms_after_expiration():
    events = account_failures([0, 10, 20, 30, 40, 600, 610, 620, 630, 640])

    assert len(detect_multi_account_failures(events)) == 2


def test_duplicates_do_not_inflate_distinct_account_count():
    events = account_failures([0, 10, 20, 30])

    assert detect_multi_account_failures(events + events) == []


def test_successful_accounts_do_not_count_for_multi_account_rule():
    events = account_failures([0, 10, 20, 30])
    events.append(recorded_event(40, 5, username="user4", outcome="success"))

    assert detect_multi_account_failures(events) == []


@pytest.mark.parametrize("threshold", [0, 1, True, 2.5, "5"])
def test_multi_account_rule_rejects_invalid_threshold(threshold):
    with pytest.raises(ValueError, match="threshold"):
        detect_multi_account_failures([], threshold=threshold)


@pytest.mark.parametrize(
    "window",
    [timedelta(0), timedelta(seconds=-1), 300, None],
)
def test_multi_account_rule_rejects_invalid_window(window):
    with pytest.raises(ValueError, match="window"):
        detect_multi_account_failures([], window=window)


def test_multi_account_rule_sorts_unordered_input():
    events = account_failures([0, 10, 20, 30, 40])

    expected = detect_multi_account_failures(events)

    assert len(expected) == 1
    assert detect_multi_account_failures(reversed(events)) == expected


def test_continuous_multi_account_burst_emits_one_alert():
    events = account_failures([0, 10, 20, 30, 40, 50, 60])

    alerts = detect_multi_account_failures(events)

    assert len(alerts) == 1
    assert len(alerts[0].usernames) == 5
