"""Detect repeated authentication failures in a sliding time window."""

from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta

from soc_evidence.deduplication import deduplicate_records
from soc_evidence.models import RecordedEvent


@dataclass(frozen=True)
class FailureBurstAlert:
    """Evidence collected when a failure threshold is crossed."""

    hostname: str
    source_ip: str
    username: str
    evidence: tuple[RecordedEvent, ...]


def detect_failure_bursts(
    events: Iterable[RecordedEvent],
    *,
    threshold: int = 5,
    window: timedelta = timedelta(minutes=2),
) -> list[FailureBurstAlert]:
    """Detect threshold crossings per host, source IP and username."""
    if type(threshold) is not int or threshold < 2:
        raise ValueError("threshold must be an integer of at least 2")

    if not isinstance(window, timedelta) or window <= timedelta(0):
        raise ValueError("window must be a positive timedelta")

    unique = deduplicate_records(events)
    ordered = sorted(unique.records, key=lambda item: item.event.timestamp)
    histories: dict[tuple[str, str, str], deque[RecordedEvent]] = {}
    alerts = []

    for recorded in ordered:
        event = recorded.event
        if event.outcome != "failure":
            continue

        key = (event.hostname, event.source_ip, event.username)
        history = histories.setdefault(key, deque())
        cutoff = event.timestamp - window

        while history and history[0].event.timestamp < cutoff:
            history.popleft()

        was_above_threshold = len(history) >= threshold
        history.append(recorded)

        if len(history) >= threshold and not was_above_threshold:
            alerts.append(
                FailureBurstAlert(
                    hostname=event.hostname,
                    source_ip=event.source_ip,
                    username=event.username,
                    evidence=tuple(history),
                )
            )

    return alerts


@dataclass(frozen=True)
class SuccessAfterFailuresAlert:
    """Failures followed by a successful authentication."""

    hostname: str
    source_ip: str
    username: str
    evidence: tuple[RecordedEvent, ...]


def detect_success_after_failures(
    events: Iterable[RecordedEvent],
    *,
    threshold: int = 3,
    window: timedelta = timedelta(minutes=2),
) -> list[SuccessAfterFailuresAlert]:
    """Detect success preceded by failures since the previous success."""
    if type(threshold) is not int or threshold < 2:
        raise ValueError("threshold must be an integer of at least 2")

    if not isinstance(window, timedelta) or window <= timedelta(0):
        raise ValueError("window must be a positive timedelta")

    unique = deduplicate_records(events)
    ordered = sorted(unique.records, key=lambda item: item.event.timestamp)
    histories: dict[tuple[str, str, str], deque[RecordedEvent]] = {}
    alerts = []

    for recorded in ordered:
        event = recorded.event
        key = (event.hostname, event.source_ip, event.username)
        history = histories.setdefault(key, deque())
        cutoff = event.timestamp - window

        while history and history[0].event.timestamp < cutoff:
            history.popleft()

        if event.outcome == "failure":
            history.append(recorded)
            continue

        preceding = tuple(
            item for item in history if item.event.timestamp < event.timestamp
        )

        if len(preceding) >= threshold:
            alerts.append(
                SuccessAfterFailuresAlert(
                    hostname=event.hostname,
                    source_ip=event.source_ip,
                    username=event.username,
                    evidence=preceding + (recorded,),
                )
            )

        history.clear()

    return alerts


@dataclass(frozen=True)
class MultiAccountFailureAlert:
    """Failed authentication targeting several distinct accounts."""

    hostname: str
    source_ip: str
    usernames: tuple[str, ...]
    evidence: tuple[RecordedEvent, ...]


def detect_multi_account_failures(
    events: Iterable[RecordedEvent],
    *,
    threshold: int = 5,
    window: timedelta = timedelta(minutes=5),
) -> list[MultiAccountFailureAlert]:
    """Detect distinct-account threshold crossings per host and source IP."""
    if type(threshold) is not int or threshold < 2:
        raise ValueError("threshold must be an integer of at least 2")

    if not isinstance(window, timedelta) or window <= timedelta(0):
        raise ValueError("window must be a positive timedelta")

    unique = deduplicate_records(events)
    ordered = sorted(unique.records, key=lambda item: item.event.timestamp)
    histories: dict[tuple[str, str], deque[RecordedEvent]] = {}
    alerts = []

    for recorded in ordered:
        event = recorded.event
        if event.outcome != "failure":
            continue

        key = (event.hostname, event.source_ip)
        history = histories.setdefault(key, deque())
        cutoff = event.timestamp - window

        while history and history[0].event.timestamp < cutoff:
            history.popleft()

        previous_users = {item.event.username for item in history}
        history.append(recorded)
        current_users = previous_users | {event.username}

        if len(previous_users) < threshold <= len(current_users):
            alerts.append(
                MultiAccountFailureAlert(
                    hostname=event.hostname,
                    source_ip=event.source_ip,
                    usernames=tuple(sorted(current_users)),
                    evidence=tuple(history),
                )
            )

    return alerts
