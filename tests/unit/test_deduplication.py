"""Tests for source-based deduplication."""

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from soc_evidence.deduplication import deduplicate_records
from soc_evidence.models import AuthEvent, RecordedEvent, SourceRef


def sample_record():
    return RecordedEvent(
        event=AuthEvent(
            timestamp=datetime(2026, 10, 11, 16, 0, tzinfo=UTC),
            hostname="lab-server",
            username="student",
            source_ip="192.0.2.10",
            outcome="failure",
        ),
        source=SourceRef(file_name="synthetic.log", line_number=1),
    )


def test_repeated_source_is_counted_once():
    record = sample_record()

    result = deduplicate_records([record, record, record])

    assert result.records == (record,)
    assert result.duplicates_removed == 2


def test_identical_events_on_different_lines_are_preserved():
    first = sample_record()
    second = replace(
        first,
        source=SourceRef(file_name="synthetic.log", line_number=2),
    )

    result = deduplicate_records([first, second])

    assert result.records == (first, second)
    assert result.duplicates_removed == 0


def test_conflicting_content_for_same_source_is_rejected():
    first = sample_record()
    second = replace(
        first,
        event=replace(first.event, outcome="success"),
    )

    with pytest.raises(ValueError, match="Conflicting events"):
        deduplicate_records([first, second])


def test_empty_input():
    result = deduplicate_records([])

    assert result.records == ()
    assert result.duplicates_removed == 0
