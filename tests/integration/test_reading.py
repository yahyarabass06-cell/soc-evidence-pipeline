"""Integration tests for file ingestion."""

import json

import pytest

from soc_evidence.parsing import ParseError
from soc_evidence.reading import iter_json_events


def event_line(outcome="failure"):
    return json.dumps(
        {
            "timestamp": "2026-10-11T16:00:00Z",
            "hostname": "lab-server",
            "username": "student",
            "source_ip": "192.0.2.10",
            "outcome": outcome,
        }
    )


def test_reads_events_in_order_with_line_numbers(tmp_path):
    path = tmp_path / "auth.jsonl"
    path.write_text(
        event_line() + "\n" + event_line("success") + "\n",
        encoding="utf-8",
    )

    events = list(iter_json_events(path))

    assert [item.event.outcome for item in events] == ["failure", "success"]
    assert [item.source.line_number for item in events] == [1, 2]
    assert all(item.source.file_name == str(path) for item in events)


def test_empty_file_contains_no_events(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")

    assert list(iter_json_events(path)) == []


@pytest.mark.parametrize("invalid_line", ["{broken", ""])
def test_invalid_line_stops_reading(tmp_path, invalid_line):
    path = tmp_path / "invalid.jsonl"
    path.write_text(
        event_line() + "\n" + invalid_line + "\n" + event_line() + "\n",
        encoding="utf-8",
    )
    events = iter_json_events(path)

    assert next(events).source.line_number == 1

    with pytest.raises(ParseError, match="invalid.jsonl:2"):
        next(events)


def test_missing_file_raises_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        list(iter_json_events(tmp_path / "missing.jsonl"))


def test_invalid_utf8_raises_an_error(tmp_path):
    path = tmp_path / "invalid-encoding.jsonl"
    path.write_bytes(b"\xff\n")

    with pytest.raises(UnicodeDecodeError):
        list(iter_json_events(path))
