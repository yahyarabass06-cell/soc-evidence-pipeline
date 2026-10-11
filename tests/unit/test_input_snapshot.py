"""Tests for input fingerprinting and parsing."""

import pytest

from soc_evidence.input_snapshot import load_input


def test_empty_input_has_known_sha256(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_bytes(b"")

    snapshot = load_input(path, "jsonl")

    assert snapshot.sha256 == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert snapshot.size_bytes == 0
    assert snapshot.records == ()


def test_snapshot_preserves_size_and_source(tmp_path):
    path = tmp_path / "ssh.log"
    raw = (
        b"2026-10-11T16:00:00Z lab-server sshd[123]: "
        b"Failed password for student from 192.0.2.10 port 45000 ssh2\n"
    )
    path.write_bytes(raw)

    snapshot = load_input(path, "ssh")

    assert snapshot.size_bytes == len(raw)
    assert len(snapshot.records) == 1
    assert snapshot.records[0].source.file_name == str(path)
    assert snapshot.records[0].source.line_number == 1


def test_changed_content_changes_fingerprint(tmp_path):
    path = tmp_path / "ssh.log"
    line = (
        "2026-10-11T16:00:00Z lab-server sshd[123]: "
        "Failed password for student from 192.0.2.10 port 45000 ssh2\n"
    )
    path.write_text(line, encoding="utf-8")
    first = load_input(path, "ssh")

    path.write_text(line.replace("student", "admin"), encoding="utf-8")
    second = load_input(path, "ssh")

    assert first.sha256 != second.sha256
    assert first.records[0].event.username == "student"
    assert second.records[0].event.username == "admin"


def test_invalid_utf8_is_rejected(tmp_path):
    path = tmp_path / "invalid.jsonl"
    path.write_bytes(b"\xff")

    with pytest.raises(UnicodeDecodeError):
        load_input(path, "jsonl")
