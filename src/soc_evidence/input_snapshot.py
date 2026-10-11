"""Analyze the same input bytes used to compute file provenance."""

import hashlib
import io
from dataclasses import dataclass
from pathlib import Path

from soc_evidence.models import RecordedEvent, SourceRef
from soc_evidence.parsing import parse_json_line
from soc_evidence.ssh_parsing import parse_ssh_password_line


@dataclass(frozen=True)
class InputSnapshot:
    """Parsed records and the identity of their original byte content."""

    file_name: str
    sha256: str
    size_bytes: int
    records: tuple[RecordedEvent, ...]


def load_input(path: Path, input_format: str) -> InputSnapshot:
    """Read once, hash original bytes, then parse their UTF-8 content."""
    parsers = {
        "jsonl": parse_json_line,
        "ssh": parse_ssh_password_line,
    }
    if input_format not in parsers:
        raise ValueError("unsupported input format")

    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8")
    records = []

    with io.StringIO(text, newline=None) as stream:
        for line_number, line in enumerate(stream, start=1):
            source = SourceRef(
                file_name=str(path),
                line_number=line_number,
            )
            records.append(parsers[input_format](line, source))

    return InputSnapshot(
        file_name=str(path),
        sha256=digest,
        size_bytes=len(raw),
        records=tuple(records),
    )
