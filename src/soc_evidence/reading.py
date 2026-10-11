"""Read authentication events from UTF-8 JSON Lines files."""

from collections.abc import Iterator
from pathlib import Path

from soc_evidence.models import RecordedEvent, SourceRef
from soc_evidence.parsing import parse_json_line


def iter_json_events(path: Path) -> Iterator[RecordedEvent]:
    """Yield events in file order; stop on the first invalid line."""
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            source = SourceRef(
                file_name=str(path),
                line_number=line_number,
            )
            yield parse_json_line(line, source)
