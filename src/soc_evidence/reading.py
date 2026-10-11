"""Read authentication events from UTF-8 files."""

from collections.abc import Callable, Iterator
from pathlib import Path

from soc_evidence.models import RecordedEvent, SourceRef
from soc_evidence.parsing import parse_json_line
from soc_evidence.ssh_parsing import parse_ssh_password_line

LineParser = Callable[[str, SourceRef], RecordedEvent]


def _iter_events(path: Path, parser: LineParser) -> Iterator[RecordedEvent]:
    """Read lines using the selected parser; stop on the first error."""
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            source = SourceRef(
                file_name=str(path),
                line_number=line_number,
            )
            yield parser(line, source)


def iter_json_events(path: Path) -> Iterator[RecordedEvent]:
    """Yield events from the synthetic JSON Lines format."""
    yield from _iter_events(path, parse_json_line)


def iter_ssh_events(path: Path) -> Iterator[RecordedEvent]:
    """Yield events from the supported SSH password log format."""
    yield from _iter_events(path, parse_ssh_password_line)
