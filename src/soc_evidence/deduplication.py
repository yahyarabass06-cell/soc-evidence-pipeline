"""Deduplicate records by source reference."""

from collections.abc import Iterable
from dataclasses import dataclass

from soc_evidence.models import AuthEvent, RecordedEvent, SourceRef


@dataclass(frozen=True)
class DeduplicationResult:
    """Unique records and the number of duplicate records removed."""

    records: tuple[RecordedEvent, ...]
    duplicates_removed: int


def deduplicate_records(
    records: Iterable[RecordedEvent],
) -> DeduplicationResult:
    """Preserve distinct sources and reject conflicting source content."""
    seen: dict[SourceRef, AuthEvent] = {}
    unique = []
    duplicates_removed = 0

    for recorded in records:
        if recorded.source in seen:
            if seen[recorded.source] != recorded.event:
                raise ValueError(
                    f"Conflicting events at "
                    f"{recorded.source.file_name}:{recorded.source.line_number}"
                )
            duplicates_removed += 1
            continue

        seen[recorded.source] = recorded.event
        unique.append(recorded)

    return DeduplicationResult(
        records=tuple(unique),
        duplicates_removed=duplicates_removed,
    )
