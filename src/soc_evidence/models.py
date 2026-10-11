"""Validated authentication events used by detection rules."""

from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Literal


@dataclass(frozen=True)
class AuthEvent:
    """An immutable remote authentication event."""

    timestamp: datetime
    hostname: str
    username: str
    source_ip: str
    outcome: Literal["success", "failure"]

    def __post_init__(self) -> None:
        if not isinstance(self.timestamp, datetime):
            raise ValueError("timestamp must be a datetime")

        if self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")

        for field_name in ("hostname", "username", "source_ip"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")

        if self.outcome not in ("success", "failure"):
            raise ValueError("outcome must be success or failure")

        normalized_ip = str(ip_address(self.source_ip))

        object.__setattr__(self, "source_ip", normalized_ip)
        object.__setattr__(self, "timestamp", self.timestamp.astimezone(UTC))


@dataclass(frozen=True)
class SourceRef:
    """Location of an event in its input file."""

    file_name: str
    line_number: int

    def __post_init__(self) -> None:
        if not isinstance(self.file_name, str) or not self.file_name.strip():
            raise ValueError("file_name must be a non-empty string")

        if type(self.line_number) is not int or self.line_number < 1:
            raise ValueError("line_number must be a positive integer")


@dataclass(frozen=True)
class RecordedEvent:
    """An authentication event linked to its source."""

    event: AuthEvent
    source: SourceRef

    def __post_init__(self) -> None:
        if not isinstance(self.event, AuthEvent):
            raise ValueError("event must be an AuthEvent")

        if not isinstance(self.source, SourceRef):
            raise ValueError("source must be a SourceRef")
