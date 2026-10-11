"""Write reports without overwriting existing files."""

import os
from pathlib import Path


def write_new_report(path: Path, content: str) -> None:
    """Create a UTF-8 report with owner-only permissions on Linux."""
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
