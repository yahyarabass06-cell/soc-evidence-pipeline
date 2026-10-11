# SOC Evidence Pipeline

Explainable Linux authentication detection and investigation pipeline.

## Status

Under development. Event validation, provenance, synthetic JSON Lines
and limited SSH password log ingestion are implemented.
Detection rules are not implemented yet.

## Requirements

Python 3.12 or newer and Git.
Currently verified locally with Python 3.14 only.

## Installation

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Usage

```bash
python - <<'PY'
from pathlib import Path
from soc_evidence.reading import iter_json_events

events = list(iter_json_events(Path("data/synthetic/auth-demo.jsonl")))
print(f"Completed: {len(events)} valid events")
PY
```

Expected output: `Completed: 3 valid events`.

## Quality Checks

```bash
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
```

## Architecture

JSON line → validation → authentication event → source reference

Timestamps are normalized to UTC. Each event retains its source file
and line number. Reading stops on the first invalid line.

## Security Considerations

Use authorized data and isolated laboratories.
Examples are synthetic and perform no network connections.
Do not commit real logs or credentials.
Git ignore rules are not a security boundary.

## Limitations

- JSON ingestion requires the documented synthetic schema.
- SSH ingestion supports only the password messages described below.
- Detection rules and reports are pending.
- Source references do not verify file integrity.
- Exact dependency versions are not locked yet.

## Supported SSH Input

The current parser supports:
- ISO timestamps containing a year and timezone.
- `sshd[PID]` messages.
- `Accepted password` and `Failed password`.
- Failed authentication for an `invalid user`.
- IPv4 and IPv6 addresses.
- An optional trailing `[preauth]` marker.

Read the synthetic example:

```bash
python - <<'PY'
from pathlib import Path
from soc_evidence.reading import iter_ssh_events

events = list(iter_ssh_events(Path("data/synthetic/ssh-demo.log")))
print(f"Completed: {len(events)} SSH events")
PY
```

Expected output: `Completed: 3 SSH events`.

This is not a general-purpose system log parser.
Unsupported messages stop ingestion rather than being silently ignored.
Public-key authentication, PAM messages and dates without a year or
timezone are not currently supported.
