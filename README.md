# SOC Evidence Pipeline

Explainable Linux authentication detection and investigation pipeline.

## Status

Under development. Event validation, provenance, synthetic JSON Lines
and limited SSH password log ingestion are implemented.
Three authentication detection rules are implemented: repeated failures,
success after failures, and failures across multiple accounts.

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
- Detailed reports, configurable thresholds and operational evaluation are pending.
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

## Repeated Authentication Failure Detection

Default parameters:
- Threshold: 5 failures.
- Sliding window: 120 seconds, inclusive.
- Grouping: hostname, source IP and username.

Events are sorted by timestamp before analysis.
An alert is emitted when the failure count crosses the threshold.
A new alert becomes possible after the count falls below the threshold.
Successful authentication does not clear previous failures.

Run the synthetic demonstration:

```bash
python - <<'PY'
from pathlib import Path
from soc_evidence.detection import detect_failure_bursts
from soc_evidence.reading import iter_ssh_events

path = Path("data/synthetic/ssh-failure-burst.log")
alerts = detect_failure_bursts(iter_ssh_events(path))
print(f"Completed: {len(alerts)} alerts")
PY
```

Expected output: `Completed: 1 alerts`.

These parameters are demonstration defaults, not validated production
recommendations. An alert does not prove malicious activity.
The current implementation sorts input in memory.
Repeated source references are deduplicated before detection.

## Evidence Deduplication

A source reference consists of the supplied file path and line number.

- Repeated references with identical events are counted once.
- Different source lines remain distinct, even with identical event content.
- Conflicting events for the same reference stop analysis.
- The deduplication result includes the number of duplicates removed.

This does not identify copied files under different paths.
File fingerprints and path normalization are not implemented yet.

## Success After Failures

Default parameters:
- At least 3 failures before a successful authentication.
- A 120-second lookback window, inclusive.
- Matching hostname, source IP and username.

Each successful authentication ends the previous failure sequence.
Failures with the same timestamp as the success are not considered prior.
Evidence contains the preceding failures and the final success.

Run the synthetic example:

```bash
python - <<'PY'
from pathlib import Path
from soc_evidence.detection import detect_success_after_failures
from soc_evidence.reading import iter_ssh_events

path = Path("data/synthetic/ssh-success-after-failures.log")
alerts = detect_success_after_failures(iter_ssh_events(path))
print(f"Alerts: {len(alerts)}")
PY
```

Expected output: one alert with four evidence records.

This pattern can also represent legitimate password mistakes.
The alert requires contextual investigation and does not prove compromise.

## Multi-Account Authentication Failures

Default parameters:
- At least 5 distinct usernames with failed authentication.
- A 300-second sliding window, inclusive.
- Matching hostname and source IP.

Repeated attempts against one username do not increase the account count.
Successful authentications do not count toward this rule.
An alert captures evidence at the threshold crossing.
Further attempts do not update that alert.
The rule rearms when the distinct-account count falls below the threshold.

Run the synthetic example:

```bash
python - <<'PY'
from pathlib import Path
from soc_evidence.detection import detect_multi_account_failures
from soc_evidence.reading import iter_ssh_events

path = Path("data/synthetic/ssh-multi-account.log")
alerts = detect_multi_account_failures(iter_ssh_events(path))
print(f"Alerts: {len(alerts)}")
PY
```

Expected output: one alert involving five distinct usernames.

This pattern may warrant investigation for password spraying.
Logs do not reveal attempted passwords, so the rule cannot establish
that the same password was tried across accounts.
Shared source IPs and legitimate activity may produce false positives.

## Command-Line Interface

After installation, analyze a file with:

```bash
soc-evidence data/synthetic/ssh-failure-burst.log --format ssh
soc-evidence data/synthetic/auth-demo.jsonl --format jsonl
soc-evidence --help
```

The CLI executes all three rules with their default parameters.
It prints a JSON summary containing event counts, duplicate counts
and alert counts per rule.

Results are written to stdout. Errors are written to stderr.
No completed summary is emitted if ingestion or detection fails.

Exit codes:
- 0: analysis completed, including when alerts were found.
- 1: input or analysis error.
- 2: invalid command-line arguments.

The current output is a summary, not a detailed investigation report.
