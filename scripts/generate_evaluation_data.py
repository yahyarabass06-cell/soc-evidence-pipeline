"""Generate a small labeled synthetic regression corpus."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESTINATION = ROOT / "data" / "evaluation"
BASE_TIME = datetime(2026, 10, 11, 16, 0, tzinfo=UTC)


def event(second, outcome="failure", username="student", hostname="lab-server"):
    return {
        "timestamp": (BASE_TIME + timedelta(seconds=second)).isoformat(),
        "hostname": hostname,
        "username": username,
        "source_ip": "192.0.2.10",
        "outcome": outcome,
    }


def counts(failure=0, success=0, account=0):
    return {
        "failure_burst": failure,
        "success_after_failures": success,
        "multi_account_failures": account,
    }


def main():
    scenarios = [
        (
            "normal_success",
            [event(0, outcome="success")],
            counts(),
            "benign",
            "Successful login without preceding failures.",
        ),
        (
            "two_mistakes_then_success",
            [event(0), event(10), event(20, outcome="success")],
            counts(),
            "benign",
            "Two mistakes remain below both single-account thresholds.",
        ),
        (
            "rapid_failure_burst",
            [event(t) for t in [0, 10, 20, 30, 40]],
            counts(failure=1),
            "simulated_suspicious",
            "Five failures within 120 seconds against one account.",
        ),
        (
            "success_after_three_failures",
            [event(0), event(10), event(20), event(30, outcome="success")],
            counts(success=1),
            "simulated_suspicious",
            "Three failures precede success; fewer than five failures.",
        ),
        (
            "five_accounts",
            [event(i * 10, username=f"user{i}") for i in range(5)],
            counts(account=1),
            "simulated_suspicious",
            "Five distinct accounts fail from one IP on one host.",
        ),
        (
            "slow_failures",
            [event(i * 180) for i in range(5)],
            counts(),
            "simulated_suspicious",
            "Attempts are too spread out for the configured burst rule.",
        ),
        (
            "separate_hosts",
            [event(i * 10, hostname=f"host{i}") for i in range(5)],
            counts(),
            "simulated_suspicious",
            "Each host receives only one failure.",
        ),
        (
            "legitimate_password_mistakes",
            [event(t) for t in [0, 10, 20, 30, 40]],
            counts(failure=1),
            "benign",
            "Legitimate mistakes match the failure pattern: intent is ambiguous.",
        ),
    ]

    DESTINATION.mkdir(parents=True, exist_ok=True)
    manifest = []

    for name, events, expected, intent, explanation in scenarios:
        file_name = f"{name}.jsonl"
        content = "".join(json.dumps(item) + "\n" for item in events)
        (DESTINATION / file_name).write_text(content, encoding="utf-8")
        manifest.append(
            {
                "id": name,
                "file": file_name,
                "format": "jsonl",
                "expected_alert_counts": expected,
                "intent": intent,
                "explanation": explanation,
            }
        )

    (DESTINATION / "manifest.json").write_text(
        json.dumps({"scenarios": manifest}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Generated {len(manifest)} labeled scenarios.")


if __name__ == "__main__":
    main()
