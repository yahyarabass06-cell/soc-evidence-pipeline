"""Convert detection alerts into JSON-compatible evidence."""

from soc_evidence.detection import (
    FailureBurstAlert,
    MultiAccountFailureAlert,
    SuccessAfterFailuresAlert,
)

DetectionAlert = (
    FailureBurstAlert | SuccessAfterFailuresAlert | MultiAccountFailureAlert
)


def serialize_alert(rule_name: str, alert: DetectionAlert) -> dict:
    """Describe an alert without including raw log content."""
    if isinstance(alert, MultiAccountFailureAlert):
        usernames = list(alert.usernames)
    else:
        usernames = [alert.username]

    evidence = []
    for recorded in alert.evidence:
        event = recorded.event
        evidence.append(
            {
                "timestamp": event.timestamp.isoformat(),
                "hostname": event.hostname,
                "username": event.username,
                "source_ip": event.source_ip,
                "outcome": event.outcome,
                "source": {
                    "file_name": recorded.source.file_name,
                    "line_number": recorded.source.line_number,
                },
            }
        )

    return {
        "rule": rule_name,
        "hostname": alert.hostname,
        "source_ip": alert.source_ip,
        "usernames": usernames,
        "start_time": evidence[0]["timestamp"],
        "end_time": evidence[-1]["timestamp"],
        "evidence_count": len(evidence),
        "evidence": evidence,
    }
