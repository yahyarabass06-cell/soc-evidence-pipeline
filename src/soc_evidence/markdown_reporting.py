"""Render analysis reports as Markdown."""

import html
import re


def _safe_text(value: object) -> str:
    """Escape untrusted text for Markdown paragraphs and table cells."""
    text = " ".join(str(value).split())
    text = html.escape(text, quote=True)
    return re.sub(r"([\\`*_{}\[\]()#+.!|<>~-])", r"\\\1", text)


def render_markdown(report: dict) -> str:
    """Render a JSON-compatible analysis report without raw log content."""
    lines = [
        "# Authentication Analysis Report",
        "",
        f"- **Status:** {_safe_text(report['status'])}",
        f"- **Input format:** {_safe_text(report['input_format'])}",
        f"- **Records read:** {report['records_read']}",
        f"- **Unique records:** {report['unique_records']}",
        f"- **Duplicates removed:** {report['duplicates_removed']}",
        "",
        "## Configuration",
        "",
        "| Rule | Threshold | Window in seconds |",
        "|---|---:|---:|",
    ]

    for rule, settings in report["configuration"].items():
        lines.append(
            f"| {_safe_text(rule)} | {settings['threshold']} "
            f"| {settings['window_seconds']} |"
        )

    lines.extend(
        [
            "",
            "## Alert Summary",
            "",
            "| Rule | Alerts |",
            "|---|---:|",
        ]
    )
    for rule, count in report["alerts"].items():
        lines.append(f"| {_safe_text(rule)} | {count} |")

    lines.extend(["", "## Alert Details", ""])

    if not report["alert_details"]:
        lines.append("No alerts were produced by the configured rules.")

    for number, alert in enumerate(report["alert_details"], start=1):
        accounts = ", ".join(_safe_text(name) for name in alert["usernames"])
        lines.extend(
            [
                f"### Alert {number}: {_safe_text(alert['rule'])}",
                "",
                f"- **Host:** {_safe_text(alert['hostname'])}",
                f"- **Source IP:** {_safe_text(alert['source_ip'])}",
                f"- **Accounts:** {accounts}",
                f"- **Start:** {_safe_text(alert['start_time'])}",
                f"- **End:** {_safe_text(alert['end_time'])}",
                f"- **Evidence records:** {alert['evidence_count']}",
                "",
                "| Timestamp | Account | Outcome | Source file | Line |",
                "|---|---|---|---|---:|",
            ]
        )

        for item in alert["evidence"]:
            source = item["source"]
            lines.append(
                f"| {_safe_text(item['timestamp'])} "
                f"| {_safe_text(item['username'])} "
                f"| {_safe_text(item['outcome'])} "
                f"| {_safe_text(source['file_name'])} "
                f"| {source['line_number']} |"
            )
        lines.append("")

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "Alerts identify patterns requiring investigation; they do not prove",
            "malicious activity or compromise. Review the operational context.",
            "",
        ]
    )
    return "\n".join(lines)
