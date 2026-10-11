"""Integration test from SSH file to detection evidence."""

from soc_evidence.detection import detect_failure_bursts
from soc_evidence.reading import iter_ssh_events


def test_ssh_file_produces_an_alert_with_source_lines(tmp_path):
    path = tmp_path / "failure-burst.log"
    lines = [
        f"2026-10-11T16:00:{second:02d}Z lab-server sshd[123]: "
        "Failed password for student from 192.0.2.10 port 45000 ssh2"
        for second in [0, 10, 20, 30, 40]
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    alerts = detect_failure_bursts(iter_ssh_events(path))

    assert len(alerts) == 1
    assert alerts[0].username == "student"
    assert [item.source.line_number for item in alerts[0].evidence] == [1, 2, 3, 4, 5]
    assert all(item.source.file_name == str(path) for item in alerts[0].evidence)
