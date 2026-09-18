from datetime import datetime, timezone

from network_leak_auditor.matching import DomainMatcher, RuleList
from network_leak_auditor.models import ConnectionRecord
from network_leak_auditor.reporting import build_report


def test_build_report_matches_schema_shape():
    record = ConnectionRecord(
        process_name="browser",
        pid=321,
        protocol="tcp",
        remote_ip="8.8.8.8",
        remote_port=443,
        observed_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        domain="api.segment.io",
    )
    rule_lists = [RuleList(name="starter", domains=("segment.io",))]
    report = build_report([record], DomainMatcher(rule_lists), rule_lists)

    assert set(report) == {"tool", "version", "generated_at", "host", "summary", "findings"}
    assert set(report["summary"]) == {
        "connections_seen",
        "unique_destinations",
        "flagged",
        "lists_used",
    }
    assert set(report["findings"][0]) == {
        "process_name",
        "pid",
        "protocol",
        "remote_ip",
        "remote_port",
        "domain",
        "matched_domain",
        "list_name",
        "first_seen",
        "last_seen",
        "count",
    }


def test_build_report_aggregates_duplicate_findings():
    first = datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc)
    second = datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc)
    records = [
        ConnectionRecord("browser", 1, "tcp", "8.8.8.8", 443, first, domain="api.segment.io"),
        ConnectionRecord("browser", 1, "tcp", "8.8.8.8", 443, second, domain="api.segment.io"),
    ]
    rule_lists = [RuleList(name="starter", domains=("segment.io",))]

    report = build_report(records, DomainMatcher(rule_lists), rule_lists)

    assert report["summary"]["connections_seen"] == 2
    assert report["summary"]["unique_destinations"] == 1
    assert report["summary"]["flagged"] == 1
    assert report["findings"][0]["count"] == 2
    assert report["findings"][0]["first_seen"] == "2026-01-01T00:00:00Z"
    assert report["findings"][0]["last_seen"] == "2026-01-01T00:05:00Z"
