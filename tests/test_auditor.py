from datetime import datetime, timezone
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from network_leak_auditor.auditor import (
    ConnectionRecord,
    ReverseDNSResolver,
    build_report,
    collect_connections,
    match_domain,
    parse_domain_list,
    parse_mapping_file,
    render_report,
    update_aggregate,
)
from network_leak_auditor.cli import build_parser, main


def test_parse_domain_list_ignores_comments_blanks_and_case(tmp_path: Path) -> None:
    path = tmp_path / "trackers.txt"
    path.write_text("\n# comment\nExample.COM\n example.com  # duplicate\n\nSub.Example.org\n", encoding="utf-8")

    domains = parse_domain_list(path)

    assert domains == {"example.com", "sub.example.org"}


def test_parse_mapping_file_parses_domain_ip_pairs(tmp_path: Path) -> None:
    path = tmp_path / "mappings.txt"
    path.write_text("cdn.example.com=1.1.1.1, 8.8.8.8\n", encoding="utf-8")

    mappings = parse_mapping_file(path)

    assert mappings == {"1.1.1.1": "cdn.example.com", "8.8.8.8": "cdn.example.com"}


def test_match_domain_supports_exact_and_suffix_matching() -> None:
    loaded_lists = [("trackers.txt", {"example.com", "segment.io"})]

    assert match_domain("example.com", loaded_lists) == ("example.com", "trackers.txt")
    assert match_domain("api.segment.io", loaded_lists) == ("segment.io", "trackers.txt")
    assert match_domain("example.org", loaded_lists) == (None, None)


def test_collect_connections_filters_private_and_non_established() -> None:
    connections = [
        SimpleNamespace(type=socket.SOCK_STREAM, status="ESTABLISHED", raddr=("8.8.8.8", 443), pid=100),
        SimpleNamespace(type=socket.SOCK_STREAM, status="LISTEN", raddr=("8.8.4.4", 443), pid=101),
        SimpleNamespace(type=socket.SOCK_DGRAM, status="", raddr=("192.168.1.10", 53), pid=102),
        SimpleNamespace(type=socket.SOCK_DGRAM, status="", raddr=("1.1.1.1", 53), pid=103),
    ]

    records = collect_connections(
        include_private=False,
        net_connections=lambda kind: connections,
        process_lookup=lambda pid: f"proc-{pid}",
    )

    assert records == [
        ConnectionRecord("proc-100", 100, "tcp", "8.8.8.8", 443),
        ConnectionRecord("proc-103", 103, "udp", "1.1.1.1", 53),
    ]


def test_collect_connections_ignores_invalid_remote_ip() -> None:
    connections = [
        SimpleNamespace(type=socket.SOCK_STREAM, status="ESTABLISHED", raddr=("not-an-ip", 443), pid=100),
    ]

    records = collect_connections(
        include_private=False,
        net_connections=lambda kind: connections,
        process_lookup=lambda pid: f"proc-{pid}",
    )

    assert records == []


def test_reverse_dns_resolver_caches_success_and_handles_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_gethostbyaddr(ip_address: str):
        calls.append(ip_address)
        if ip_address == "8.8.8.8":
            return ("Api.Segment.io", [], [ip_address])
        raise socket.herror("lookup failed")

    monkeypatch.setattr("network_leak_auditor.auditor.socket.gethostbyaddr", fake_gethostbyaddr)
    resolver = ReverseDNSResolver(timeout=0.1)
    try:
        assert resolver.lookup("8.8.8.8") == "api.segment.io"
        assert resolver.lookup("8.8.8.8") == "api.segment.io"
        assert resolver.lookup("1.1.1.1") is None
    finally:
        resolver.close()

    assert calls == ["8.8.8.8", "1.1.1.1"]


def test_aggregation_and_report_shape() -> None:
    aggregate = {}
    records = [
        ConnectionRecord("python", 123, "tcp", "8.8.8.8", 443),
        ConnectionRecord("python", 123, "udp", "8.8.8.8", 443),
    ]

    class Resolver:
        def lookup(self, ip_address: str) -> str:
            assert ip_address == "8.8.8.8"
            return "api.segment.io"

    update_aggregate(
        aggregate,
        records,
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        Resolver(),
        {},
        [("trackers.txt", {"segment.io"})],
    )
    update_aggregate(
        aggregate,
        records,
        datetime(2026, 1, 1, 0, 0, 5, tzinfo=timezone.utc),
        Resolver(),
        {},
        [("trackers.txt", {"segment.io"})],
    )

    report = build_report(list(aggregate.values()), ["trackers.txt"], datetime(2026, 1, 1, 0, 0, 10, tzinfo=timezone.utc))

    assert report["tool"] == "network-leak-auditor"
    assert report["summary"] == {
        "connections_seen": 4,
        "unique_destinations": 2,
        "flagged": 2,
        "lists_used": ["trackers.txt"],
    }
    assert report["findings"] == [
        {
            "process_name": "python",
            "pid": 123,
            "protocol": "tcp",
            "remote_ip": "8.8.8.8",
            "remote_port": 443,
            "domain": "api.segment.io",
            "matched_domain": "segment.io",
            "list_name": "trackers.txt",
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:00:05+00:00",
            "count": 2,
    },
    {
        "process_name": "python",
        "pid": 123,
        "protocol": "udp",
        "remote_ip": "8.8.8.8",
        "remote_port": 443,
        "domain": "api.segment.io",
        "matched_domain": "segment.io",
        "list_name": "trackers.txt",
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-01T00:00:05+00:00",
        "count": 2,
    },
    ]


def test_render_report_csv_contains_expected_columns() -> None:
    report = {
        "tool": "network-leak-auditor",
        "version": "0.1.0",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "host": "test-host",
        "summary": {"connections_seen": 1, "unique_destinations": 1, "flagged": 0, "lists_used": ["trackers.txt"]},
        "findings": [
            {
                "process_name": "python",
                "pid": 1,
                "protocol": "tcp",
                "remote_ip": "8.8.8.8",
                "remote_port": 443,
                "domain": "dns.google",
                "matched_domain": None,
                "list_name": None,
                "first_seen": "2026-01-01T00:00:00+00:00",
                "last_seen": "2026-01-01T00:00:00+00:00",
                "count": 1,
            }
        ],
    }

    rendered = render_report(report, "csv")

    assert "process_name,pid,protocol,remote_ip,remote_port,domain,matched_domain,list_name,first_seen,last_seen,count" in rendered
    assert "python,1,tcp,8.8.8.8,443,dns.google" in rendered


def test_watch_parser_rejects_non_positive_values() -> None:
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["watch", "--interval", "0"])

    with pytest.raises(SystemExit):
        parser.parse_args(["watch", "--duration", "-1"])


def test_main_reports_mapping_file_context(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["scan", "--mapping-file", "missing-mappings.txt"])

    assert exit_code == 2
    assert "--mapping-file not found: missing-mappings.txt" in capsys.readouterr().err
