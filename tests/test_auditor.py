from datetime import datetime, timezone
import io
import json
import socket
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from network_leak_auditor.auditor import (
    ConnectionRecord,
    VISIBILITY_WARNING_MESSAGE,
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

    records, visibility_restricted = collect_connections(
        include_private=False,
        net_connections=lambda kind: connections,
        process_lookup=lambda pid: f"proc-{pid}",
    )

    assert visibility_restricted is False
    assert records == [
        ConnectionRecord("proc-100", 100, "tcp", "8.8.8.8", 443),
        ConnectionRecord("proc-103", 103, "udp", "1.1.1.1", 53),
    ]


def test_collect_connections_ignores_invalid_remote_ip() -> None:
    connections = [
        SimpleNamespace(type=socket.SOCK_STREAM, status="ESTABLISHED", raddr=("not-an-ip", 443), pid=100),
    ]

    records, visibility_restricted = collect_connections(
        include_private=False,
        net_connections=lambda kind: connections,
        process_lookup=lambda pid: f"proc-{pid}",
    )

    assert visibility_restricted is False
    assert records == []


def test_collect_connections_sets_visibility_warning_when_net_connections_denied() -> None:
    def denied(kind: str):
        raise PermissionError("unexpected")

    def denied_psutil(kind: str):
        raise psutil.AccessDenied()

    with pytest.raises(PermissionError):
        collect_connections(net_connections=denied)

    records, visibility_restricted = collect_connections(net_connections=denied_psutil)

    assert records == []
    assert visibility_restricted is True


def test_collect_connections_sets_visibility_warning_when_process_name_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeProcess:
        def __init__(self, pid: int) -> None:
            self.pid = pid

        def name(self) -> str:
            raise psutil.AccessDenied(pid=self.pid)

    monkeypatch.setattr("network_leak_auditor.auditor.psutil.Process", FakeProcess)
    records, visibility_restricted = collect_connections(
        include_private=False,
        net_connections=lambda kind: [SimpleNamespace(type=socket.SOCK_STREAM, status="ESTABLISHED", raddr=("8.8.8.8", 443), pid=123)],
    )

    assert records == [ConnectionRecord("unknown", 123, "tcp", "8.8.8.8", 443)]
    assert visibility_restricted is True


def test_visibility_warning_fires_when_net_connections_denied() -> None:
    records, visibility_restricted = collect_connections(net_connections=lambda kind: (_ for _ in ()).throw(psutil.AccessDenied()))
    report = build_report(
        [],
        ["trackers.txt"],
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        visibility_warning=VISIBILITY_WARNING_MESSAGE if visibility_restricted else None,
    )

    assert records == []
    assert report["visibility_warning"] == VISIBILITY_WARNING_MESSAGE
    assert f"WARNING: {VISIBILITY_WARNING_MESSAGE}" in render_report(report, "text")


def test_visibility_warning_fires_when_process_name_denied_in_report(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeProcess:
        def __init__(self, pid: int) -> None:
            self.pid = pid

        def name(self) -> str:
            raise psutil.AccessDenied(pid=self.pid)

    monkeypatch.setattr("network_leak_auditor.auditor.psutil.Process", FakeProcess)
    records, visibility_restricted = collect_connections(
        net_connections=lambda kind: [SimpleNamespace(type=socket.SOCK_STREAM, status="ESTABLISHED", raddr=("8.8.8.8", 443), pid=321)],
    )
    aggregate = {}

    update_aggregate(
        aggregate,
        records,
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        resolver=None,
        mappings={},
        loaded_lists=[("trackers.txt", {"segment.io"})],
        resolve_rdns=False,
    )
    report = build_report(
        list(aggregate.values()),
        ["trackers.txt"],
        datetime(2026, 1, 1, tzinfo=timezone.utc),
        visibility_warning=VISIBILITY_WARNING_MESSAGE if visibility_restricted else None,
    )

    assert report["visibility_warning"] == VISIBILITY_WARNING_MESSAGE


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
        "unclassified": 0,
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
    assert report["visibility_warning"] is None


def test_render_report_csv_contains_expected_columns() -> None:
    report = {
        "tool": "network-leak-auditor",
        "version": "0.1.0",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "host": "test-host",
        "visibility_warning": None,
        "summary": {"connections_seen": 1, "unique_destinations": 1, "flagged": 0, "unclassified": 1, "lists_used": ["trackers.txt"]},
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


def test_render_text_includes_unclassified_and_warning() -> None:
    report = {
        "tool": "network-leak-auditor",
        "version": "0.1.0",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "host": "test-host",
        "visibility_warning": VISIBILITY_WARNING_MESSAGE,
        "summary": {"connections_seen": 1, "unique_destinations": 1, "flagged": 0, "unclassified": 1, "lists_used": ["trackers.txt"]},
        "findings": [],
    }

    rendered = render_report(report, "text")

    assert "Unclassified: 1 destination(s) did not match any list" in rendered
    assert f"WARNING: {VISIBILITY_WARNING_MESSAGE}" in rendered


def test_scan_with_input_file_uses_pipeline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    input_path = tmp_path / "capture.jsonl"
    list_path = tmp_path / "trackers.txt"
    input_path.write_text(
        '{"process_name":"python","pid":123,"protocol":"tcp","remote_ip":"8.8.8.8","remote_port":443}\n',
        encoding="utf-8",
    )
    list_path.write_text("segment.io\n", encoding="utf-8")

    class Resolver:
        def __init__(self) -> None:
            self.calls = 0

        def lookup(self, ip_address: str) -> str:
            self.calls += 1
            assert ip_address == "8.8.8.8"
            return "api.segment.io"

        def close(self) -> None:
            pass

    resolver = Resolver()
    monkeypatch.setattr("network_leak_auditor.cli.ReverseDNSResolver", lambda: resolver)
    monkeypatch.setattr(
        "network_leak_auditor.cli.collect_connections",
        lambda **kwargs: (_ for _ in ()).throw(AssertionError("live collection should be skipped with --input")),
    )

    exit_code = main(["scan", "--input", str(input_path), "--format", "json", "--list", str(list_path)])
    assert exit_code == 1
    captured = json.loads(capsys.readouterr().out)
    assert captured["summary"]["flagged"] == 1
    assert captured["summary"]["unclassified"] == 0
    assert captured["visibility_warning"] is None


def test_scan_with_stdin_input_and_no_rdns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    list_path = tmp_path / "trackers.txt"
    mapping_path = tmp_path / "mapping.txt"
    list_path.write_text("example.test\n", encoding="utf-8")
    mapping_path.write_text("mapped.example.test=1.1.1.1\n", encoding="utf-8")
    payload = '{"process_name":"curl","pid":42,"protocol":"tcp","remote_ip":"1.1.1.1","remote_port":443}\n'
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))

    class FailingResolver:
        def __init__(self) -> None:
            raise AssertionError("resolver should not be created when --no-rdns is set")

    monkeypatch.setattr("network_leak_auditor.cli.ReverseDNSResolver", FailingResolver)
    exit_code = main(
        [
            "scan",
            "--input",
            "-",
            "--format",
            "json",
            "--no-rdns",
            "--mapping-file",
            str(mapping_path),
            "--list",
            str(list_path),
        ]
    )

    assert exit_code == 1
    captured = json.loads(capsys.readouterr().out)
    assert captured["findings"][0]["domain"] == "mapped.example.test"
    assert captured["findings"][0]["matched_domain"] == "example.test"


def test_scan_with_malformed_input_returns_exit_code_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    list_path = tmp_path / "trackers.txt"
    list_path.write_text("segment.io\n", encoding="utf-8")
    input_path = tmp_path / "bad.jsonl"
    input_path.write_text('{"process_name":"python","pid":123}\n', encoding="utf-8")

    exit_code = main(["scan", "--input", str(input_path), "--list", str(list_path)])

    assert exit_code == 2
    assert "--input line 1: missing required key 'protocol'" in capsys.readouterr().err


def test_scan_cli_access_denied_sets_visibility_warning_in_json_and_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    list_path = tmp_path / "trackers.txt"
    list_path.write_text("segment.io\n", encoding="utf-8")

    monkeypatch.setattr(
        "network_leak_auditor.cli.collect_connections",
        lambda **kwargs: collect_connections(
            net_connections=lambda kind: (_ for _ in ()).throw(psutil.AccessDenied())
        ),
    )

    exit_code = main(["scan", "--list", str(list_path), "--format", "json"])
    assert exit_code == 0
    json_report = json.loads(capsys.readouterr().out)
    assert json_report["visibility_warning"] == VISIBILITY_WARNING_MESSAGE

    exit_code = main(["scan", "--list", str(list_path), "--format", "text"])
    assert exit_code == 0
    text_report = capsys.readouterr().out
    assert f"WARNING: {VISIBILITY_WARNING_MESSAGE}" in text_report
