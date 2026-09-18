import io

from network_leak_auditor.collectors import parse_connection_input


def test_parse_connection_input_from_file(tmp_path):
    input_file = tmp_path / "connections.jsonl"
    input_file.write_text(
        '{"process_name":"app","pid":5,"protocol":"TCP","remote_ip":"8.8.8.8","remote_port":443,"observed_at":"2026-01-01T00:00:00Z","domain":"API.SEGMENT.IO."}\n',
        encoding="utf-8",
    )

    records = parse_connection_input(str(input_file))

    assert len(records) == 1
    assert records[0].protocol == "tcp"
    assert records[0].remote_port == 443
    assert records[0].domain == "api.segment.io"


def test_parse_connection_input_from_stdin(monkeypatch):
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(
            '{"process_name":"app","pid":7,"protocol":"udp","remote_ip":"8.8.4.4","remote_port":53}\n'
        ),
    )

    records = parse_connection_input("-")

    assert len(records) == 1
    assert records[0].pid == 7
    assert records[0].remote_ip == "8.8.4.4"
