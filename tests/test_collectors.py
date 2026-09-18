from collections import namedtuple
from datetime import datetime, timezone

import psutil

from network_leak_auditor.collectors import collect_psutil_snapshot


def test_collect_psutil_snapshot_filters_and_normalizes(monkeypatch):
    address = namedtuple("addr", ["ip", "port"])
    connection = namedtuple("conn", ["type", "status", "raddr", "pid"])

    fake_connections = [
        connection(psutil.socket.SOCK_STREAM, psutil.CONN_ESTABLISHED, address("8.8.8.8", 443), 11),
        connection(psutil.socket.SOCK_STREAM, "LISTEN", address("1.1.1.1", 443), 11),
        connection(psutil.socket.SOCK_DGRAM, "", address("9.9.9.9", 53), 12),
        connection(psutil.socket.SOCK_STREAM, psutil.CONN_ESTABLISHED, address("192.168.1.10", 443), 13),
    ]

    class FakeProcess:
        def __init__(self, pid):
            self.pid = pid

        def name(self):
            return f"proc-{self.pid}"

    monkeypatch.setattr("network_leak_auditor.collectors.psutil.net_connections", lambda kind: fake_connections)
    monkeypatch.setattr("network_leak_auditor.collectors.psutil.Process", FakeProcess)
    monkeypatch.setattr(
        "network_leak_auditor.collectors.utc_now",
        lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    records = collect_psutil_snapshot()

    assert [(record.protocol, record.remote_ip, record.remote_port) for record in records] == [
        ("tcp", "8.8.8.8", 443),
        ("udp", "9.9.9.9", 53),
    ]
    assert [record.process_name for record in records] == ["proc-11", "proc-12"]
