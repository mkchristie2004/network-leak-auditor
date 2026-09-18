from network_leak_auditor.enrich import ReverseDNSResolver, enrich_records
from network_leak_auditor.models import ConnectionRecord, utc_now


def test_reverse_dns_enrichment_uses_cache(monkeypatch):
    calls = []

    def fake_gethostbyaddr(remote_ip):
        calls.append(remote_ip)
        return ("collector.example.com", [], [])

    monkeypatch.setattr("network_leak_auditor.enrich.socket.gethostbyaddr", fake_gethostbyaddr)

    records = [
        ConnectionRecord("proc", 1, "tcp", "8.8.8.8", 443, utc_now()),
        ConnectionRecord("proc", 1, "tcp", "8.8.8.8", 443, utc_now()),
    ]

    enriched = enrich_records(records, ReverseDNSResolver())

    assert [record.domain for record in enriched] == ["collector.example.com", "collector.example.com"]
    assert calls == ["8.8.8.8"]
