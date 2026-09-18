import csv
import io
import json
import socket
from typing import Iterable, List

from network_leak_auditor import __version__
from network_leak_auditor.matching import DomainMatcher, RuleList
from network_leak_auditor.models import ConnectionRecord, isoformat_utc, utc_now

FINDING_FIELDS = [
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
]


def build_report(records: Iterable[ConnectionRecord], matcher: DomainMatcher, rule_lists: Iterable[RuleList]) -> dict:
    materialized_records = list(records)
    findings_by_key = {}

    for record in materialized_records:
        match = matcher.match(record.domain)
        if not match:
            continue
        key = (
            record.process_name,
            record.pid,
            record.protocol,
            record.remote_ip,
            record.remote_port,
            record.domain,
            match.matched_domain,
            match.list_name,
        )
        finding = findings_by_key.get(key)
        if finding is None:
            findings_by_key[key] = {
                "process_name": record.process_name,
                "pid": record.pid,
                "protocol": record.protocol,
                "remote_ip": record.remote_ip,
                "remote_port": record.remote_port,
                "domain": record.domain,
                "matched_domain": match.matched_domain,
                "list_name": match.list_name,
                "first_seen": record.observed_at,
                "last_seen": record.observed_at,
                "count": 1,
            }
            continue

        finding["first_seen"] = min(finding["first_seen"], record.observed_at)
        finding["last_seen"] = max(finding["last_seen"], record.observed_at)
        finding["count"] += 1

    findings: List[dict] = []
    for finding in findings_by_key.values():
        findings.append(
            {
                **finding,
                "first_seen": isoformat_utc(finding["first_seen"]),
                "last_seen": isoformat_utc(finding["last_seen"]),
            }
        )

    findings.sort(key=lambda item: (-item["count"], item["process_name"], item["remote_ip"], item["remote_port"]))

    unique_destinations = {
        (record.protocol, record.remote_ip, record.remote_port)
        for record in materialized_records
    }

    return {
        "tool": "network-leak-auditor",
        "version": __version__,
        "generated_at": isoformat_utc(utc_now()),
        "host": socket.gethostname(),
        "summary": {
            "connections_seen": len(materialized_records),
            "unique_destinations": len(unique_destinations),
            "flagged": len(findings),
            "lists_used": [rule_list.name for rule_list in rule_lists],
        },
        "findings": findings,
    }


def render_report(report: dict, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report, indent=2)
    if output_format == "csv":
        return _render_csv(report["findings"])
    return _render_text(report)


def write_report_output(rendered_report: str, output_path: str | None) -> None:
    if output_path:
        with open(output_path, "w", encoding="utf-8", newline="") as handle:
            handle.write(rendered_report)
            if not rendered_report.endswith("\n"):
                handle.write("\n")
        return
    print(rendered_report)


def _render_csv(findings: Iterable[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=FINDING_FIELDS)
    writer.writeheader()
    for finding in findings:
        writer.writerow({field: finding.get(field) for field in FINDING_FIELDS})
    return buffer.getvalue().rstrip("\n")


def _render_text(report: dict) -> str:
    summary = report["summary"]
    lines = [
        f"{report['tool']} {report['version']}",
        f"Generated at: {report['generated_at']}",
        f"Host: {report['host']}",
        (
            "Summary: "
            f"{summary['connections_seen']} connections seen, "
            f"{summary['unique_destinations']} unique destinations, "
            f"{summary['flagged']} flagged"
        ),
        f"Lists used: {', '.join(summary['lists_used'])}",
    ]

    findings = report["findings"]
    if not findings:
        lines.append("")
        lines.append("No flagged destinations found.")
        return "\n".join(lines)

    rows = [
        [
            str(finding["process_name"]),
            str(finding["pid"]),
            str(finding["protocol"]),
            str(finding["remote_ip"]),
            str(finding["remote_port"]),
            str(finding["domain"] or ""),
            str(finding["matched_domain"]),
            str(finding["list_name"]),
            str(finding["count"]),
        ]
        for finding in findings
    ]
    headers = ["process", "pid", "proto", "ip", "port", "domain", "matched", "list", "count"]
    widths = [max(len(header), *(len(row[index]) for row in rows)) for index, header in enumerate(headers)]
    lines.append("")
    lines.append(" | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    lines.append("-+-".join("-" * width for width in widths))
    for row in rows:
        lines.append(" | ".join(cell.ljust(widths[index]) for index, cell in enumerate(row)))
    return "\n".join(lines)
