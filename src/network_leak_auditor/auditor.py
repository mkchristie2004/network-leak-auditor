from __future__ import annotations

import csv
import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import resources
from io import StringIO
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import psutil

from . import __version__

TOOL_NAME = "network-leak-auditor"
DEFAULT_TIMEOUT = 0.5
VISIBILITY_WARNING_MESSAGE = (
    "Some connections or process names may be hidden: the OS restricts cross-process visibility "
    "without elevated privileges. Results may be incomplete."
)


@dataclass(frozen=True)
class ConnectionRecord:
    process_name: str
    pid: Optional[int]
    protocol: str
    remote_ip: str
    remote_port: int


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(timestamp: datetime) -> str:
    return timestamp.replace(microsecond=0).isoformat()


def normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


class ReverseDNSResolver:
    def __init__(self, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.timeout = timeout
        self.cache: Dict[str, Optional[str]] = {}
        self._executor = ThreadPoolExecutor(max_workers=4)

    def lookup(self, ip_address: str) -> Optional[str]:
        if ip_address in self.cache:
            return self.cache[ip_address]

        future = self._executor.submit(socket.gethostbyaddr, ip_address)
        try:
            hostname = future.result(timeout=self.timeout)[0]
            domain = normalize_domain(hostname)
        except TimeoutError:
            future.cancel()
            domain = None
        except (OSError, socket.herror, socket.gaierror):
            domain = None
        self.cache[ip_address] = domain
        return domain

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


def is_public_destination(remote_ip: str, include_private: bool) -> bool:
    try:
        address = ipaddress.ip_address(remote_ip)
    except ValueError:
        return False

    if include_private:
        return True

    excluded = (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_private
    )
    return not excluded


def collect_connections(
    include_private: bool = False,
    net_connections: Callable[..., Iterable[object]] = psutil.net_connections,
    process_lookup: Callable[[Optional[int]], str] | None = None,
) -> Tuple[List[ConnectionRecord], bool]:
    visibility_restricted = False

    findings: List[ConnectionRecord] = []
    try:
        connections = net_connections(kind="inet")
    except psutil.AccessDenied:
        return findings, True

    for connection in connections:
        protocol = classify_protocol(connection)
        if protocol is None:
            continue

        remote = getattr(connection, "raddr", None)
        if not remote:
            continue

        remote_ip = getattr(remote, "ip", None) or remote[0]
        remote_port = getattr(remote, "port", None) or remote[1]
        if not is_public_destination(remote_ip, include_private=include_private):
            continue

        pid = getattr(connection, "pid", None)
        if process_lookup is None:
            process_name, process_access_denied = resolve_process_name_with_reason(pid)
            visibility_restricted = visibility_restricted or process_access_denied
        else:
            process_name = process_lookup(pid)
        findings.append(
            ConnectionRecord(
                process_name=process_name,
                pid=pid,
                protocol=protocol,
                remote_ip=remote_ip,
                remote_port=remote_port,
            )
        )
    return findings, visibility_restricted


def classify_protocol(connection: object) -> Optional[str]:
    connection_type = getattr(connection, "type", None)
    status = getattr(connection, "status", "")

    if connection_type == socket.SOCK_STREAM:
        return "tcp" if status == psutil.CONN_ESTABLISHED else None
    if connection_type == socket.SOCK_DGRAM:
        return "udp"
    return None


def resolve_process_name(pid: Optional[int]) -> str:
    return resolve_process_name_with_reason(pid)[0]


def resolve_process_name_with_reason(pid: Optional[int]) -> Tuple[str, bool]:
    if pid is None:
        return "unknown", False
    try:
        return psutil.Process(pid).name(), False
    except psutil.AccessDenied:
        return "unknown", True
    except (psutil.Error, OSError):
        return "unknown", False


def parse_domain_list(path: Path) -> set[str]:
    domains: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        domains.add(normalize_domain(line))
    return domains


def parse_mapping_file(path: Path) -> Dict[str, str]:
    mappings: Dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        domain, separator, values = line.partition("=")
        if not separator:
            continue
        normalized_domain = normalize_domain(domain)
        for ip_address in values.split(","):
            ip_address = ip_address.strip()
            if ip_address:
                mappings[ip_address] = normalized_domain
    return mappings


def default_tracker_list_path() -> Path:
    return Path(resources.files("network_leak_auditor").joinpath("data/trackers.txt"))


def load_lists(list_file: Optional[str], extra_lists: Optional[Sequence[str]]) -> List[Tuple[str, set[str]]]:
    loaded: List[Tuple[str, set[str]]] = []
    paths: List[Path] = []

    if list_file:
        paths.append(Path(list_file))
    else:
        paths.append(default_tracker_list_path())

    for extra in extra_lists or []:
        paths.append(Path(extra))

    for path in paths:
        loaded.append((path.name, parse_domain_list(path)))
    return loaded


def match_domain(domain: Optional[str], loaded_lists: Sequence[Tuple[str, set[str]]]) -> Tuple[Optional[str], Optional[str]]:
    if not domain:
        return None, None

    normalized = normalize_domain(domain)
    parts = normalized.split(".")
    for index in range(len(parts)):
        candidate = ".".join(parts[index:])
        for list_name, domains in loaded_lists:
            if candidate in domains:
                return candidate, list_name
    return None, None


def update_aggregate(
    aggregate: Dict[Tuple[str, Optional[int], str, str, int], dict],
    records: Iterable[ConnectionRecord],
    timestamp: datetime,
    resolver: Optional[ReverseDNSResolver],
    mappings: Dict[str, str],
    loaded_lists: Sequence[Tuple[str, set[str]]],
    resolve_rdns: bool = True,
) -> None:
    stamp = isoformat(timestamp)
    for record in records:
        key = (
            record.process_name,
            record.pid,
            record.protocol,
            record.remote_ip,
            record.remote_port,
        )
        item = aggregate.get(key)
        if item is None:
            domain = mappings.get(record.remote_ip)
            if domain is None and resolve_rdns and resolver is not None:
                domain = resolver.lookup(record.remote_ip)
            matched_domain, list_name = match_domain(domain, loaded_lists)
            aggregate[key] = {
                "process_name": record.process_name,
                "pid": record.pid,
                "protocol": record.protocol,
                "remote_ip": record.remote_ip,
                "remote_port": record.remote_port,
                "domain": domain,
                "matched_domain": matched_domain,
                "list_name": list_name,
                "first_seen": stamp,
                "last_seen": stamp,
                "count": 1,
            }
            continue

        item["last_seen"] = stamp
        item["count"] += 1


def build_report(
    findings: Sequence[dict],
    lists_used: Sequence[str],
    generated_at: datetime,
    visibility_warning: Optional[str] = None,
) -> dict:
    return {
        "tool": TOOL_NAME,
        "version": __version__,
        "generated_at": isoformat(generated_at),
        "host": socket.gethostname(),
        "visibility_warning": visibility_warning,
        "summary": {
            "connections_seen": sum(item["count"] for item in findings),
            "unique_destinations": len(
                {(item["protocol"], item["remote_ip"], item["remote_port"]) for item in findings}
            ),
            "flagged": sum(1 for item in findings if item["matched_domain"]),
            "unclassified": sum(1 for item in findings if item["matched_domain"] is None),
            "lists_used": list(lists_used),
        },
        "findings": list(findings),
    }


def render_report(report: dict, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(report, indent=2) + "\n"
    if output_format == "csv":
        return render_csv(report)
    return render_text(report)


def render_csv(report: dict) -> str:
    buffer = StringIO()
    fieldnames = [
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
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for finding in report["findings"]:
        writer.writerow({name: finding.get(name) for name in fieldnames})
    return buffer.getvalue()


def render_text(report: dict) -> str:
    summary = report["summary"]
    lines = [
        f"Tool: {report['tool']} {report['version']}",
        f"Generated at: {report['generated_at']}",
        f"Host: {report['host']}",
        (
            "Summary: "
            f"connections_seen={summary['connections_seen']} "
            f"unique_destinations={summary['unique_destinations']} "
            f"flagged={summary['flagged']} "
            f"unclassified={summary['unclassified']} "
            f"lists_used={','.join(summary['lists_used'])}"
        ),
        (
            "Unclassified: "
            f"{summary['unclassified']} destination(s) did not match any list "
            "(possibly CDN-fronted or unlisted)."
        ),
    ]
    if report.get("visibility_warning"):
        lines.append(f"WARNING: {report['visibility_warning']}")
    lines.append("")

    if not report["findings"]:
        lines.append("No connections observed.")
        return "\n".join(lines) + "\n"

    headers = ["PROCESS", "PID", "PROTO", "REMOTE", "DOMAIN", "MATCH", "LIST", "COUNT"]
    rows = []
    for finding in report["findings"]:
        rows.append(
            [
                str(finding["process_name"]),
                "" if finding["pid"] is None else str(finding["pid"]),
                finding["protocol"],
                f"{finding['remote_ip']}:{finding['remote_port']}",
                finding["domain"] or "",
                finding["matched_domain"] or "",
                finding["list_name"] or "",
                str(finding["count"]),
            ]
        )

    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))

    lines.append("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    lines.append("  ".join("-" * width for width in widths))
    for row in rows:
        lines.append("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))
    return "\n".join(lines) + "\n"


def write_output(content: str, output_path: Optional[str]) -> None:
    if output_path:
        with Path(output_path).open("w", encoding="utf-8") as handle:
            handle.write(content)
    else:
        print(content, end="")


def sleep_until_next(interval: float, started: float, duration: Optional[float]) -> bool:
    if duration is None:
        time.sleep(interval)
        return True

    elapsed = time.monotonic() - started
    remaining = duration - elapsed
    if remaining <= 0:
        return False

    time.sleep(min(interval, remaining))
    return True
