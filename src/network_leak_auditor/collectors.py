import json
import socket
import sys
from typing import Iterable, List, Optional

import psutil

from network_leak_auditor.models import ConnectionRecord, parse_timestamp, utc_now
from network_leak_auditor.net import is_filtered_remote


def _extract_remote_endpoint(raddr: object) -> tuple[Optional[str], Optional[int]]:
    if not raddr:
        return None, None
    if hasattr(raddr, "ip") and hasattr(raddr, "port"):
        return getattr(raddr, "ip"), getattr(raddr, "port")
    if isinstance(raddr, tuple) and len(raddr) >= 2:
        return raddr[0], raddr[1]
    return None, None


def _protocol_for_connection(connection: object) -> Optional[str]:
    if connection.type == socket.SOCK_STREAM:
        return "tcp"
    if connection.type == socket.SOCK_DGRAM:
        return "udp"
    return None


def _process_name_for_pid(pid: Optional[int], cache: dict[Optional[int], str]) -> str:
    if pid in cache:
        return cache[pid]
    if pid is None:
        cache[pid] = "unknown"
        return cache[pid]
    try:
        cache[pid] = psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        cache[pid] = "unknown"
    return cache[pid]


def collect_psutil_snapshot(include_private: bool = False) -> List[ConnectionRecord]:
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.Error, OSError):
        return []

    observed_at = utc_now()
    process_names: dict[Optional[int], str] = {}
    records: List[ConnectionRecord] = []

    for connection in connections:
        protocol = _protocol_for_connection(connection)
        if not protocol:
            continue
        if protocol == "tcp" and connection.status != psutil.CONN_ESTABLISHED:
            continue

        remote_ip, remote_port = _extract_remote_endpoint(connection.raddr)
        if not remote_ip or not remote_port:
            continue
        if not include_private and is_filtered_remote(remote_ip):
            continue

        records.append(
            ConnectionRecord(
                process_name=_process_name_for_pid(connection.pid, process_names),
                pid=connection.pid,
                protocol=protocol,
                remote_ip=remote_ip,
                remote_port=int(remote_port),
                observed_at=observed_at,
            )
        )

    return records


def _record_from_json_line(raw_record: dict, include_private: bool = False) -> Optional[ConnectionRecord]:
    remote_ip = str(raw_record["remote_ip"])
    if not include_private and is_filtered_remote(remote_ip):
        return None

    domain = raw_record.get("domain")
    normalized_domain = str(domain).strip().lower() if domain else None
    return ConnectionRecord(
        process_name=str(raw_record.get("process_name") or "unknown"),
        pid=raw_record.get("pid"),
        protocol=str(raw_record["protocol"]).lower(),
        remote_ip=remote_ip,
        remote_port=int(raw_record["remote_port"]),
        observed_at=parse_timestamp(raw_record.get("observed_at")),
        domain=normalized_domain,
    )


def parse_connection_input(path: str, include_private: bool = False) -> List[ConnectionRecord]:
    handle = sys.stdin if path == "-" else open(path, "r", encoding="utf-8")
    try:
        return list(_iter_connection_input(handle, include_private=include_private))
    finally:
        if handle is not sys.stdin:
            handle.close()


def _iter_connection_input(lines: Iterable[str], include_private: bool = False) -> Iterable[ConnectionRecord]:
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            raw_record = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on line {line_number}") from exc
        record = _record_from_json_line(raw_record, include_private=include_private)
        if record is not None:
            yield record
