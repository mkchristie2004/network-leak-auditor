from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Optional


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_utc(value: datetime) -> str:
    normalized = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return normalized.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: Optional[str]) -> datetime:
    if not value:
        return utc_now()
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class ConnectionRecord:
    process_name: str
    pid: Optional[int]
    protocol: str
    remote_ip: str
    remote_port: int
    observed_at: datetime
    domain: Optional[str] = None

    def with_domain(self, domain: Optional[str]) -> "ConnectionRecord":
        return replace(self, domain=domain)
