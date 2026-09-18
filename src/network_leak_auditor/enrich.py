import socket
import threading
from queue import Queue
from typing import Iterable, List, Optional

from network_leak_auditor.models import ConnectionRecord


class ReverseDNSResolver:
    def __init__(self, enabled: bool = True, timeout: float = 0.2):
        self.enabled = enabled
        self.timeout = timeout
        self._cache: dict[str, Optional[str]] = {}

    def resolve(self, remote_ip: str) -> Optional[str]:
        if not self.enabled:
            return None
        if remote_ip in self._cache:
            return self._cache[remote_ip]

        result_queue: Queue[Optional[str]] = Queue(maxsize=1)

        def lookup() -> None:
            try:
                name = socket.gethostbyaddr(remote_ip)[0].rstrip(".").lower()
            except (socket.herror, socket.gaierror, OSError):
                name = None
            result_queue.put(name)

        thread = threading.Thread(target=lookup, daemon=True)
        thread.start()
        thread.join(self.timeout)
        name = result_queue.get_nowait() if not thread.is_alive() else None

        self._cache[remote_ip] = name
        return name


def enrich_records(
    records: Iterable[ConnectionRecord], resolver: ReverseDNSResolver
) -> List[ConnectionRecord]:
    enriched: List[ConnectionRecord] = []
    for record in records:
        domain = record.domain or resolver.resolve(record.remote_ip)
        enriched.append(record.with_domain(domain))
    return enriched
