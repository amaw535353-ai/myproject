from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from threading import Lock
from types import MappingProxyType
from typing import Mapping, Sequence


class SyntheticTransportError(RuntimeError):
    """Raised when a deterministic synthetic network fixture has no matching route."""


@dataclass(frozen=True)
class SyntheticHttpResponse:
    status_code: int
    body: bytes = b""
    location: str | None = None


@dataclass(frozen=True)
class SyntheticTransportEvent:
    url: str
    connect_ip: str
    target_class: str


class SyntheticResolver:
    """Deterministic resolver. It never performs operating-system or network DNS."""

    def __init__(self, records: Mapping[str, Sequence[str]]) -> None:
        normalized = {
            hostname.rstrip(".").casefold(): tuple(addresses)
            for hostname, addresses in records.items()
        }
        self._records = MappingProxyType(normalized)

    def resolve(self, hostname: str) -> tuple[str, ...]:
        canonical = hostname.rstrip(".").casefold()
        try:
            return (str(ip_address(canonical)),)
        except ValueError:
            pass
        addresses = self._records.get(canonical)
        if addresses is None:
            raise LookupError("synthetic DNS record not found")
        return addresses


class SyntheticHttpTransport:
    """In-memory HTTP transport used to prove SSRF invariants without sockets."""

    def __init__(self, routes: Mapping[str, SyntheticHttpResponse]) -> None:
        self._routes = MappingProxyType(dict(routes))
        self._events: list[SyntheticTransportEvent] = []
        self._lock = Lock()

    def request(self, *, url: str, connect_ip: str) -> SyntheticHttpResponse:
        try:
            address = ip_address(connect_ip)
        except ValueError as exc:
            raise SyntheticTransportError("invalid synthetic connection address") from exc

        event = SyntheticTransportEvent(
            url=url,
            connect_ip=str(address),
            target_class="public" if address.is_global else "forbidden",
        )
        with self._lock:
            self._events.append(event)

        response = self._routes.get(url)
        if response is None:
            raise SyntheticTransportError("synthetic route not found")
        return response

    def events(self) -> tuple[SyntheticTransportEvent, ...]:
        with self._lock:
            return tuple(self._events)
