from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin

from aegis.network.policy import UrlPolicyError, UrlSecurityPolicy
from aegis.network.synthetic_http import (
    SyntheticHttpTransport,
    SyntheticResolver,
    SyntheticTransportError,
)


_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True)
class FetchResult:
    final_url: str
    status_code: int
    body: bytes
    visited_urls: tuple[str, ...]
    connected_ips: tuple[str, ...]


class SafeUrlFetcher:
    """Validate URL, DNS result, and every redirect hop before synthetic I/O."""

    def __init__(
        self,
        *,
        policy: UrlSecurityPolicy,
        resolver: SyntheticResolver,
        transport: SyntheticHttpTransport,
    ) -> None:
        self._policy = policy
        self._resolver = resolver
        self._transport = transport

    def fetch(self, url: str) -> FetchResult:
        current = url
        visited_urls: list[str] = []
        connected_ips: list[str] = []

        for redirect_count in range(self._policy.max_redirects + 1):
            target = self._policy.validate(current, resolver=self._resolver)
            response = self._transport.request(
                url=target.normalized_url,
                connect_ip=target.connect_ip,
            )
            visited_urls.append(target.normalized_url)
            connected_ips.append(target.connect_ip)

            if len(response.body) > self._policy.max_response_bytes:
                raise UrlPolicyError("outbound response exceeds configured byte budget")

            if response.status_code in _REDIRECT_STATUSES:
                if response.location is None:
                    raise UrlPolicyError("redirect response is missing a location")
                if redirect_count >= self._policy.max_redirects:
                    raise UrlPolicyError("outbound redirect budget exhausted")
                current = urljoin(target.normalized_url, response.location)
                continue

            return FetchResult(
                final_url=target.normalized_url,
                status_code=response.status_code,
                body=response.body,
                visited_urls=tuple(visited_urls),
                connected_ips=tuple(connected_ips),
            )

        raise SyntheticTransportError("unreachable redirect state")
