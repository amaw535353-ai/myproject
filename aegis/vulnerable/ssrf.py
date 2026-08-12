from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from aegis.network.fetcher import FetchResult
from aegis.network.synthetic_http import SyntheticHttpTransport, SyntheticResolver


_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class VulnerableUrlFetcher:
    """INTENTIONALLY VULNERABLE local P2-E fetcher.

    It checks only the initial HTTPS hostname against an allowlist. It does not
    validate resolved IP addresses and it follows redirects without reapplying the
    hostname policy. No real network I/O is used by this class in the lab.
    """

    def __init__(
        self,
        *,
        allowed_hosts: frozenset[str],
        resolver: SyntheticResolver,
        transport: SyntheticHttpTransport,
        max_redirects: int = 3,
        max_response_bytes: int = 64 * 1024,
    ) -> None:
        self._allowed_hosts = frozenset(host.rstrip(".").casefold() for host in allowed_hosts)
        self._resolver = resolver
        self._transport = transport
        self._max_redirects = max_redirects
        self._max_response_bytes = max_response_bytes

    def _resolve_without_address_policy(self, url: str) -> tuple[str, str]:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        if hostname is None:
            raise RuntimeError("synthetic vulnerable fetch rejected malformed URL")
        addresses = self._resolver.resolve(hostname)
        if not addresses:
            raise RuntimeError("synthetic vulnerable DNS resolution failed")
        return url, str(addresses[0])

    def fetch(self, url: str) -> FetchResult:
        initial = urlsplit(url)
        initial_host = initial.hostname.rstrip(".").casefold() if initial.hostname else ""
        if initial.scheme.casefold() != "https" or initial_host not in self._allowed_hosts:
            raise RuntimeError("synthetic vulnerable initial URL rejected")

        current = url
        visited_urls: list[str] = []
        connected_ips: list[str] = []

        for redirect_count in range(self._max_redirects + 1):
            request_url, connect_ip = self._resolve_without_address_policy(current)
            response = self._transport.request(url=request_url, connect_ip=connect_ip)
            visited_urls.append(request_url)
            connected_ips.append(connect_ip)

            if len(response.body) > self._max_response_bytes:
                raise RuntimeError("synthetic vulnerable response byte budget exhausted")

            if response.status_code in _REDIRECT_STATUSES:
                if response.location is None or redirect_count >= self._max_redirects:
                    raise RuntimeError("synthetic vulnerable redirect failed")
                # VULNERABILITY: the redirect target is never passed through the
                # original allowlist or a resolved-IP safety check.
                current = urljoin(request_url, response.location)
                continue

            return FetchResult(
                final_url=request_url,
                status_code=response.status_code,
                body=response.body,
                visited_urls=tuple(visited_urls),
                connected_ips=tuple(connected_ips),
            )

        raise RuntimeError("unreachable synthetic redirect state")
