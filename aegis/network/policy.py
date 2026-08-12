from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Protocol, Sequence
from urllib.parse import urlsplit, urlunsplit


class UrlPolicyError(RuntimeError):
    """Raised when an outbound URL fails a server-owned network policy."""


class Resolver(Protocol):
    def resolve(self, hostname: str) -> Sequence[str]: ...


def _canonical_hostname(hostname: str) -> str:
    canonical = hostname.rstrip(".").casefold()
    if not canonical or not canonical.isascii():
        raise UrlPolicyError("outbound hostname rejected")
    return canonical


@dataclass(frozen=True)
class ValidatedTarget:
    normalized_url: str
    hostname: str
    connect_ip: str


@dataclass(frozen=True)
class UrlSecurityPolicy:
    """Server-owned URL policy enforced before every synthetic connection.

    Hostnames are exact-match allowlisted, HTTPS is mandatory, credentials and
    non-default ports are forbidden, and every resolved address must be globally
    routable. Redirect targets must be passed through this policy again.
    """

    allowed_hosts: frozenset[str]
    max_redirects: int = 3
    max_response_bytes: int = 64 * 1024
    max_url_length: int = 2048

    def __post_init__(self) -> None:
        if self.max_redirects < 0:
            raise ValueError("max_redirects must be non-negative")
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if self.max_url_length <= 0:
            raise ValueError("max_url_length must be positive")
        canonical = frozenset(_canonical_hostname(host) for host in self.allowed_hosts)
        if not canonical:
            raise ValueError("at least one allowed host is required")
        object.__setattr__(self, "allowed_hosts", canonical)

    def validate(self, url: str, *, resolver: Resolver) -> ValidatedTarget:
        if not url or len(url) > self.max_url_length:
            raise UrlPolicyError("outbound URL rejected")
        if any(ord(character) < 0x20 for character in url):
            raise UrlPolicyError("outbound URL rejected")

        try:
            parsed = urlsplit(url)
            hostname_raw = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise UrlPolicyError("outbound URL rejected") from exc

        if parsed.scheme.casefold() != "https":
            raise UrlPolicyError("outbound scheme rejected")
        if parsed.username is not None or parsed.password is not None:
            raise UrlPolicyError("userinfo in outbound URL is forbidden")
        if "\\" in parsed.netloc:
            raise UrlPolicyError("ambiguous outbound authority rejected")
        if hostname_raw is None:
            raise UrlPolicyError("outbound hostname rejected")

        hostname = _canonical_hostname(hostname_raw)
        if hostname not in self.allowed_hosts:
            raise UrlPolicyError("outbound host is not allowlisted")
        if port not in {None, 443}:
            raise UrlPolicyError("non-default outbound port rejected")

        try:
            resolved = tuple(str(item) for item in resolver.resolve(hostname))
        except (LookupError, ValueError) as exc:
            raise UrlPolicyError("outbound hostname resolution failed") from exc
        if not resolved:
            raise UrlPolicyError("outbound hostname resolution failed")

        parsed_addresses = []
        for value in resolved:
            try:
                address = ip_address(value)
            except ValueError as exc:
                raise UrlPolicyError("outbound resolved address rejected") from exc
            if not address.is_global:
                raise UrlPolicyError("outbound resolved address is not globally routable")
            parsed_addresses.append(address)

        connect_ip = str(parsed_addresses[0])
        netloc = hostname
        path = parsed.path or "/"
        normalized_url = urlunsplit(("https", netloc, path, parsed.query, ""))
        return ValidatedTarget(
            normalized_url=normalized_url,
            hostname=hostname,
            connect_ip=connect_ip,
        )
