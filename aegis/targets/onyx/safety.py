from __future__ import annotations

import hmac
import ipaddress
import socket
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from aegis.targets.onyx.config import LAB_ACK_VALUE, OnyxTargetConfig

Resolver = Callable[..., Sequence[tuple[object, object, object, object, tuple[object, ...]]]]

_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
_IPV6_ULA = ipaddress.ip_network("fc00::/7")


class TargetGateStatus(StrEnum):
    VERIFIED = "VERIFIED"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class TargetValidation:
    status: TargetGateStatus
    reason: str
    hostname: str | None = None
    resolved_addresses: tuple[str, ...] = ()

    @property
    def verified(self) -> bool:
        return self.status is TargetGateStatus.VERIFIED


def _blocked(reason: str, *, hostname: str | None = None) -> TargetValidation:
    return TargetValidation(status=TargetGateStatus.BLOCKED, reason=reason, hostname=hostname)


def _is_loopback(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address.is_loopback


def _is_private_lab_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if _is_loopback(address):
        return True
    if isinstance(address, ipaddress.IPv4Address):
        return any(address in network for network in _RFC1918)
    return address in _IPV6_ULA


def _literal_address(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def _resolved_addresses(
    hostname: str,
    port: int,
    resolver: Resolver,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    try:
        answers = resolver(hostname, port, type=socket.SOCK_STREAM)
    except OSError:
        return ()
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for answer in answers:
        sockaddr = answer[4]
        if not sockaddr:
            continue
        raw_address = str(sockaddr[0])
        try:
            addresses.add(ipaddress.ip_address(raw_address))
        except ValueError:
            return ()
    return tuple(sorted(addresses, key=str))


def validate_target_location(
    config: OnyxTargetConfig,
    *,
    resolver: Resolver = socket.getaddrinfo,
) -> TargetValidation:
    """Validate destination identity before any application-level attack request is sent."""

    if config.lab_ack != LAB_ACK_VALUE:
        return _blocked("explicit authorized-lab acknowledgement is missing")

    parsed = urlsplit(config.base_url)
    if parsed.scheme not in {"http", "https"}:
        return _blocked("target scheme must be http or https")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return _blocked("target URL must not contain credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        return _blocked("target base URL must not contain an application path")
    if parsed.hostname is None:
        return _blocked("target URL must contain a hostname")

    hostname = parsed.hostname.casefold()
    literal = _literal_address(hostname)
    if literal is not None and _is_loopback(literal):
        return TargetValidation(
            status=TargetGateStatus.VERIFIED,
            reason="loopback target location verified",
            hostname=hostname,
            resolved_addresses=(str(literal),),
        )
    if hostname == "localhost":
        return TargetValidation(
            status=TargetGateStatus.VERIFIED,
            reason="localhost target location verified",
            hostname=hostname,
            resolved_addresses=("loopback",),
        )

    if not config.allow_private_network_targets:
        return _blocked("non-loopback targets are disabled by default", hostname=hostname)
    if hostname not in config.approved_lab_hosts:
        return _blocked("target hostname is not in the explicit private-lab allowlist", hostname=hostname)

    if literal is not None:
        addresses = (literal,)
    else:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = _resolved_addresses(hostname, port, resolver)
    if not addresses:
        return _blocked("target hostname could not be resolved safely", hostname=hostname)
    if not all(_is_private_lab_address(address) for address in addresses):
        return _blocked("target resolves outside approved private/loopback ranges", hostname=hostname)

    return TargetValidation(
        status=TargetGateStatus.VERIFIED,
        reason="explicit private-lab target location verified",
        hostname=hostname,
        resolved_addresses=tuple(str(address) for address in addresses),
    )


def validate_authorized_target(
    config: OnyxTargetConfig,
    *,
    observed_lab_marker: str,
    resolver: Resolver = socket.getaddrinfo,
) -> TargetValidation:
    location = validate_target_location(config, resolver=resolver)
    if not location.verified:
        return location
    if not observed_lab_marker:
        return _blocked("target lab marker is missing", hostname=location.hostname)
    if not hmac.compare_digest(observed_lab_marker, config.expected_lab_marker):
        return _blocked("target lab marker does not match", hostname=location.hostname)
    return TargetValidation(
        status=TargetGateStatus.VERIFIED,
        reason="authorized local Onyx lab target verified",
        hostname=location.hostname,
        resolved_addresses=location.resolved_addresses,
    )
