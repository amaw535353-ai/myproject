from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

LAB_ACK_ENV = "AEGIS_ONYX_LAB_ACK"
LAB_ACK_VALUE = "YES"


@dataclass(frozen=True)
class OnyxTargetConfig:
    """Security-sensitive configuration for an authorized local Onyx target."""

    base_url: str
    expected_lab_marker: str
    lab_ack: str
    allow_private_network_targets: bool = False
    approved_lab_hosts: tuple[str, ...] = ()
    timeout_seconds: float = 5.0

    def __post_init__(self) -> None:
        if not self.base_url.strip():
            raise ValueError("base_url must be non-empty")
        if not self.expected_lab_marker:
            raise ValueError("expected_lab_marker must be non-empty")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        normalized_hosts = tuple(sorted({host.casefold().strip() for host in self.approved_lab_hosts}))
        if any(not host for host in normalized_hosts):
            raise ValueError("approved_lab_hosts cannot contain empty values")
        object.__setattr__(self, "approved_lab_hosts", normalized_hosts)

    @classmethod
    def from_environment(
        cls,
        *,
        base_url: str,
        expected_lab_marker: str,
        allow_private_network_targets: bool = False,
        approved_lab_hosts: tuple[str, ...] = (),
        timeout_seconds: float = 5.0,
        environ: Mapping[str, str] | None = None,
    ) -> OnyxTargetConfig:
        env = os.environ if environ is None else environ
        return cls(
            base_url=base_url,
            expected_lab_marker=expected_lab_marker,
            lab_ack=env.get(LAB_ACK_ENV, ""),
            allow_private_network_targets=allow_private_network_targets,
            approved_lab_hosts=approved_lab_hosts,
            timeout_seconds=timeout_seconds,
        )
