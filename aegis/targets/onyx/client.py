from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from aegis.targets.onyx.config import OnyxTargetConfig
from aegis.targets.onyx.safety import (
    Resolver,
    TargetValidation,
    validate_authorized_target,
    validate_target_location,
)


class OnyxTransport(Protocol):
    """Transport boundary; concrete Onyx endpoint bindings are added only after source inspection."""

    def probe_lab_marker(self, *, base_url: str, timeout_seconds: float) -> str: ...

    def request_json(
        self,
        *,
        base_url: str,
        method: str,
        path: str,
        headers: Mapping[str, str],
        payload: Mapping[str, Any] | None,
        timeout_seconds: float,
    ) -> Mapping[str, Any]: ...


class TargetBlockedError(RuntimeError):
    def __init__(self, validation: TargetValidation) -> None:
        super().__init__(validation.reason)
        self.validation = validation


@dataclass
class AuthorizedOnyxClient:
    """Client wrapper that cannot dispatch until the authorized-local target gate passes."""

    config: OnyxTargetConfig
    transport: OnyxTransport
    resolver: Resolver
    target_validation: TargetValidation

    @classmethod
    def connect(
        cls,
        *,
        config: OnyxTargetConfig,
        transport: OnyxTransport,
        resolver: Resolver,
    ) -> AuthorizedOnyxClient:
        location = validate_target_location(config, resolver=resolver)
        if not location.verified:
            raise TargetBlockedError(location)

        observed_marker = transport.probe_lab_marker(
            base_url=config.base_url,
            timeout_seconds=config.timeout_seconds,
        )
        validation = validate_authorized_target(
            config,
            observed_lab_marker=observed_marker,
            resolver=resolver,
        )
        if not validation.verified:
            raise TargetBlockedError(validation)
        return cls(
            config=config,
            transport=transport,
            resolver=resolver,
            target_validation=validation,
        )

    def request_json(
        self,
        *,
        method: str,
        path: str,
        headers: Mapping[str, str] | None = None,
        payload: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        current = validate_target_location(self.config, resolver=self.resolver)
        if not current.verified:
            raise TargetBlockedError(current)
        if current.resolved_addresses != self.target_validation.resolved_addresses:
            raise TargetBlockedError(
                TargetValidation(
                    status=current.status.BLOCKED,
                    reason="target resolution changed after authorization",
                    hostname=current.hostname,
                    resolved_addresses=current.resolved_addresses,
                )
            )
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("path must be an absolute application path")
        return self.transport.request_json(
            base_url=self.config.base_url,
            method=method.upper(),
            path=path,
            headers={} if headers is None else headers,
            payload=payload,
            timeout_seconds=self.config.timeout_seconds,
        )
