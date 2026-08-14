from __future__ import annotations

from dataclasses import dataclass

from aegis.model_supply_chain.registry_acquisition import (
    ModelRegistryTransport,
    RegistryReleaseCache,
    RegistryReleasePin,
)


@dataclass(frozen=True)
class VulnerableRegistryRelease:
    registry_id: str
    channel: str
    tag: str
    declared_release_digest: str
    package_id: str
    model_id: str
    revision: str
    provenance_verified: bool = False
    digest_addressed: bool = False
    channel_pin_verified: bool = False
    cache_verified: bool = False
    code_executed: bool = False


class VulnerableMutableRegistryAcquirer:
    """Intentionally trusts mutable registry resolution, cache keys, and release declarations."""

    def __init__(self, cache: RegistryReleaseCache | None = None) -> None:
        self._cache = cache

    def acquire(
        self,
        *,
        pin: RegistryReleasePin,
        transport: ModelRegistryTransport,
    ) -> VulnerableRegistryRelease:
        pointer = transport.resolve(
            registry_id=pin.registry_id,
            channel=pin.channel,
            tag=pin.tag,
        )
        cached = self._cache.get(pointer.release_digest) if self._cache is not None else None
        if cached is not None:
            envelope = cached
        else:
            fetched = transport.fetch_by_digest(
                registry_id=pointer.registry_id,
                source=pointer.source,
                release_digest=pointer.release_digest,
            )
            envelope = fetched.envelope
        manifest = envelope.package_manifest
        return VulnerableRegistryRelease(
            registry_id=pointer.registry_id,
            channel=pointer.channel,
            tag=pointer.tag,
            declared_release_digest=pointer.release_digest,
            package_id=manifest.package_id,
            model_id=manifest.model_id,
            revision=manifest.revision,
        )
