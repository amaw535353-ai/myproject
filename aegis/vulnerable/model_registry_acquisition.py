from __future__ import annotations

from dataclasses import dataclass

from aegis.model_supply_chain.registry_acquisition import (
    ModelRegistryTransport,
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
    """Intentionally trusts mutable registry resolution and returned release declarations."""

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
        fetched = transport.fetch_by_digest(
            registry_id=pointer.registry_id,
            source=pointer.source,
            release_digest=pointer.release_digest,
        )
        manifest = fetched.envelope.package_manifest
        return VulnerableRegistryRelease(
            registry_id=pointer.registry_id,
            channel=pointer.channel,
            tag=pointer.tag,
            declared_release_digest=pointer.release_digest,
            package_id=manifest.package_id,
            model_id=manifest.model_id,
            revision=manifest.revision,
        )
