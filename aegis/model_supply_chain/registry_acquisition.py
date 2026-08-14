from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping, Protocol

from .package_provenance import (
    ModelPackageManifest,
    ModelPackageRejected,
    ModelPackageRequest,
    RestrictedModelPackageLoader,
    SignedModelArtifact,
    VerifiedModelPackage,
    canonical_package_manifest_bytes,
)
from .provenance import canonical_manifest_bytes


P5C_REGISTRY_POLICY_VERSION = "immutable-model-registry-acquisition-v1"
P5C_RELEASE_SCHEMA_VERSION = "aegis-model-registry-release-v1"
P5C_ACQUISITION_MODE = "digest-pinned-release-handoff-v1"


class RegistryAcquisitionRejectReason(StrEnum):
    PIN_INVALID = "pin_invalid"
    REGISTRY_UNTRUSTED = "registry_untrusted"
    CHANNEL_UNPINNED = "channel_unpinned"
    TAG_DRIFT = "tag_drift"
    SOURCE_UNTRUSTED = "source_untrusted"
    REDIRECT_UNTRUSTED = "redirect_untrusted"
    RELEASE_NOT_FOUND = "release_not_found"
    RELEASE_IDENTITY_MISMATCH = "release_identity_mismatch"
    RELEASE_DIGEST_MISMATCH = "release_digest_mismatch"
    CACHE_DIGEST_MISMATCH = "cache_digest_mismatch"
    PACKAGE_INVALID = "package_invalid"


class RegistryAcquisitionRejected(ValueError):
    def __init__(
        self,
        reason: RegistryAcquisitionRejectReason,
        message: str,
        *,
        nested_reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.nested_reason = nested_reason


@dataclass(frozen=True)
class RegistryReleasePin:
    registry_id: str
    channel: str
    tag: str
    release_digest: str
    package_id: str
    model_id: str
    revision: str


@dataclass(frozen=True)
class RegistryReleasePointer:
    registry_id: str
    channel: str
    tag: str
    release_digest: str
    source: str


@dataclass(frozen=True)
class RegistryReleaseEnvelope:
    registry_id: str
    channel: str
    tag: str
    package_manifest: ModelPackageManifest
    package_signature: bytes
    artifacts: Mapping[str, SignedModelArtifact]
    schema_version: str = P5C_RELEASE_SCHEMA_VERSION


@dataclass(frozen=True)
class RegistryFetchResult:
    envelope: RegistryReleaseEnvelope
    final_source: str
    redirects: tuple[str, ...] = ()


@dataclass(frozen=True)
class RegistryAcquisitionPolicy:
    trusted_registry_sources: Mapping[str, tuple[str, ...]]
    channel_pins: Mapping[tuple[str, str, str], str]
    allow_redirects: bool = False
    trusted_redirect_sources: Mapping[str, tuple[str, ...]] | None = None


@dataclass(frozen=True)
class VerifiedRegistryRelease:
    registry_id: str
    channel: str
    tag: str
    release_digest: str
    source: str
    redirect_count: int
    package: VerifiedModelPackage
    policy_version: str = P5C_REGISTRY_POLICY_VERSION
    acquisition_mode: str = P5C_ACQUISITION_MODE
    digest_addressed: bool = True
    mutable_tag_pin_verified: bool = True
    cache_verified: bool = True
    network_operations: int = 0
    code_execution_capable: bool = False


class ModelRegistryTransport(Protocol):
    def resolve(self, *, registry_id: str, channel: str, tag: str) -> RegistryReleasePointer:
        ...

    def fetch_by_digest(
        self,
        *,
        registry_id: str,
        source: str,
        release_digest: str,
    ) -> RegistryFetchResult:
        ...


class RegistryReleaseCache:
    """Small verified cache keyed by immutable release digest.

    Cache reads are always re-hashed before use, so a same-key substituted envelope fails closed.
    """

    def __init__(self) -> None:
        self._entries: dict[str, RegistryReleaseEnvelope] = {}

    def put(self, release_digest: str, envelope: RegistryReleaseEnvelope) -> None:
        self._entries[release_digest.casefold()] = envelope

    def get(self, release_digest: str) -> RegistryReleaseEnvelope | None:
        return self._entries.get(release_digest.casefold())


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_registry_release_bytes(envelope: RegistryReleaseEnvelope) -> bytes:
    artifacts = []
    for artifact_id, bundle in sorted(envelope.artifacts.items()):
        artifacts.append(
            {
                "artifact_id": artifact_id,
                "manifest_sha256": sha256_hex(canonical_manifest_bytes(bundle.manifest)),
                "signature_sha256": sha256_hex(bundle.signature),
                "payload_sha256": sha256_hex(bundle.payload),
                "payload_size": len(bundle.payload),
            }
        )
    document = {
        "artifacts": artifacts,
        "channel": envelope.channel,
        "package_manifest_sha256": sha256_hex(
            canonical_package_manifest_bytes(envelope.package_manifest)
        ),
        "package_signature_sha256": sha256_hex(envelope.package_signature),
        "registry_id": envelope.registry_id,
        "schema_version": envelope.schema_version,
        "tag": envelope.tag,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def registry_release_digest(envelope: RegistryReleaseEnvelope) -> str:
    return sha256_hex(canonical_registry_release_bytes(envelope))


def _reject(
    reason: RegistryAcquisitionRejectReason,
    message: str,
    *,
    nested_reason: str | None = None,
) -> None:
    raise RegistryAcquisitionRejected(reason, message, nested_reason=nested_reason)


def _valid_digest(value: str) -> bool:
    digest = value.casefold()
    return len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)


def _source_allowed(source: str, prefixes: tuple[str, ...]) -> bool:
    return bool(prefixes) and any(source.startswith(prefix) for prefix in prefixes)


class ImmutableModelRegistryAcquirer:
    """Acquire only a policy-pinned immutable release and verify its full package closure."""

    def __init__(
        self,
        *,
        policy: RegistryAcquisitionPolicy,
        package_loader: RestrictedModelPackageLoader,
        cache: RegistryReleaseCache | None = None,
    ) -> None:
        self._policy = policy
        self._package_loader = package_loader
        self._cache = cache

    def acquire(
        self,
        *,
        pin: RegistryReleasePin,
        transport: ModelRegistryTransport,
    ) -> VerifiedRegistryRelease:
        if (
            not pin.registry_id
            or not pin.channel
            or not pin.tag
            or not pin.package_id
            or not pin.model_id
            or not pin.revision
            or not _valid_digest(pin.release_digest)
        ):
            _reject(RegistryAcquisitionRejectReason.PIN_INVALID, "release pin is incomplete or malformed")

        source_prefixes = self._policy.trusted_registry_sources.get(pin.registry_id)
        if not source_prefixes:
            _reject(RegistryAcquisitionRejectReason.REGISTRY_UNTRUSTED, "registry is not trusted by policy")

        configured_digest = self._policy.channel_pins.get((pin.registry_id, pin.channel, pin.tag))
        if configured_digest is None:
            _reject(RegistryAcquisitionRejectReason.CHANNEL_UNPINNED, "release channel and tag are not pinned")
        if not hmac.compare_digest(configured_digest.casefold(), pin.release_digest.casefold()):
            _reject(RegistryAcquisitionRejectReason.CHANNEL_UNPINNED, "caller pin does not match deployment channel pin")

        pointer = transport.resolve(
            registry_id=pin.registry_id,
            channel=pin.channel,
            tag=pin.tag,
        )
        if (
            pointer.registry_id != pin.registry_id
            or pointer.channel != pin.channel
            or pointer.tag != pin.tag
        ):
            _reject(RegistryAcquisitionRejectReason.RELEASE_IDENTITY_MISMATCH, "registry pointer identity mismatch")
        if not hmac.compare_digest(pointer.release_digest.casefold(), pin.release_digest.casefold()):
            _reject(RegistryAcquisitionRejectReason.TAG_DRIFT, "mutable tag no longer resolves to the pinned release")
        if not _source_allowed(pointer.source, source_prefixes):
            _reject(RegistryAcquisitionRejectReason.SOURCE_UNTRUSTED, "resolved registry source is outside trusted prefixes")

        cached = self._cache.get(pin.release_digest) if self._cache is not None else None
        if cached is not None:
            actual = registry_release_digest(cached)
            if not hmac.compare_digest(actual, pin.release_digest.casefold()):
                _reject(RegistryAcquisitionRejectReason.CACHE_DIGEST_MISMATCH, "cached release does not match immutable key")
            envelope = cached
            final_source = pointer.source
            redirects: tuple[str, ...] = ()
        else:
            try:
                fetched = transport.fetch_by_digest(
                    registry_id=pin.registry_id,
                    source=pointer.source,
                    release_digest=pin.release_digest,
                )
            except KeyError:
                _reject(RegistryAcquisitionRejectReason.RELEASE_NOT_FOUND, "pinned immutable release was not found")

            if fetched.redirects and not self._policy.allow_redirects:
                _reject(RegistryAcquisitionRejectReason.REDIRECT_UNTRUSTED, "registry redirects are disabled")
            redirect_prefixes = (
                self._policy.trusted_redirect_sources.get(pin.registry_id, ())
                if self._policy.trusted_redirect_sources is not None
                else source_prefixes
            )
            for source in (*fetched.redirects, fetched.final_source):
                if not _source_allowed(source, redirect_prefixes):
                    _reject(RegistryAcquisitionRejectReason.REDIRECT_UNTRUSTED, "redirect or final source is untrusted")

            envelope = fetched.envelope
            final_source = fetched.final_source
            redirects = fetched.redirects
            actual = registry_release_digest(envelope)
            if not hmac.compare_digest(actual, pin.release_digest.casefold()):
                _reject(RegistryAcquisitionRejectReason.RELEASE_DIGEST_MISMATCH, "fetched release bytes do not match immutable digest")
            if self._cache is not None:
                self._cache.put(pin.release_digest, envelope)

        if (
            envelope.schema_version != P5C_RELEASE_SCHEMA_VERSION
            or envelope.registry_id != pin.registry_id
            or envelope.channel != pin.channel
            or envelope.tag != pin.tag
        ):
            _reject(RegistryAcquisitionRejectReason.RELEASE_IDENTITY_MISMATCH, "release envelope identity mismatch")
        manifest = envelope.package_manifest
        if (
            manifest.package_id != pin.package_id
            or manifest.model_id != pin.model_id
            or manifest.revision != pin.revision
        ):
            _reject(RegistryAcquisitionRejectReason.RELEASE_IDENTITY_MISMATCH, "release package identity does not match pin")

        try:
            package = self._package_loader.load(
                request=ModelPackageRequest(
                    package_id=pin.package_id,
                    model_id=pin.model_id,
                    revision=pin.revision,
                ),
                manifest=manifest,
                package_signature=envelope.package_signature,
                artifacts=envelope.artifacts,
            )
        except ModelPackageRejected as exc:
            _reject(
                RegistryAcquisitionRejectReason.PACKAGE_INVALID,
                "acquired release failed model-package provenance verification",
                nested_reason=exc.reason.value,
            )

        return VerifiedRegistryRelease(
            registry_id=pin.registry_id,
            channel=pin.channel,
            tag=pin.tag,
            release_digest=pin.release_digest.casefold(),
            source=final_source,
            redirect_count=len(redirects),
            package=package,
        )
