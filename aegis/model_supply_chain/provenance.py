from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


P5A_MODEL_ARTIFACT_POLICY_VERSION = "model-artifact-provenance-safe-loading-v1"
P5A_MANIFEST_SCHEMA_VERSION = "aegis-model-artifact-manifest-v1"
P5A_SAFE_LOADER_MODE = "verified-opaque-handoff-v1"


class ModelArtifactRejectReason(StrEnum):
    MANIFEST_INVALID = "manifest_invalid"
    IDENTITY_MISMATCH = "identity_mismatch"
    PUBLISHER_UNTRUSTED = "publisher_untrusted"
    SOURCE_UNTRUSTED = "source_untrusted"
    FORMAT_UNSAFE = "format_unsafe"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    SIZE_MISMATCH = "size_mismatch"
    DIGEST_MISMATCH = "digest_mismatch"
    SIGNATURE_INVALID = "signature_invalid"


class ModelArtifactRejected(ValueError):
    def __init__(self, reason: ModelArtifactRejectReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class ModelArtifactRequest:
    artifact_id: str
    model_id: str
    revision: str


@dataclass(frozen=True)
class ModelArtifactManifest:
    artifact_id: str
    model_id: str
    revision: str
    publisher_id: str
    source: str
    artifact_format: str
    sha256: str
    size_bytes: int
    schema_version: str = P5A_MANIFEST_SCHEMA_VERSION


@dataclass(frozen=True)
class ModelArtifactTrustPolicy:
    trusted_publishers: Mapping[str, bytes]
    trusted_source_prefixes: Mapping[str, tuple[str, ...]]
    allowed_formats: frozenset[str] = frozenset({"safetensors", "onnx"})
    max_artifact_bytes: int = 1_073_741_824


@dataclass(frozen=True)
class VerifiedModelArtifact:
    artifact_id: str
    model_id: str
    revision: str
    publisher_id: str
    source: str
    artifact_format: str
    sha256: str
    size_bytes: int
    policy_version: str = P5A_MODEL_ARTIFACT_POLICY_VERSION
    loader_mode: str = P5A_SAFE_LOADER_MODE
    deserialized: bool = False
    code_execution_capable: bool = False
    network_operations: int = 0


def canonical_manifest_bytes(manifest: ModelArtifactManifest) -> bytes:
    return json.dumps(
        {
            "artifact_format": manifest.artifact_format,
            "artifact_id": manifest.artifact_id,
            "model_id": manifest.model_id,
            "publisher_id": manifest.publisher_id,
            "revision": manifest.revision,
            "schema_version": manifest.schema_version,
            "sha256": manifest.sha256,
            "size_bytes": manifest.size_bytes,
            "source": manifest.source,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _reject(reason: ModelArtifactRejectReason, message: str) -> None:
    raise ModelArtifactRejected(reason, message)


def _validate_manifest_shape(manifest: ModelArtifactManifest) -> None:
    if manifest.schema_version != P5A_MANIFEST_SCHEMA_VERSION:
        _reject(ModelArtifactRejectReason.MANIFEST_INVALID, "unsupported model artifact manifest schema")
    if not manifest.artifact_id or not manifest.model_id or not manifest.revision:
        _reject(ModelArtifactRejectReason.MANIFEST_INVALID, "artifact identity fields must be non-empty")
    if not manifest.publisher_id or not manifest.source or not manifest.artifact_format:
        _reject(ModelArtifactRejectReason.MANIFEST_INVALID, "publisher source and format must be non-empty")
    if manifest.size_bytes < 0:
        _reject(ModelArtifactRejectReason.MANIFEST_INVALID, "artifact size must be non-negative")
    digest = manifest.sha256.casefold()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        _reject(ModelArtifactRejectReason.MANIFEST_INVALID, "artifact digest must be lowercase-compatible SHA-256 hex")


class RestrictedModelArtifactLoader:
    """Verify provenance and policy before producing a non-deserialized artifact handle.

    P5-A intentionally does not parse model formats. The returned handle proves that the
    caller-requested identity, signed manifest, source policy, digest, size, and format
    allowlist were checked before any later model-runtime integration receives the artifact.
    """

    def __init__(self, policy: ModelArtifactTrustPolicy) -> None:
        self._policy = policy

    def load(
        self,
        *,
        request: ModelArtifactRequest,
        manifest: ModelArtifactManifest,
        signature: bytes,
        payload: bytes,
    ) -> VerifiedModelArtifact:
        _validate_manifest_shape(manifest)

        if (
            request.artifact_id != manifest.artifact_id
            or request.model_id != manifest.model_id
            or request.revision != manifest.revision
        ):
            _reject(
                ModelArtifactRejectReason.IDENTITY_MISMATCH,
                "signed artifact identity does not match the caller request",
            )

        public_key_bytes = self._policy.trusted_publishers.get(manifest.publisher_id)
        if public_key_bytes is None:
            _reject(ModelArtifactRejectReason.PUBLISHER_UNTRUSTED, "publisher is not trusted by policy")

        allowed_prefixes = self._policy.trusted_source_prefixes.get(manifest.publisher_id, ())
        if not allowed_prefixes or not any(manifest.source.startswith(prefix) for prefix in allowed_prefixes):
            _reject(ModelArtifactRejectReason.SOURCE_UNTRUSTED, "artifact source is not trusted for publisher")

        artifact_format = manifest.artifact_format.casefold()
        if artifact_format not in self._policy.allowed_formats:
            _reject(ModelArtifactRejectReason.FORMAT_UNSAFE, "artifact format is not in the data-only allowlist")

        if len(payload) > self._policy.max_artifact_bytes:
            _reject(ModelArtifactRejectReason.PAYLOAD_TOO_LARGE, "artifact exceeds configured byte budget")
        if len(payload) != manifest.size_bytes:
            _reject(ModelArtifactRejectReason.SIZE_MISMATCH, "artifact size does not match signed manifest")

        actual_digest = sha256_hex(payload)
        if not hmac.compare_digest(actual_digest, manifest.sha256.casefold()):
            _reject(ModelArtifactRejectReason.DIGEST_MISMATCH, "artifact payload digest does not match manifest")

        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature, canonical_manifest_bytes(manifest))
        except (ValueError, InvalidSignature):
            _reject(ModelArtifactRejectReason.SIGNATURE_INVALID, "artifact manifest signature verification failed")

        return VerifiedModelArtifact(
            artifact_id=manifest.artifact_id,
            model_id=manifest.model_id,
            revision=manifest.revision,
            publisher_id=manifest.publisher_id,
            source=manifest.source,
            artifact_format=artifact_format,
            sha256=actual_digest,
            size_bytes=len(payload),
        )
