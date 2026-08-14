from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .package_provenance import (
    ModelPackageComponentRole,
    ModelPackageManifest,
    ModelPackageRejected,
    ModelPackageRequest,
    ModelPackageTrustPolicy,
    RestrictedModelPackageLoader,
    SignedModelArtifact,
    VerifiedModelPackage,
    canonical_package_manifest_bytes,
)
from .provenance import (
    ModelArtifactManifest,
    ModelArtifactTrustPolicy,
    canonical_manifest_bytes,
)


P5D_KEY_LIFECYCLE_POLICY_VERSION = "provenance-signing-key-lifecycle-v1"
P5D_SIGNATURE_ENVELOPE_SCHEMA_VERSION = "aegis-provenance-signature-envelope-v1"
P5D_LOADER_MODE = "lifecycle-gated-transitive-opaque-handoff-v1"


class SigningKeyUsage(StrEnum):
    MODEL_ARTIFACT = "model_artifact"
    MODEL_PACKAGE = "model_package"


class SigningKeyState(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class KeyLifecycleRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    SIGNATURE_ENVELOPE_INVALID = "signature_envelope_invalid"
    KEY_UNKNOWN = "key_unknown"
    ISSUER_UNTRUSTED = "issuer_untrusted"
    ISSUER_MISMATCH = "issuer_mismatch"
    PUBLISHER_MISMATCH = "publisher_mismatch"
    USAGE_MISMATCH = "usage_mismatch"
    KEY_NOT_YET_VALID = "key_not_yet_valid"
    KEY_EXPIRED = "key_expired"
    KEY_RETIRED = "key_retired"
    KEY_REVOKED = "key_revoked"
    SIGNED_AT_INVALID = "signed_at_invalid"
    SUBJECT_MISMATCH = "subject_mismatch"
    SIGNATURE_INVALID = "signature_invalid"
    KEY_CONFLICT = "key_conflict"
    PACKAGE_INVALID = "package_invalid"


class KeyLifecycleRejected(ValueError):
    def __init__(
        self,
        reason: KeyLifecycleRejectReason,
        message: str,
        *,
        key_id: str | None = None,
        component_id: str | None = None,
        nested_reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.key_id = key_id
        self.component_id = component_id
        self.nested_reason = nested_reason


@dataclass(frozen=True)
class SigningKeyRecord:
    key_id: str
    issuer_id: str
    publisher_id: str
    public_key: bytes
    usages: frozenset[SigningKeyUsage]
    valid_from: int
    valid_until: int
    state: SigningKeyState = SigningKeyState.ACTIVE
    retired_at: int | None = None
    revoked_at: int | None = None
    successor_key_id: str | None = None


@dataclass(frozen=True)
class BoundProvenanceSignature:
    key_id: str
    issuer_id: str
    publisher_id: str
    usage: SigningKeyUsage
    signed_at: int
    subject_sha256: str
    signature: bytes
    legacy_signature: bytes
    schema_version: str = P5D_SIGNATURE_ENVELOPE_SCHEMA_VERSION


@dataclass(frozen=True)
class KeyLifecyclePolicy:
    keys: Mapping[str, SigningKeyRecord]
    trusted_issuers: frozenset[str]
    evaluation_time: int
    max_future_skew_seconds: int = 0
    accept_retired_signatures: bool = False


@dataclass(frozen=True)
class LifecycleSignedModelArtifact:
    manifest: ModelArtifactManifest
    signature: BoundProvenanceSignature
    payload: bytes


@dataclass(frozen=True)
class LifecycleModelPackageTrustPolicy:
    key_lifecycle: KeyLifecyclePolicy
    trusted_source_prefixes: Mapping[str, tuple[str, ...]]
    role_publishers: Mapping[ModelPackageComponentRole, frozenset[str]]
    allowed_formats: frozenset[str] = frozenset({"safetensors", "onnx", "json"})
    max_artifact_bytes: int = 1_073_741_824
    allowed_roles: frozenset[ModelPackageComponentRole] = frozenset(ModelPackageComponentRole)
    allow_remote_code: bool = False


@dataclass(frozen=True)
class VerifiedLifecycleModelPackage:
    package: VerifiedModelPackage
    package_key_id: str
    component_key_ids: tuple[tuple[str, str], ...]
    key_lifecycle_verified: bool = True
    current_key_policy_verified: bool = True
    revocation_checked: bool = True
    policy_version: str = P5D_KEY_LIFECYCLE_POLICY_VERSION
    loader_mode: str = P5D_LOADER_MODE
    deserialized: bool = False
    code_execution_capable: bool = False
    network_operations: int = 0


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical_bound_signature_bytes(signature: BoundProvenanceSignature) -> bytes:
    return json.dumps(
        {
            "issuer_id": signature.issuer_id,
            "key_id": signature.key_id,
            "publisher_id": signature.publisher_id,
            "schema_version": signature.schema_version,
            "signed_at": signature.signed_at,
            "subject_sha256": signature.subject_sha256,
            "usage": signature.usage.value,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _reject(
    reason: KeyLifecycleRejectReason,
    message: str,
    *,
    key_id: str | None = None,
    component_id: str | None = None,
    nested_reason: str | None = None,
) -> None:
    raise KeyLifecycleRejected(
        reason,
        message,
        key_id=key_id,
        component_id=component_id,
        nested_reason=nested_reason,
    )


def _validate_record(record: SigningKeyRecord) -> None:
    if not record.key_id or not record.issuer_id or not record.publisher_id:
        _reject(KeyLifecycleRejectReason.POLICY_INVALID, "key identity fields must be non-empty", key_id=record.key_id or None)
    if len(record.public_key) != 32:
        _reject(KeyLifecycleRejectReason.POLICY_INVALID, "Ed25519 public key must be 32 bytes", key_id=record.key_id)
    if not record.usages:
        _reject(KeyLifecycleRejectReason.POLICY_INVALID, "key must authorize at least one provenance usage", key_id=record.key_id)
    if record.valid_from < 0 or record.valid_until <= record.valid_from:
        _reject(KeyLifecycleRejectReason.POLICY_INVALID, "key validity window is invalid", key_id=record.key_id)
    if record.state is SigningKeyState.RETIRED and record.retired_at is None:
        _reject(KeyLifecycleRejectReason.POLICY_INVALID, "retired key must declare retired_at", key_id=record.key_id)
    if record.state is SigningKeyState.REVOKED and record.revoked_at is None:
        _reject(KeyLifecycleRejectReason.POLICY_INVALID, "revoked key must declare revoked_at", key_id=record.key_id)
    if record.retired_at is not None and record.retired_at < record.valid_from:
        _reject(KeyLifecycleRejectReason.POLICY_INVALID, "retirement precedes key validity", key_id=record.key_id)
    if record.revoked_at is not None and record.revoked_at < record.valid_from:
        _reject(KeyLifecycleRejectReason.POLICY_INVALID, "revocation precedes key validity", key_id=record.key_id)


def _validate_policy(policy: KeyLifecyclePolicy) -> None:
    if policy.evaluation_time < 0 or policy.max_future_skew_seconds < 0:
        _reject(KeyLifecycleRejectReason.POLICY_INVALID, "evaluation time and future skew must be non-negative")
    if not policy.trusted_issuers:
        _reject(KeyLifecycleRejectReason.POLICY_INVALID, "at least one provenance issuer must be trusted")
    seen: set[str] = set()
    for mapping_key, record in policy.keys.items():
        _validate_record(record)
        if mapping_key != record.key_id:
            _reject(KeyLifecycleRejectReason.POLICY_INVALID, "keyring mapping key must equal record key_id", key_id=record.key_id)
        if record.key_id in seen:
            _reject(KeyLifecycleRejectReason.POLICY_INVALID, "duplicate key ID", key_id=record.key_id)
        seen.add(record.key_id)
        if record.successor_key_id is not None and record.successor_key_id == record.key_id:
            _reject(KeyLifecycleRejectReason.POLICY_INVALID, "key may not supersede itself", key_id=record.key_id)


class KeyLifecycleVerifier:
    """Verify signer identity, lifecycle state, time policy, and a bound provenance signature."""

    def __init__(self, policy: KeyLifecyclePolicy) -> None:
        _validate_policy(policy)
        self._policy = policy

    def verify(
        self,
        *,
        subject: bytes,
        expected_publisher_id: str,
        expected_usage: SigningKeyUsage,
        signature: BoundProvenanceSignature,
    ) -> SigningKeyRecord:
        if signature.schema_version != P5D_SIGNATURE_ENVELOPE_SCHEMA_VERSION:
            _reject(KeyLifecycleRejectReason.SIGNATURE_ENVELOPE_INVALID, "unsupported provenance signature envelope schema", key_id=signature.key_id)
        if not signature.key_id or not signature.issuer_id or not signature.publisher_id:
            _reject(KeyLifecycleRejectReason.SIGNATURE_ENVELOPE_INVALID, "signature envelope identity fields must be non-empty", key_id=signature.key_id or None)
        digest = signature.subject_sha256.casefold()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            _reject(KeyLifecycleRejectReason.SIGNATURE_ENVELOPE_INVALID, "signature envelope subject digest must be SHA-256 hex", key_id=signature.key_id)

        record = self._policy.keys.get(signature.key_id)
        if record is None:
            _reject(KeyLifecycleRejectReason.KEY_UNKNOWN, "signature references an unknown key ID", key_id=signature.key_id)
        if record.issuer_id not in self._policy.trusted_issuers:
            _reject(KeyLifecycleRejectReason.ISSUER_UNTRUSTED, "key issuer is not trusted by deployment policy", key_id=record.key_id)
        if signature.issuer_id != record.issuer_id:
            _reject(KeyLifecycleRejectReason.ISSUER_MISMATCH, "signature issuer does not match key record", key_id=record.key_id)
        if signature.publisher_id != expected_publisher_id or record.publisher_id != expected_publisher_id:
            _reject(KeyLifecycleRejectReason.PUBLISHER_MISMATCH, "signing key is not bound to the expected publisher", key_id=record.key_id)
        if signature.usage is not expected_usage or expected_usage not in record.usages:
            _reject(KeyLifecycleRejectReason.USAGE_MISMATCH, "signing key is not authorized for this provenance usage", key_id=record.key_id)

        actual_subject_digest = _sha256_hex(subject)
        if not hmac.compare_digest(actual_subject_digest, digest):
            _reject(KeyLifecycleRejectReason.SUBJECT_MISMATCH, "bound signature does not match the provenance subject", key_id=record.key_id)

        if signature.signed_at > self._policy.evaluation_time + self._policy.max_future_skew_seconds:
            _reject(KeyLifecycleRejectReason.SIGNED_AT_INVALID, "signature timestamp is in the future beyond policy skew", key_id=record.key_id)
        if signature.signed_at < record.valid_from:
            _reject(KeyLifecycleRejectReason.KEY_NOT_YET_VALID, "signature predates signer key validity", key_id=record.key_id)
        if signature.signed_at > record.valid_until:
            _reject(KeyLifecycleRejectReason.KEY_EXPIRED, "signature was created after signer key expiry", key_id=record.key_id)

        # Deployment trust is intentionally current-state strict: a currently expired key is
        # not sufficient merely because an old signature was once valid.
        if self._policy.evaluation_time < record.valid_from:
            _reject(KeyLifecycleRejectReason.KEY_NOT_YET_VALID, "signer key is not yet valid at policy evaluation time", key_id=record.key_id)
        if self._policy.evaluation_time > record.valid_until:
            _reject(KeyLifecycleRejectReason.KEY_EXPIRED, "signer key is expired at policy evaluation time", key_id=record.key_id)

        if record.state is SigningKeyState.REVOKED or (
            record.revoked_at is not None and self._policy.evaluation_time >= record.revoked_at
        ):
            _reject(KeyLifecycleRejectReason.KEY_REVOKED, "signer key is revoked by current deployment policy", key_id=record.key_id)
        if record.state is SigningKeyState.RETIRED:
            if not self._policy.accept_retired_signatures:
                _reject(KeyLifecycleRejectReason.KEY_RETIRED, "signer key was retired during controlled rotation", key_id=record.key_id)
            assert record.retired_at is not None
            if signature.signed_at >= record.retired_at:
                _reject(KeyLifecycleRejectReason.KEY_RETIRED, "retired signer key was used at or after retirement", key_id=record.key_id)

        try:
            Ed25519PublicKey.from_public_bytes(record.public_key).verify(
                signature.signature,
                canonical_bound_signature_bytes(signature),
            )
        except (ValueError, InvalidSignature):
            _reject(KeyLifecycleRejectReason.SIGNATURE_INVALID, "provenance lifecycle signature verification failed", key_id=record.key_id)
        return record


class LifecycleRestrictedModelPackageLoader:
    """Gate P5-B package verification on current provenance signing-key lifecycle state."""

    def __init__(self, policy: LifecycleModelPackageTrustPolicy) -> None:
        self._policy = policy
        self._verifier = KeyLifecycleVerifier(policy.key_lifecycle)

    def load(
        self,
        *,
        request: ModelPackageRequest,
        manifest: ModelPackageManifest,
        package_signature: BoundProvenanceSignature,
        artifacts: Mapping[str, LifecycleSignedModelArtifact],
    ) -> VerifiedLifecycleModelPackage:
        package_record = self._verifier.verify(
            subject=canonical_package_manifest_bytes(manifest),
            expected_publisher_id=manifest.publisher_id,
            expected_usage=SigningKeyUsage.MODEL_PACKAGE,
            signature=package_signature,
        )

        artifact_records: dict[str, SigningKeyRecord] = {}
        artifact_key_ids: list[tuple[str, str]] = []
        legacy_artifacts: dict[str, SignedModelArtifact] = {}
        for artifact_id, bundle in sorted(artifacts.items()):
            record = self._verifier.verify(
                subject=canonical_manifest_bytes(bundle.manifest),
                expected_publisher_id=bundle.manifest.publisher_id,
                expected_usage=SigningKeyUsage.MODEL_ARTIFACT,
                signature=bundle.signature,
            )
            prior = artifact_records.get(record.publisher_id)
            if prior is not None and prior.key_id != record.key_id:
                _reject(
                    KeyLifecycleRejectReason.KEY_CONFLICT,
                    "one package closure uses multiple active signer keys for the same publisher",
                    key_id=record.key_id,
                    component_id=artifact_id,
                )
            artifact_records[record.publisher_id] = record
            artifact_key_ids.append((artifact_id, record.key_id))
            legacy_artifacts[artifact_id] = SignedModelArtifact(
                manifest=bundle.manifest,
                signature=bundle.signature.legacy_signature,
                payload=bundle.payload,
            )

        nested_policy = ModelPackageTrustPolicy(
            package_publishers={manifest.publisher_id: package_record.public_key},
            artifact_policy=ModelArtifactTrustPolicy(
                trusted_publishers={publisher_id: record.public_key for publisher_id, record in artifact_records.items()},
                trusted_source_prefixes=self._policy.trusted_source_prefixes,
                allowed_formats=self._policy.allowed_formats,
                max_artifact_bytes=self._policy.max_artifact_bytes,
            ),
            role_publishers=self._policy.role_publishers,
            allowed_roles=self._policy.allowed_roles,
            allow_remote_code=self._policy.allow_remote_code,
        )
        try:
            package = RestrictedModelPackageLoader(nested_policy).load(
                request=request,
                manifest=manifest,
                package_signature=package_signature.legacy_signature,
                artifacts=legacy_artifacts,
            )
        except ModelPackageRejected as exc:
            _reject(
                KeyLifecycleRejectReason.PACKAGE_INVALID,
                "package failed nested P5-B provenance validation after key lifecycle checks",
                nested_reason=exc.reason.value,
                component_id=exc.component_id,
            )

        return VerifiedLifecycleModelPackage(
            package=package,
            package_key_id=package_record.key_id,
            component_key_ids=tuple(artifact_key_ids),
        )
