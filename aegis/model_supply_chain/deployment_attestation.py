from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .model_scanning import VerifiedModelScan
from .privacy_controls import (
    P5G_PRIVACY_POLICY_VERSION,
    PrivacyControlPolicy,
)
from .registry_acquisition import VerifiedRegistryRelease
from .runtime_isolation import VerifiedRuntimePlan


P5H_DEPLOYMENT_ATTESTATION_POLICY_VERSION = "deployment-provenance-attestation-v1"
P5H_ATTESTATION_SCHEMA_VERSION = "aegis-deployment-attestation-v1"
P5H_ATTESTATION_MODE = "deterministic-synthetic-deployment-attestation-v1"


class DeploymentAttestationRejectReason(StrEnum):
    RELEASE_UNVERIFIED = "release_unverified"
    RUNTIME_UNVERIFIED = "runtime_unverified"
    SCAN_UNVERIFIED = "scan_unverified"
    IDENTITY_MISMATCH = "identity_mismatch"
    POLICY_BINDING_MISMATCH = "policy_binding_mismatch"
    ENVIRONMENT_UNTRUSTED = "environment_untrusted"
    MEASUREMENT_MISMATCH = "measurement_mismatch"
    CAPABILITY_MISMATCH = "capability_mismatch"
    ATTESTOR_UNTRUSTED = "attestor_untrusted"
    ATTESTATION_INVALID = "attestation_invalid"
    ATTESTATION_STALE = "attestation_stale"
    NONCE_MISMATCH = "nonce_mismatch"
    SIGNATURE_INVALID = "signature_invalid"


class DeploymentAttestationRejected(ValueError):
    def __init__(
        self,
        reason: DeploymentAttestationRejectReason,
        message: str,
    ) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class DeploymentAttestationRequest:
    deployment_id: str
    package_id: str
    model_id: str
    revision: str
    runtime_id: str
    registry_id: str
    channel: str
    tag: str
    release_digest: str
    scan_evidence_sha256: str
    privacy_policy_sha256: str
    environment_id: str
    nonce: str
    evaluated_at_epoch: int


@dataclass(frozen=True)
class DeploymentEnvironmentEvidence:
    environment_id: str
    orchestrator: str
    image_digest: str
    runtime_measurement: str
    sandbox_backend: str
    network_mode: str = "isolated"
    filesystem_mode: str = "read_only"
    secrets_mode: str = "brokered"
    debug_enabled: bool = False
    privileged: bool = False
    host_pid_namespace: bool = False
    host_network: bool = False
    writable_root_filesystem: bool = False


@dataclass(frozen=True)
class DeploymentAttestationStatement:
    deployment_id: str
    package_id: str
    model_id: str
    revision: str
    runtime_id: str
    registry_id: str
    channel: str
    tag: str
    release_digest: str
    release_policy_version: str
    release_acquisition_mode: str
    runtime_policy_version: str
    runtime_admission_mode: str
    scan_evidence_sha256: str
    scan_policy_version: str
    scan_mode: str
    privacy_policy_sha256: str
    privacy_policy_version: str
    environment: DeploymentEnvironmentEvidence
    nonce: str
    issued_at_epoch: int
    expires_at_epoch: int
    attestor_id: str
    schema_version: str = P5H_ATTESTATION_SCHEMA_VERSION


@dataclass(frozen=True)
class SignedDeploymentAttestation:
    statement: DeploymentAttestationStatement
    signature: bytes


@dataclass(frozen=True)
class DeploymentAttestationPolicy:
    expected_release_digest: str
    expected_scan_evidence_sha256: str
    expected_privacy_policy_sha256: str
    trusted_attestors: Mapping[str, bytes]
    expected_image_digests: Mapping[str, str]
    expected_runtime_measurements: Mapping[str, str]
    allowed_orchestrators: frozenset[str]
    allowed_sandbox_backends: frozenset[str]
    max_attestation_age_seconds: int = 300


@dataclass(frozen=True)
class VerifiedDeploymentAttestation:
    deployment_id: str
    package_id: str
    model_id: str
    revision: str
    runtime_id: str
    registry_id: str
    channel: str
    tag: str
    release_digest: str
    scan_evidence_sha256: str
    privacy_policy_sha256: str
    environment_id: str
    image_digest: str
    runtime_measurement: str
    sandbox_backend: str
    attestor_id: str
    nonce: str
    issued_at_epoch: int
    expires_at_epoch: int
    statement_sha256: str
    prior_release_verified: bool = True
    runtime_policy_verified: bool = True
    scan_evidence_verified: bool = True
    privacy_policy_verified: bool = True
    environment_policy_verified: bool = True
    attestor_signature_verified: bool = True
    least_privilege_environment_verified: bool = True
    hardware_backed_attestation: bool = False
    transparency_log_verified: bool = False
    real_remote_attestation: bool = False
    network_operations: int = 0
    policy_version: str = P5H_DEPLOYMENT_ATTESTATION_POLICY_VERSION
    attestation_mode: str = P5H_ATTESTATION_MODE


def _reject(reason: DeploymentAttestationRejectReason, message: str) -> None:
    raise DeploymentAttestationRejected(reason, message)


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def canonical_privacy_policy_bytes(policy: PrivacyControlPolicy) -> bytes:
    document = {
        "allowed_output_modes": sorted(policy.allowed_output_modes),
        "expected_scan_evidence_sha256": policy.expected_scan_evidence_sha256.casefold(),
        "forbidden_canary_fragments": sorted(
            fragment.casefold() for fragment in policy.forbidden_canary_fragments
        ),
        "max_confidence_decimals": policy.max_confidence_decimals,
        "max_extraction_similarity_milli": policy.max_extraction_similarity_milli,
        "max_membership_advantage_milli": policy.max_membership_advantage_milli,
        "max_memorization_overlap_ppm": policy.max_memorization_overlap_ppm,
        "max_output_tokens": policy.max_output_tokens,
        "max_queries_per_session": policy.max_queries_per_session,
        "max_repeated_fingerprint_queries": policy.max_repeated_fingerprint_queries,
        "max_top_k": policy.max_top_k,
        "policy_version": P5G_PRIVACY_POLICY_VERSION,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def privacy_policy_digest(policy: PrivacyControlPolicy) -> str:
    return hashlib.sha256(canonical_privacy_policy_bytes(policy)).hexdigest()


def canonical_deployment_attestation_bytes(
    statement: DeploymentAttestationStatement,
) -> bytes:
    document = asdict(statement)
    document["release_digest"] = statement.release_digest.casefold()
    document["scan_evidence_sha256"] = statement.scan_evidence_sha256.casefold()
    document["privacy_policy_sha256"] = statement.privacy_policy_sha256.casefold()
    document["environment"]["image_digest"] = statement.environment.image_digest.casefold()
    document["environment"]["runtime_measurement"] = (
        statement.environment.runtime_measurement.casefold()
    )
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def deployment_attestation_digest(statement: DeploymentAttestationStatement) -> str:
    return hashlib.sha256(canonical_deployment_attestation_bytes(statement)).hexdigest()


def _validate_release(release: VerifiedRegistryRelease) -> None:
    package = release.package
    if (
        not release.digest_addressed
        or not release.mutable_tag_pin_verified
        or not release.cache_verified
        or release.network_operations != 0
        or release.code_execution_capable
        or not package.package_signature_verified
        or not package.transitive_components_verified
        or not package.dependency_graph_verified
        or package.remote_code_required
        or package.deserialized
        or package.code_execution_capable
        or package.network_operations != 0
    ):
        _reject(
            DeploymentAttestationRejectReason.RELEASE_UNVERIFIED,
            "deployment attestation requires an intact P5-C immutable verified release",
        )


def _validate_runtime(
    runtime: VerifiedRuntimePlan,
    release: VerifiedRegistryRelease,
) -> None:
    if (
        not runtime.provenance_verified
        or not runtime.transitive_package_verified
        or not runtime.parser_policy_verified
        or not runtime.backend_policy_verified
        or runtime.remote_code_allowed
        or runtime.dynamic_code_allowed
        or runtime.native_extensions_allowed
        or runtime.custom_ops_allowed
        or runtime.network_access
        or runtime.subprocess_allowed
        or runtime.host_filesystem_write
        or runtime.environment_passthrough
        or runtime.host_ipc
        or runtime.ptrace_allowed
        or not runtime.sandbox_required
        or runtime.model_bytes_parsed
        or runtime.model_executed
        or runtime.network_operations != 0
    ):
        _reject(
            DeploymentAttestationRejectReason.RUNTIME_UNVERIFIED,
            "deployment attestation requires an intact P5-E verified runtime plan",
        )
    if (
        runtime.package_id,
        runtime.model_id,
        runtime.revision,
    ) != (
        release.package.package_id,
        release.package.model_id,
        release.package.revision,
    ):
        _reject(
            DeploymentAttestationRejectReason.RUNTIME_UNVERIFIED,
            "runtime plan does not bind to the verified release package",
        )


def _validate_scan(
    scan: VerifiedModelScan,
    runtime: VerifiedRuntimePlan,
) -> None:
    if (
        not scan.subject_digest_pins_verified
        or not scan.exact_component_coverage_verified
        or not scan.runtime_plan_verified
        or not scan.static_indicators_clear
        or not scan.synthetic_probe_indicators_clear
        or scan.indicator_count != 0
        or scan.raw_model_bytes_scanned
        or scan.model_executed
        or scan.network_operations != 0
    ):
        _reject(
            DeploymentAttestationRejectReason.SCAN_UNVERIFIED,
            "deployment attestation requires an intact clear P5-F verified scan",
        )
    if (
        scan.package_id,
        scan.model_id,
        scan.revision,
        scan.runtime_id,
    ) != (
        runtime.package_id,
        runtime.model_id,
        runtime.revision,
        runtime.runtime_id,
    ):
        _reject(
            DeploymentAttestationRejectReason.SCAN_UNVERIFIED,
            "scan handle does not bind to the verified runtime release identity",
        )


class DeploymentAttestationVerifier:
    """Verify deterministic deployment provenance and synthetic environment attestation.

    P5-H deliberately verifies signed deployment *evidence*. It does not perform real
    hardware-rooted remote attestation or contact a transparency service.
    """

    def __init__(self, policy: DeploymentAttestationPolicy) -> None:
        self._policy = policy

    def verify(
        self,
        *,
        request: DeploymentAttestationRequest,
        release: VerifiedRegistryRelease,
        runtime: VerifiedRuntimePlan,
        scan: VerifiedModelScan,
        privacy_policy: PrivacyControlPolicy,
        attestation: SignedDeploymentAttestation,
    ) -> VerifiedDeploymentAttestation:
        _validate_release(release)
        _validate_runtime(runtime, release)
        _validate_scan(scan, runtime)

        statement = attestation.statement
        identity = (
            request.package_id,
            request.model_id,
            request.revision,
            request.runtime_id,
        )
        prior_identity = (
            release.package.package_id,
            release.package.model_id,
            release.package.revision,
            runtime.runtime_id,
        )
        statement_identity = (
            statement.package_id,
            statement.model_id,
            statement.revision,
            statement.runtime_id,
        )
        if identity != prior_identity or identity != statement_identity:
            _reject(
                DeploymentAttestationRejectReason.IDENTITY_MISMATCH,
                "deployment identity must exactly match release, runtime, and attestation",
            )
        if (
            request.deployment_id != statement.deployment_id
            or not request.deployment_id
            or request.registry_id != release.registry_id
            or request.channel != release.channel
            or request.tag != release.tag
            or (
                statement.registry_id,
                statement.channel,
                statement.tag,
            )
            != (release.registry_id, release.channel, release.tag)
        ):
            _reject(
                DeploymentAttestationRejectReason.IDENTITY_MISMATCH,
                "deployment/registry/channel/tag identity does not match verified release",
            )

        policy_release = self._policy.expected_release_digest.casefold()
        policy_scan = self._policy.expected_scan_evidence_sha256.casefold()
        actual_privacy_digest = privacy_policy_digest(privacy_policy)
        policy_privacy = self._policy.expected_privacy_policy_sha256.casefold()
        digest_values = (
            policy_release,
            request.release_digest.casefold(),
            release.release_digest.casefold(),
            statement.release_digest.casefold(),
            policy_scan,
            request.scan_evidence_sha256.casefold(),
            scan.evidence_sha256.casefold(),
            statement.scan_evidence_sha256.casefold(),
            policy_privacy,
            request.privacy_policy_sha256.casefold(),
            actual_privacy_digest,
            statement.privacy_policy_sha256.casefold(),
        )
        if not all(_is_sha256(item) for item in digest_values):
            _reject(
                DeploymentAttestationRejectReason.ATTESTATION_INVALID,
                "deployment binding digests must be valid SHA-256 hex",
            )
        if not (
            hmac.compare_digest(policy_release, request.release_digest.casefold())
            and hmac.compare_digest(policy_release, release.release_digest.casefold())
            and hmac.compare_digest(policy_release, statement.release_digest.casefold())
            and hmac.compare_digest(policy_scan, request.scan_evidence_sha256.casefold())
            and hmac.compare_digest(policy_scan, scan.evidence_sha256.casefold())
            and hmac.compare_digest(policy_scan, statement.scan_evidence_sha256.casefold())
            and hmac.compare_digest(policy_privacy, request.privacy_policy_sha256.casefold())
            and hmac.compare_digest(policy_privacy, actual_privacy_digest)
            and hmac.compare_digest(policy_privacy, statement.privacy_policy_sha256.casefold())
            and hmac.compare_digest(
                privacy_policy.expected_scan_evidence_sha256.casefold(),
                policy_scan,
            )
        ):
            _reject(
                DeploymentAttestationRejectReason.POLICY_BINDING_MISMATCH,
                "release, scan, and privacy-policy digests must match deployment pins",
            )

        if (
            statement.schema_version != P5H_ATTESTATION_SCHEMA_VERSION
            or statement.release_policy_version != release.policy_version
            or statement.release_acquisition_mode != release.acquisition_mode
            or statement.runtime_policy_version != runtime.policy_version
            or statement.runtime_admission_mode != runtime.admission_mode
            or statement.scan_policy_version != scan.policy_version
            or statement.scan_mode != scan.scan_mode
            or statement.privacy_policy_version != P5G_PRIVACY_POLICY_VERSION
        ):
            _reject(
                DeploymentAttestationRejectReason.POLICY_BINDING_MISMATCH,
                "attestation policy/mode versions do not match the verified deployment chain",
            )

        environment = statement.environment
        if (
            request.environment_id != environment.environment_id
            or environment.environment_id not in self._policy.expected_image_digests
            or environment.environment_id not in self._policy.expected_runtime_measurements
            or environment.orchestrator not in self._policy.allowed_orchestrators
        ):
            _reject(
                DeploymentAttestationRejectReason.ENVIRONMENT_UNTRUSTED,
                "deployment environment/orchestrator is not policy-authorized",
            )

        expected_image = self._policy.expected_image_digests[environment.environment_id].casefold()
        expected_measurement = self._policy.expected_runtime_measurements[
            environment.environment_id
        ].casefold()
        if (
            not _is_sha256(expected_image)
            or not _is_sha256(expected_measurement)
            or not _is_sha256(environment.image_digest)
            or not _is_sha256(environment.runtime_measurement)
            or not hmac.compare_digest(expected_image, environment.image_digest.casefold())
            or not hmac.compare_digest(
                expected_measurement,
                environment.runtime_measurement.casefold(),
            )
        ):
            _reject(
                DeploymentAttestationRejectReason.MEASUREMENT_MISMATCH,
                "image digest and runtime measurement must match environment pins",
            )

        if (
            environment.sandbox_backend != runtime.backend
            or environment.sandbox_backend not in self._policy.allowed_sandbox_backends
            or environment.network_mode != "isolated"
            or environment.filesystem_mode != "read_only"
            or environment.secrets_mode != "brokered"
            or environment.debug_enabled
            or environment.privileged
            or environment.host_pid_namespace
            or environment.host_network
            or environment.writable_root_filesystem
        ):
            _reject(
                DeploymentAttestationRejectReason.CAPABILITY_MISMATCH,
                "attested environment violates least-privilege deployment policy",
            )

        if not request.nonce or request.nonce != statement.nonce:
            _reject(
                DeploymentAttestationRejectReason.NONCE_MISMATCH,
                "attestation nonce does not match the deployment challenge",
            )

        if (
            statement.issued_at_epoch < 0
            or statement.expires_at_epoch <= statement.issued_at_epoch
            or request.evaluated_at_epoch < statement.issued_at_epoch
            or request.evaluated_at_epoch > statement.expires_at_epoch
            or request.evaluated_at_epoch - statement.issued_at_epoch
            > self._policy.max_attestation_age_seconds
            or statement.expires_at_epoch - statement.issued_at_epoch
            > self._policy.max_attestation_age_seconds
        ):
            _reject(
                DeploymentAttestationRejectReason.ATTESTATION_STALE,
                "attestation issuance/expiry window is invalid or stale",
            )

        public_bytes = self._policy.trusted_attestors.get(statement.attestor_id)
        if public_bytes is None:
            _reject(
                DeploymentAttestationRejectReason.ATTESTOR_UNTRUSTED,
                "attestation signer is not trusted by deployment policy",
            )
        if len(public_bytes) != 32 or len(attestation.signature) != 64:
            _reject(
                DeploymentAttestationRejectReason.ATTESTATION_INVALID,
                "Ed25519 attestor key/signature encoding is invalid",
            )
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
            public_key.verify(
                attestation.signature,
                canonical_deployment_attestation_bytes(statement),
            )
        except (ValueError, InvalidSignature):
            _reject(
                DeploymentAttestationRejectReason.SIGNATURE_INVALID,
                "deployment attestation signature verification failed",
            )

        return VerifiedDeploymentAttestation(
            deployment_id=statement.deployment_id,
            package_id=statement.package_id,
            model_id=statement.model_id,
            revision=statement.revision,
            runtime_id=statement.runtime_id,
            registry_id=statement.registry_id,
            channel=statement.channel,
            tag=statement.tag,
            release_digest=statement.release_digest.casefold(),
            scan_evidence_sha256=statement.scan_evidence_sha256.casefold(),
            privacy_policy_sha256=statement.privacy_policy_sha256.casefold(),
            environment_id=environment.environment_id,
            image_digest=environment.image_digest.casefold(),
            runtime_measurement=environment.runtime_measurement.casefold(),
            sandbox_backend=environment.sandbox_backend,
            attestor_id=statement.attestor_id,
            nonce=statement.nonce,
            issued_at_epoch=statement.issued_at_epoch,
            expires_at_epoch=statement.expires_at_epoch,
            statement_sha256=deployment_attestation_digest(statement),
        )
