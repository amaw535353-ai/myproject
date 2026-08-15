from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Mapping

P9H_POLICY_VERSION = "training-model-registry-promotion-v1"
P9H_SCHEMA_VERSION = "aegis-model-registry-promotion-manifest-v1"
P9H_ASSESSMENT_SCHEMA_VERSION = "aegis-model-registry-promotion-assessment-v1"
P9H_ASSESSMENT_MODE = "deterministic-evidence-bound-model-promotion-v1"


class PromotionDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class PromotionRisk(str, Enum):
    UPSTREAM_P9G_INVALID = "upstream_p9g_invalid"
    UPSTREAM_BINDING_MISMATCH = "upstream_binding_mismatch"
    TRAINING_LINEAGE_MISMATCH = "training_lineage_mismatch"
    MODEL_IDENTITY_MISMATCH = "model_identity_mismatch"
    ARTIFACT_COVERAGE_MISMATCH = "artifact_coverage_mismatch"
    ARTIFACT_METADATA_MISMATCH = "artifact_metadata_mismatch"
    PHASE5_BRIDGE_MISMATCH = "phase5_bridge_mismatch"
    REGISTRY_IDENTITY_MISMATCH = "registry_identity_mismatch"
    MUTABLE_REFERENCE_UNSAFE = "mutable_reference_unsafe"
    PROMOTION_AUTHORIZATION_INVALID = "promotion_authorization_invalid"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    PREDECESSOR_MISMATCH = "predecessor_mismatch"
    ROLLBACK_BINDING_MISMATCH = "rollback_binding_mismatch"
    REVOCATION_POLICY_MISMATCH = "revocation_policy_mismatch"
    NETWORK_OPERATION_UNEXPECTED = "network_operation_unexpected"


class PromotionRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_SUMMARY_MISMATCH = "declared_summary_mismatch"


class ModelPromotionSecurityRejected(ValueError):
    def __init__(self, reason: PromotionRejectReason, message: str):
        super().__init__(f"{reason.value}: {message}")
        self.reason = reason
        self.message = message


def reject(reason: PromotionRejectReason, message: str) -> None:
    raise ModelPromotionSecurityRejected(reason, message)


def _jsonable(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {
            str(key.value if isinstance(key, Enum) else key): _jsonable(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def canonical_json_bytes(value) -> bytes:
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest_json(value) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True)
class PromotionArtifactEvidence:
    artifact_id: str
    component_role: str
    artifact_format: str
    sha256: str
    size_bytes: int
    source: str


@dataclass(frozen=True)
class Phase5ProvenanceBridgeEvidence:
    p5a_policy_version: str
    p5a_manifest_schema_version: str
    p5b_policy_version: str
    p5b_manifest_schema_version: str
    p5c_policy_version: str
    p5c_release_schema_version: str
    package_id: str
    package_publisher_id: str
    package_manifest_sha256: str
    registry_id: str
    channel: str
    tag: str
    release_digest: str


@dataclass(frozen=True)
class ModelPromotionAuthorizationEvidence:
    authorization_id: str
    grant_id: str
    principal_id: str
    action: str
    target: str
    p9g_assessment_sha256: str
    issued_at_epoch: int
    expires_at_epoch: int


@dataclass(frozen=True)
class ModelRegistryPromotionManifest:
    schema_version: str
    promotion_id: str
    created_at_epoch: int
    p9g_assessment_sha256: str
    governance_id: str
    evaluation_id: str
    checkpoint_id: str
    execution_id: str
    job_id: str
    model_id: str
    revision: str
    base_model_id: str
    base_model_revision: str
    final_checkpoint_artifact_sha256: str
    artifacts: tuple[PromotionArtifactEvidence, ...]
    phase5_bridge: Phase5ProvenanceBridgeEvidence
    registry_namespace: str
    registry_model_name: str
    registry_version: str
    immutable_artifact_uri: str
    predecessor_version: str
    rollback_release_digest: str
    revocation_epoch: int
    overwrite_existing: bool
    mutable_alias_update: bool
    authorization: ModelPromotionAuthorizationEvidence
    network_operations: int = 0


@dataclass(frozen=True)
class ModelRegistryPromotionPolicy:
    policy_version: str
    expected_promotion_id: str
    expected_manifest_sha256: str
    expected_p9g_assessment_sha256: str
    expected_governance_id: str
    expected_evaluation_id: str
    expected_checkpoint_id: str
    expected_execution_id: str
    expected_job_id: str
    expected_model_id: str
    expected_revision: str
    expected_base_model_id: str
    expected_base_model_revision: str
    expected_final_checkpoint_artifact_sha256: str
    expected_artifact_order: tuple[str, ...]
    expected_role_by_artifact_id: Mapping[str, str]
    expected_format_by_artifact_id: Mapping[str, str]
    expected_sha256_by_artifact_id: Mapping[str, str]
    expected_size_by_artifact_id: Mapping[str, int]
    expected_source_prefix_by_artifact_id: Mapping[str, str]
    expected_phase5_bridge_sha256: str
    expected_package_id: str
    expected_package_publisher_id: str
    expected_package_manifest_sha256: str
    expected_registry_id: str
    expected_channel: str
    expected_tag: str
    expected_release_digest: str
    expected_registry_namespace: str
    expected_registry_model_name: str
    expected_registry_version: str
    expected_immutable_artifact_uri: str
    expected_predecessor_version: str
    expected_rollback_release_digest: str
    expected_revocation_epoch: int
    expected_principal_id: str
    expected_authorization_id: str
    expected_grant_id: str
    max_manifest_age_seconds: int
    max_future_skew_seconds: int


@dataclass(frozen=True)
class ModelRegistryPromotionRequest:
    promotion_id: str
    manifest_sha256: str
    evaluated_at_epoch: int
    declared_model_id: str
    declared_revision: str
    declared_registry_namespace: str
    declared_registry_model_name: str
    declared_registry_version: str
    declared_artifact_ids: tuple[str, ...]
    declared_upstream_bound: bool
    declared_training_lineage_valid: bool
    declared_phase5_provenance_bound: bool
    declared_registry_target_immutable: bool
    declared_promotion_authorized: bool
    declared_promotion_safe: bool


@dataclass(frozen=True)
class VerifiedModelRegistryPromotionAssessment:
    promotion_id: str
    model_id: str
    revision: str
    governance_id: str
    evaluation_id: str
    checkpoint_id: str
    execution_id: str
    job_id: str
    decision: PromotionDecision
    risks: tuple[PromotionRisk, ...]
    p9g_assessment_sha256: str
    artifact_ids: tuple[str, ...]
    package_id: str
    registry_id: str
    registry_namespace: str
    registry_model_name: str
    registry_version: str
    release_digest: str
    upstream_p9g_bound: bool
    training_lineage_verified: bool
    phase5_provenance_handoff_bound: bool
    registry_target_immutable: bool
    promotion_authorization_verified: bool
    rollback_and_revocation_bound: bool
    caller_declared_safety_trusted: bool
    registry_write_executed: bool
    production_model_registry_integrated: bool
    cryptographic_promotion_signature_verified: bool
    deployment_executed: bool
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def phase5_provenance_bridge_digest(bridge: Phase5ProvenanceBridgeEvidence) -> str:
    return digest_json(bridge)


def model_registry_promotion_manifest_digest(manifest: ModelRegistryPromotionManifest) -> str:
    return digest_json(manifest)
