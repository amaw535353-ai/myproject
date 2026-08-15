from __future__ import annotations

import re

from aegis.model_supply_chain.package_provenance import (
    P5B_PACKAGE_MANIFEST_SCHEMA_VERSION,
    P5B_PACKAGE_POLICY_VERSION,
    ModelPackageComponentRole,
)
from aegis.model_supply_chain.provenance import (
    P5A_MANIFEST_SCHEMA_VERSION,
    P5A_MODEL_ARTIFACT_POLICY_VERSION,
)
from aegis.model_supply_chain.registry_acquisition import (
    P5C_REGISTRY_POLICY_VERSION,
    P5C_RELEASE_SCHEMA_VERSION,
)
from .sensitive_data_types import (
    P9G_ASSESSMENT_MODE,
    P9G_ASSESSMENT_SCHEMA_VERSION,
    SensitiveDataDecision,
)
from .model_promotion_types import *

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_MUTABLE_NAMES = {"latest", "stable", "current", "prod", "production", "default"}
_PHASE5_DATA_ONLY_FORMATS = {"safetensors", "onnx"}


class ModelRegistryPromotionAnalyzer:
    def __init__(self, policy: ModelRegistryPromotionPolicy):
        self.policy = policy
        self._validate_policy()

    @staticmethod
    def _sha(value: str) -> bool:
        return bool(_SHA256_RE.fullmatch(str(value)))

    def _validate_policy(self) -> None:
        p = self.policy
        if p.policy_version != P9H_POLICY_VERSION:
            reject(PromotionRejectReason.POLICY_INVALID, "unexpected policy version")
        identities = (
            p.expected_promotion_id,
            p.expected_governance_id,
            p.expected_evaluation_id,
            p.expected_checkpoint_id,
            p.expected_execution_id,
            p.expected_job_id,
            p.expected_model_id,
            p.expected_revision,
            p.expected_base_model_id,
            p.expected_base_model_revision,
            p.expected_package_id,
            p.expected_package_publisher_id,
            p.expected_registry_id,
            p.expected_channel,
            p.expected_tag,
            p.expected_registry_namespace,
            p.expected_registry_model_name,
            p.expected_registry_version,
            p.expected_immutable_artifact_uri,
            p.expected_principal_id,
            p.expected_authorization_id,
            p.expected_grant_id,
        )
        if not all(identities):
            reject(PromotionRejectReason.POLICY_INVALID, "promotion identity pins are required")
        digests = (
            p.expected_manifest_sha256,
            p.expected_p9g_assessment_sha256,
            p.expected_final_checkpoint_artifact_sha256,
            p.expected_phase5_bridge_sha256,
            p.expected_package_manifest_sha256,
            p.expected_release_digest,
            p.expected_rollback_release_digest,
            *p.expected_sha256_by_artifact_id.values(),
        )
        if not all(self._sha(value) for value in digests):
            reject(PromotionRejectReason.POLICY_INVALID, "promotion digest pins must be SHA-256")
        ids = p.expected_artifact_order
        if not ids or len(ids) != len(set(ids)):
            reject(PromotionRejectReason.POLICY_INVALID, "artifact order must be non-empty and unique")
        maps = (
            p.expected_role_by_artifact_id,
            p.expected_format_by_artifact_id,
            p.expected_sha256_by_artifact_id,
            p.expected_size_by_artifact_id,
            p.expected_source_prefix_by_artifact_id,
        )
        if any(set(mapping) != set(ids) for mapping in maps):
            reject(PromotionRejectReason.POLICY_INVALID, "artifact pin maps must exactly cover artifact order")
        allowed_roles = {role.value for role in ModelPackageComponentRole}
        if any(role not in allowed_roles for role in p.expected_role_by_artifact_id.values()):
            reject(PromotionRejectReason.POLICY_INVALID, "artifact role is outside Phase 5 package roles")
        if sum(role == ModelPackageComponentRole.PRIMARY_MODEL.value for role in p.expected_role_by_artifact_id.values()) != 1:
            reject(PromotionRejectReason.POLICY_INVALID, "exactly one primary model artifact is required")
        if any(str(fmt).casefold() not in _PHASE5_DATA_ONLY_FORMATS for fmt in p.expected_format_by_artifact_id.values()):
            reject(PromotionRejectReason.POLICY_INVALID, "artifact format is outside the Phase 5 data-only handoff allowlist")
        if any(size < 0 for size in p.expected_size_by_artifact_id.values()):
            reject(PromotionRejectReason.POLICY_INVALID, "artifact size pins must be non-negative")
        if p.expected_registry_version.casefold() in _MUTABLE_NAMES or p.expected_tag.casefold() in _MUTABLE_NAMES:
            reject(PromotionRejectReason.POLICY_INVALID, "registry version and tag must be immutable identifiers")
        if p.expected_revocation_epoch <= 0 or p.max_manifest_age_seconds < 0 or p.max_future_skew_seconds < 0:
            reject(PromotionRejectReason.POLICY_INVALID, "promotion policy time bounds are invalid")

    def _validate_manifest(self, manifest: ModelRegistryPromotionManifest) -> None:
        if manifest.schema_version != P9H_SCHEMA_VERSION:
            reject(PromotionRejectReason.MANIFEST_INVALID, "unexpected promotion manifest schema")
        identities = (
            manifest.promotion_id,
            manifest.governance_id,
            manifest.evaluation_id,
            manifest.checkpoint_id,
            manifest.execution_id,
            manifest.job_id,
            manifest.model_id,
            manifest.revision,
            manifest.base_model_id,
            manifest.base_model_revision,
            manifest.registry_namespace,
            manifest.registry_model_name,
            manifest.registry_version,
            manifest.immutable_artifact_uri,
        )
        if not all(identities):
            reject(PromotionRejectReason.MANIFEST_INVALID, "promotion identity is incomplete")
        if not self._sha(manifest.p9g_assessment_sha256) or not self._sha(manifest.final_checkpoint_artifact_sha256):
            reject(PromotionRejectReason.MANIFEST_INVALID, "upstream/checkpoint digest is malformed")
        artifact_ids = tuple(artifact.artifact_id for artifact in manifest.artifacts)
        if not artifact_ids or len(artifact_ids) != len(set(artifact_ids)):
            reject(PromotionRejectReason.MANIFEST_INVALID, "promotion artifact IDs must be non-empty and unique")
        for artifact in manifest.artifacts:
            if not all((artifact.artifact_id, artifact.component_role, artifact.artifact_format, artifact.source)):
                reject(PromotionRejectReason.MANIFEST_INVALID, "promotion artifact metadata is incomplete")
            if not self._sha(artifact.sha256) or artifact.size_bytes < 0:
                reject(PromotionRejectReason.MANIFEST_INVALID, "promotion artifact digest/size is invalid")
        bridge = manifest.phase5_bridge
        if not all((bridge.package_id, bridge.package_publisher_id, bridge.registry_id, bridge.channel, bridge.tag)) or not self._sha(bridge.package_manifest_sha256) or not self._sha(bridge.release_digest):
            reject(PromotionRejectReason.MANIFEST_INVALID, "Phase 5 bridge evidence is incomplete")
        auth = manifest.authorization
        if not all((auth.authorization_id, auth.grant_id, auth.principal_id, auth.action, auth.target)):
            reject(PromotionRejectReason.MANIFEST_INVALID, "promotion authorization is incomplete")
        if not self._sha(auth.p9g_assessment_sha256) or auth.issued_at_epoch > auth.expires_at_epoch:
            reject(PromotionRejectReason.MANIFEST_INVALID, "promotion authorization is invalid")
        if not self._sha(manifest.rollback_release_digest) or manifest.revocation_epoch <= 0 or manifest.network_operations < 0:
            reject(PromotionRejectReason.MANIFEST_INVALID, "rollback/revocation/network metadata is invalid")

    def _upstream_ok(self, assessment) -> bool:
        flags = (
            getattr(assessment, "upstream_p9f_bound", False),
            getattr(assessment, "input_governance_verified", False),
            getattr(assessment, "output_governance_verified", False),
            getattr(assessment, "canary_reproduction_clear", False),
            getattr(assessment, "sensitive_data_policy_verified", False),
        )
        return (
            getattr(assessment, "decision", None) == SensitiveDataDecision.ALLOW
            and not getattr(assessment, "risks", ())
            and all(flags)
            and not getattr(assessment, "caller_declared_safety_trusted", True)
            and not getattr(assessment, "production_dlp_integrated", True)
            and not getattr(assessment, "comprehensive_pii_detection_validated", True)
            and not getattr(assessment, "legal_compliance_verified", True)
            and not getattr(assessment, "differential_privacy_verified", True)
            and not getattr(assessment, "memorization_absence_proven", True)
            and getattr(assessment, "assessment_schema_version", None) == P9G_ASSESSMENT_SCHEMA_VERSION
            and getattr(assessment, "assessment_mode", None) == P9G_ASSESSMENT_MODE
        )

    def derive(self, manifest: ModelRegistryPromotionManifest, p9g_assessment, now: int) -> tuple[PromotionRisk, ...]:
        self._validate_manifest(manifest)
        p = self.policy
        risks: set[PromotionRisk] = set()
        if not self._upstream_ok(p9g_assessment):
            risks.add(PromotionRisk.UPSTREAM_P9G_INVALID)
        if manifest.p9g_assessment_sha256.casefold() != p.expected_p9g_assessment_sha256.casefold() or getattr(p9g_assessment, "assessment_evidence_sha256", "").casefold() != p.expected_p9g_assessment_sha256.casefold():
            risks.add(PromotionRisk.UPSTREAM_BINDING_MISMATCH)
        if (
            manifest.governance_id != p.expected_governance_id
            or manifest.evaluation_id != p.expected_evaluation_id
            or manifest.checkpoint_id != p.expected_checkpoint_id
            or manifest.execution_id != p.expected_execution_id
            or manifest.job_id != p.expected_job_id
            or getattr(p9g_assessment, "governance_id", None) != p.expected_governance_id
            or getattr(p9g_assessment, "evaluation_id", None) != p.expected_evaluation_id
            or getattr(p9g_assessment, "checkpoint_id", None) != p.expected_checkpoint_id
        ):
            risks.add(PromotionRisk.TRAINING_LINEAGE_MISMATCH)
        if (
            manifest.model_id != p.expected_model_id
            or manifest.revision != p.expected_revision
            or manifest.base_model_id != p.expected_base_model_id
            or manifest.base_model_revision != p.expected_base_model_revision
            or manifest.final_checkpoint_artifact_sha256.casefold() != p.expected_final_checkpoint_artifact_sha256.casefold()
        ):
            risks.add(PromotionRisk.MODEL_IDENTITY_MISMATCH)
        artifact_ids = tuple(artifact.artifact_id for artifact in manifest.artifacts)
        if artifact_ids != p.expected_artifact_order:
            risks.add(PromotionRisk.ARTIFACT_COVERAGE_MISMATCH)
        for artifact in manifest.artifacts:
            if (
                p.expected_role_by_artifact_id.get(artifact.artifact_id) != artifact.component_role
                or p.expected_format_by_artifact_id.get(artifact.artifact_id) != artifact.artifact_format
                or p.expected_sha256_by_artifact_id.get(artifact.artifact_id, "").casefold() != artifact.sha256.casefold()
                or p.expected_size_by_artifact_id.get(artifact.artifact_id) != artifact.size_bytes
                or not artifact.source.startswith(p.expected_source_prefix_by_artifact_id.get(artifact.artifact_id, "\0"))
            ):
                risks.add(PromotionRisk.ARTIFACT_METADATA_MISMATCH)
        bridge = manifest.phase5_bridge
        bridge_constants_ok = (
            bridge.p5a_policy_version == P5A_MODEL_ARTIFACT_POLICY_VERSION
            and bridge.p5a_manifest_schema_version == P5A_MANIFEST_SCHEMA_VERSION
            and bridge.p5b_policy_version == P5B_PACKAGE_POLICY_VERSION
            and bridge.p5b_manifest_schema_version == P5B_PACKAGE_MANIFEST_SCHEMA_VERSION
            and bridge.p5c_policy_version == P5C_REGISTRY_POLICY_VERSION
            and bridge.p5c_release_schema_version == P5C_RELEASE_SCHEMA_VERSION
        )
        if (
            not bridge_constants_ok
            or phase5_provenance_bridge_digest(bridge).casefold() != p.expected_phase5_bridge_sha256.casefold()
            or bridge.package_id != p.expected_package_id
            or bridge.package_publisher_id != p.expected_package_publisher_id
            or bridge.package_manifest_sha256.casefold() != p.expected_package_manifest_sha256.casefold()
            or bridge.registry_id != p.expected_registry_id
            or bridge.channel != p.expected_channel
            or bridge.tag != p.expected_tag
            or bridge.release_digest.casefold() != p.expected_release_digest.casefold()
        ):
            risks.add(PromotionRisk.PHASE5_BRIDGE_MISMATCH)
        if (
            manifest.registry_namespace != p.expected_registry_namespace
            or manifest.registry_model_name != p.expected_registry_model_name
            or manifest.registry_version != p.expected_registry_version
            or manifest.immutable_artifact_uri != p.expected_immutable_artifact_uri
        ):
            risks.add(PromotionRisk.REGISTRY_IDENTITY_MISMATCH)
        if (
            manifest.overwrite_existing
            or manifest.mutable_alias_update
            or manifest.registry_version.casefold() in _MUTABLE_NAMES
            or bridge.tag.casefold() in _MUTABLE_NAMES
            or not manifest.immutable_artifact_uri.startswith("registry+sha256://")
        ):
            risks.add(PromotionRisk.MUTABLE_REFERENCE_UNSAFE)
        auth = manifest.authorization
        expected_target = f"{manifest.registry_namespace}/{manifest.registry_model_name}@{manifest.registry_version}"
        if (
            auth.authorization_id != p.expected_authorization_id
            or auth.grant_id != p.expected_grant_id
            or auth.principal_id != p.expected_principal_id
            or auth.action != "promote-model"
            or auth.target != expected_target
            or auth.p9g_assessment_sha256.casefold() != manifest.p9g_assessment_sha256.casefold()
        ):
            risks.add(PromotionRisk.PROMOTION_AUTHORIZATION_INVALID)
        if now < auth.issued_at_epoch - p.max_future_skew_seconds or now > auth.expires_at_epoch:
            risks.add(PromotionRisk.AUTHORIZATION_EXPIRED)
        if manifest.predecessor_version != p.expected_predecessor_version:
            risks.add(PromotionRisk.PREDECESSOR_MISMATCH)
        if manifest.rollback_release_digest.casefold() != p.expected_rollback_release_digest.casefold():
            risks.add(PromotionRisk.ROLLBACK_BINDING_MISMATCH)
        if manifest.revocation_epoch != p.expected_revocation_epoch or manifest.revocation_epoch <= manifest.created_at_epoch:
            risks.add(PromotionRisk.REVOCATION_POLICY_MISMATCH)
        if manifest.network_operations != 0:
            risks.add(PromotionRisk.NETWORK_OPERATION_UNEXPECTED)
        return tuple(sorted(risks, key=lambda risk: risk.value))

    def evaluate(self, request: ModelRegistryPromotionRequest, manifest: ModelRegistryPromotionManifest, p9g_assessment) -> VerifiedModelRegistryPromotionAssessment:
        self._validate_manifest(manifest)
        actual_manifest_sha = model_registry_promotion_manifest_digest(manifest)
        if actual_manifest_sha.casefold() != self.policy.expected_manifest_sha256.casefold():
            reject(PromotionRejectReason.MANIFEST_DIGEST_MISMATCH, "promotion manifest differs from policy-pinned evidence")
        if request.promotion_id != manifest.promotion_id or request.manifest_sha256.casefold() != actual_manifest_sha.casefold():
            reject(PromotionRejectReason.REQUEST_INVALID, "request promotion manifest binding mismatch")
        if request.evaluated_at_epoch < manifest.created_at_epoch - self.policy.max_future_skew_seconds:
            reject(PromotionRejectReason.REQUEST_INVALID, "promotion request predates manifest beyond allowed skew")
        if request.evaluated_at_epoch > manifest.created_at_epoch + self.policy.max_manifest_age_seconds:
            reject(PromotionRejectReason.REQUEST_INVALID, "promotion manifest is stale")
        artifact_ids = tuple(artifact.artifact_id for artifact in manifest.artifacts)
        declared = (
            request.declared_model_id == manifest.model_id
            and request.declared_revision == manifest.revision
            and request.declared_registry_namespace == manifest.registry_namespace
            and request.declared_registry_model_name == manifest.registry_model_name
            and request.declared_registry_version == manifest.registry_version
            and request.declared_artifact_ids == artifact_ids
        )
        if not declared:
            reject(PromotionRejectReason.DECLARED_SUMMARY_MISMATCH, "caller promotion summary disagrees with evidence")
        risks = self.derive(manifest, p9g_assessment, request.evaluated_at_epoch)
        decision = PromotionDecision.ALLOW if not risks else PromotionDecision.DENY
        safe = not risks
        declarations = (
            request.declared_upstream_bound,
            request.declared_training_lineage_valid,
            request.declared_phase5_provenance_bound,
            request.declared_registry_target_immutable,
            request.declared_promotion_authorized,
            request.declared_promotion_safe,
        )
        if declarations != (safe, safe, safe, safe, safe, safe):
            reject(PromotionRejectReason.DECLARED_SUMMARY_MISMATCH, "caller safety declarations disagree with derived evidence")
        assessment = VerifiedModelRegistryPromotionAssessment(
            promotion_id=manifest.promotion_id,
            model_id=manifest.model_id,
            revision=manifest.revision,
            governance_id=manifest.governance_id,
            evaluation_id=manifest.evaluation_id,
            checkpoint_id=manifest.checkpoint_id,
            execution_id=manifest.execution_id,
            job_id=manifest.job_id,
            decision=decision,
            risks=risks,
            p9g_assessment_sha256=manifest.p9g_assessment_sha256.casefold(),
            artifact_ids=artifact_ids,
            package_id=manifest.phase5_bridge.package_id,
            registry_id=manifest.phase5_bridge.registry_id,
            registry_namespace=manifest.registry_namespace,
            registry_model_name=manifest.registry_model_name,
            registry_version=manifest.registry_version,
            release_digest=manifest.phase5_bridge.release_digest.casefold(),
            upstream_p9g_bound=safe,
            training_lineage_verified=safe,
            phase5_provenance_handoff_bound=safe,
            registry_target_immutable=safe,
            promotion_authorization_verified=safe,
            rollback_and_revocation_bound=safe,
            caller_declared_safety_trusted=False,
            registry_write_executed=False,
            production_model_registry_integrated=False,
            cryptographic_promotion_signature_verified=False,
            deployment_executed=False,
            assessment_schema_version=P9H_ASSESSMENT_SCHEMA_VERSION,
            assessment_mode=P9H_ASSESSMENT_MODE,
            assessment_evidence_sha256="",
        )
        return VerifiedModelRegistryPromotionAssessment(**{**assessment.__dict__, "assessment_evidence_sha256": digest_json(assessment)})
