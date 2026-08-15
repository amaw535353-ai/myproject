from __future__ import annotations

from dataclasses import replace
import hashlib

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
from aegis.training.model_promotion_types import *
from aegis.training.sensitive_data_types import (
    P9G_ASSESSMENT_MODE,
    P9G_ASSESSMENT_SCHEMA_VERSION,
    SensitiveDataDecision,
    VerifiedSensitiveDataGovernanceAssessment,
)

NOW = 1_800_060_000
PROMOTION_ID = "p9h-model-promotion-001"
P9G_ASSESSMENT_SHA = "5f6fef4642e0f9d390ba7a7745f74290176608e4f0e24eafff7cb3de28cc5849"
GOVERNANCE_ID = "p9g-sensitive-data-governance-001"
EVALUATION_ID = "p9f-evaluation-001"
CHECKPOINT_ID = "ckpt-0800"
EXECUTION_ID = "p9d-training-execution-001"
JOB_ID = "train-job-p9d-001"
MODEL_ID = "aegisdesk-helpdesk-secure"
REVISION = "train-p9h-r1"
BASE_MODEL_ID = "aegisdesk/base-helpdesk"
BASE_MODEL_REVISION = "sha256:base-2026-08-r1"
PACKAGE_ID = "aegisdesk-helpdesk-secure-package-r1"
REGISTRY_ID = "aegisdesk-model-registry"
CHANNEL = "candidate"
TAG = "release-2026-08-15-r1"
REGISTRY_NAMESPACE = "aegisdesk/secure-training"
REGISTRY_MODEL_NAME = "helpdesk-secure"
REGISTRY_VERSION = "2026.08.15-p9h-r1"
PREDECESSOR_VERSION = "2026.08.14-p9g-r1"


def h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


ARTIFACT_IDS = ("model.safetensors", "adapter.safetensors", "config.onnx", "tokenizer.onnx")


def build_p9g_assessment() -> VerifiedSensitiveDataGovernanceAssessment:
    return VerifiedSensitiveDataGovernanceAssessment(
        governance_id=GOVERNANCE_ID,
        evaluation_id=EVALUATION_ID,
        checkpoint_id=CHECKPOINT_ID,
        decision=SensitiveDataDecision.ALLOW,
        risks=(),
        p9f_assessment_sha256=h("p9f-assessment:p9g-bound"),
        record_ids=("train-public-01", "train-pii-01", "eval-public-01", "eval-pii-01", "output-public-01", "output-public-02"),
        included_training_record_ids=("train-public-01", "train-pii-01"),
        output_record_ids=("output-public-01", "output-public-02"),
        upstream_p9f_bound=True,
        input_governance_verified=True,
        output_governance_verified=True,
        canary_reproduction_clear=True,
        sensitive_data_policy_verified=True,
        caller_declared_safety_trusted=False,
        production_dlp_integrated=False,
        comprehensive_pii_detection_validated=False,
        legal_compliance_verified=False,
        differential_privacy_verified=False,
        memorization_absence_proven=False,
        assessment_schema_version=P9G_ASSESSMENT_SCHEMA_VERSION,
        assessment_mode=P9G_ASSESSMENT_MODE,
        assessment_evidence_sha256=P9G_ASSESSMENT_SHA,
    )


def _artifacts() -> tuple[PromotionArtifactEvidence, ...]:
    return (
        PromotionArtifactEvidence("model.safetensors", ModelPackageComponentRole.PRIMARY_MODEL.value, "safetensors", h("p9h:primary-model:v1"), 800_000_000, "registry-staging://p9h/model.safetensors"),
        PromotionArtifactEvidence("adapter.safetensors", ModelPackageComponentRole.ADAPTER.value, "safetensors", h("p9h:adapter:v1"), 16_000_000, "registry-staging://p9h/adapter.safetensors"),
        PromotionArtifactEvidence("config.onnx", ModelPackageComponentRole.CONFIG.value, "onnx", h("p9h:config:v1"), 4096, "registry-staging://p9h/config.onnx"),
        PromotionArtifactEvidence("tokenizer.onnx", ModelPackageComponentRole.TOKENIZER.value, "onnx", h("p9h:tokenizer:v1"), 65536, "registry-staging://p9h/tokenizer.onnx"),
    )


def build_fixture() -> dict[str, object]:
    artifacts = _artifacts()
    package_manifest_sha = h("phase5-package-manifest:p9h:v1")
    release_digest = h("phase5-registry-release:p9h:v1")
    bridge = Phase5ProvenanceBridgeEvidence(P5A_MODEL_ARTIFACT_POLICY_VERSION, P5A_MANIFEST_SCHEMA_VERSION, P5B_PACKAGE_POLICY_VERSION, P5B_PACKAGE_MANIFEST_SCHEMA_VERSION, P5C_REGISTRY_POLICY_VERSION, P5C_RELEASE_SCHEMA_VERSION, PACKAGE_ID, "aegisdesk-training-publisher", package_manifest_sha, REGISTRY_ID, CHANNEL, TAG, release_digest)
    target = f"{REGISTRY_NAMESPACE}/{REGISTRY_MODEL_NAME}@{REGISTRY_VERSION}"
    authorization = ModelPromotionAuthorizationEvidence("promotion-auth-001", "registry-promotion-grant-001", "trainer-release-manager", "promote-model", target, P9G_ASSESSMENT_SHA, NOW - 10, NOW + 120)
    rollback_release_digest = h("phase5-registry-release:previous:v1")
    final_checkpoint_sha = h("ckpt-0800:artifact:p9h-bound")
    manifest = ModelRegistryPromotionManifest(P9H_SCHEMA_VERSION, PROMOTION_ID, NOW, P9G_ASSESSMENT_SHA, GOVERNANCE_ID, EVALUATION_ID, CHECKPOINT_ID, EXECUTION_ID, JOB_ID, MODEL_ID, REVISION, BASE_MODEL_ID, BASE_MODEL_REVISION, final_checkpoint_sha, artifacts, bridge, REGISTRY_NAMESPACE, REGISTRY_MODEL_NAME, REGISTRY_VERSION, f"registry+sha256://{REGISTRY_ID}/{release_digest}", PREDECESSOR_VERSION, rollback_release_digest, NOW + 86_400, False, False, authorization, 0)
    policy = ModelRegistryPromotionPolicy(
        policy_version=P9H_POLICY_VERSION, expected_promotion_id=PROMOTION_ID, expected_manifest_sha256=model_registry_promotion_manifest_digest(manifest), expected_p9g_assessment_sha256=P9G_ASSESSMENT_SHA, expected_governance_id=GOVERNANCE_ID, expected_evaluation_id=EVALUATION_ID, expected_checkpoint_id=CHECKPOINT_ID, expected_execution_id=EXECUTION_ID, expected_job_id=JOB_ID, expected_model_id=MODEL_ID, expected_revision=REVISION, expected_base_model_id=BASE_MODEL_ID, expected_base_model_revision=BASE_MODEL_REVISION, expected_final_checkpoint_artifact_sha256=final_checkpoint_sha,
        expected_artifact_order=ARTIFACT_IDS, expected_role_by_artifact_id={a.artifact_id:a.component_role for a in artifacts}, expected_format_by_artifact_id={a.artifact_id:a.artifact_format for a in artifacts}, expected_sha256_by_artifact_id={a.artifact_id:a.sha256 for a in artifacts}, expected_size_by_artifact_id={a.artifact_id:a.size_bytes for a in artifacts}, expected_source_prefix_by_artifact_id={a.artifact_id:"registry-staging://p9h/" for a in artifacts},
        expected_phase5_bridge_sha256=phase5_provenance_bridge_digest(bridge), expected_package_id=PACKAGE_ID, expected_package_publisher_id=bridge.package_publisher_id, expected_package_manifest_sha256=package_manifest_sha, expected_registry_id=REGISTRY_ID, expected_channel=CHANNEL, expected_tag=TAG, expected_release_digest=release_digest, expected_registry_namespace=REGISTRY_NAMESPACE, expected_registry_model_name=REGISTRY_MODEL_NAME, expected_registry_version=REGISTRY_VERSION, expected_immutable_artifact_uri=manifest.immutable_artifact_uri, expected_predecessor_version=PREDECESSOR_VERSION, expected_rollback_release_digest=rollback_release_digest, expected_revocation_epoch=manifest.revocation_epoch, expected_principal_id=authorization.principal_id, expected_authorization_id=authorization.authorization_id, expected_grant_id=authorization.grant_id, max_manifest_age_seconds=300, max_future_skew_seconds=5,
    )
    request = ModelRegistryPromotionRequest(PROMOTION_ID, model_registry_promotion_manifest_digest(manifest), NOW, MODEL_ID, REVISION, REGISTRY_NAMESPACE, REGISTRY_MODEL_NAME, REGISTRY_VERSION, ARTIFACT_IDS, True, True, True, True, True, True)
    return {"manifest": manifest, "policy": policy, "request": request, "p9g": build_p9g_assessment()}


def rebind(fixture: dict[str, object], *, manifest=None, p9g=None, preserve_declarations: bool = True, **request_updates) -> dict[str, object]:
    manifest = manifest or fixture["manifest"]; p9g = p9g or fixture["p9g"]; policy = fixture["policy"]; request = fixture["request"]
    assert isinstance(manifest, ModelRegistryPromotionManifest) and isinstance(policy, ModelRegistryPromotionPolicy) and isinstance(request, ModelRegistryPromotionRequest)
    digest = model_registry_promotion_manifest_digest(manifest)
    out = dict(fixture); out["manifest"] = manifest; out["p9g"] = p9g; out["policy"] = replace(policy, expected_manifest_sha256=digest)
    identity_updates = {}
    if not preserve_declarations:
        identity_updates = dict(declared_model_id=manifest.model_id, declared_revision=manifest.revision, declared_registry_namespace=manifest.registry_namespace, declared_registry_model_name=manifest.registry_model_name, declared_registry_version=manifest.registry_version, declared_artifact_ids=tuple(a.artifact_id for a in manifest.artifacts))
    identity_updates.update(request_updates)
    out["request"] = replace(request, manifest_sha256=digest, **identity_updates)
    return out
