from __future__ import annotations

from dataclasses import replace
import hashlib

from aegis.training.data_poisoning_types import (
    P9B_ASSESSMENT_MODE,
    P9B_ASSESSMENT_SCHEMA_VERSION,
    PoisoningDecision,
    VerifiedTrainingPoisoningAssessment,
)
from aegis.training.fine_tuning_types import *

NOW = 1_800_020_000
MANIFEST_ID = "p9c-fine-tuning-manifest-001"
DATASET_ID = "aegisdesk-helpdesk-training"
DATASET_VERSION = "2026.08-p9a"
PRINCIPAL_ID = "trainer-security"
TASK_ID = "fine-tune-helpdesk-security-v1"
GRANT_ID = "grant-p9c-001"
OUTPUT_ID = "adapter://aegisdesk/helpdesk-security-v1"
RECORD_IDS = tuple(f"record-{i:02d}" for i in range(1, 9))
ADAPTER_IDS = ("adapter-helpdesk-lora", "adapter-security-policy")


def h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


P9B_ASSESSMENT_SHA = h("p9b-clean-assessment:p9c-bound")
BASE_ARTIFACT_SHA = h("base-model:artifact:aegisdesk-base-7b@r42")
BASE_PACKAGE_SHA = h("base-model:package:aegisdesk-base-7b@r42")
TOKENIZER_SHA = h("tokenizer:aegisdesk-base-7b@r42")
SELECTED_DATA_SHA = selected_training_data_digest(P9B_ASSESSMENT_SHA, RECORD_IDS)


def build_p9b_assessment() -> VerifiedTrainingPoisoningAssessment:
    return VerifiedTrainingPoisoningAssessment(
        manifest_id="p9b-training-poisoning-manifest-001",
        dataset_id=DATASET_ID,
        dataset_version=DATASET_VERSION,
        decision=PoisoningDecision.ALLOW,
        risks=(),
        record_count=len(RECORD_IDS),
        included_record_ids=RECORD_IDS,
        quarantined_record_ids=(),
        contributor_count=3,
        reviewed_record_count=2,
        weighted_risk_score=450,
        upstream_p9a_bound=True,
        record_integrity_verified=True,
        label_integrity_verified=True,
        contributor_trust_verified=True,
        poisoning_indicators_clear=True,
        caller_declared_training_data_safety_trusted=False,
        production_data_quality_platform_integrated=False,
        semantic_poisoning_detection_validated=False,
        human_review_identity_cryptographically_authenticated=False,
        assessment_schema_version=P9B_ASSESSMENT_SCHEMA_VERSION,
        assessment_mode=P9B_ASSESSMENT_MODE,
        assessment_evidence_sha256=P9B_ASSESSMENT_SHA,
    )


def build_fixture() -> dict[str, object]:
    base = FineTuneBaseModelEvidence(
        model_id="aegisdesk-base-7b",
        revision="r42",
        artifact_sha256=BASE_ARTIFACT_SHA,
        package_sha256=BASE_PACKAGE_SHA,
        tokenizer_sha256=TOKENIZER_SHA,
        runtime_profile="transformers-safe-v3",
    )
    adapters = (
        FineTuneAdapterSpec(
            adapter_id="adapter-helpdesk-lora",
            mode=FineTuneMode.LORA,
            serialization_format="safetensors",
            rank=16,
            alpha_bps=3200,
            target_modules=("q_proj", "v_proj"),
            init_sha256=h("adapter-init:helpdesk-lora:v1"),
            parent_adapter_ids=(),
        ),
        FineTuneAdapterSpec(
            adapter_id="adapter-security-policy",
            mode=FineTuneMode.ADAPTER,
            serialization_format="safetensors",
            rank=8,
            alpha_bps=1600,
            target_modules=("o_proj",),
            init_sha256=h("adapter-init:security-policy:v1"),
            parent_adapter_ids=("adapter-helpdesk-lora",),
        ),
    )
    hp = FineTuneHyperparameters(
        learning_rate_micros=200,
        epochs_milli=2500,
        batch_size=8,
        max_steps=1200,
        seed=17,
        gradient_accumulation_steps=4,
    )
    auth = FineTuneAuthorizationEvidence(
        grant_id=GRANT_ID,
        principal_id=PRINCIPAL_ID,
        task_id=TASK_ID,
        p9b_assessment_sha256=P9B_ASSESSMENT_SHA,
        base_model_artifact_sha256=BASE_ARTIFACT_SHA,
        selected_data_sha256=SELECTED_DATA_SHA,
        issued_at_epoch=NOW - 60,
        expires_at_epoch=NOW + 600,
        allowed_modes=(FineTuneMode.LORA, FineTuneMode.ADAPTER),
    )
    manifest = FineTuningAdmissionManifest(
        schema_version=P9C_SCHEMA_VERSION,
        manifest_id=MANIFEST_ID,
        dataset_id=DATASET_ID,
        dataset_version=DATASET_VERSION,
        created_at_epoch=NOW,
        p9b_assessment_sha256=P9B_ASSESSMENT_SHA,
        selected_record_ids=RECORD_IDS,
        selected_data_sha256=SELECTED_DATA_SHA,
        principal_id=PRINCIPAL_ID,
        task_id=TASK_ID,
        base_model=base,
        adapters=adapters,
        hyperparameters=hp,
        authorization=auth,
        planned_output_artifact_id=OUTPUT_ID,
    )
    policy = FineTuningAdmissionPolicy(
        policy_version=P9C_POLICY_VERSION,
        expected_manifest_id=MANIFEST_ID,
        expected_dataset_id=DATASET_ID,
        expected_dataset_version=DATASET_VERSION,
        expected_manifest_sha256=fine_tuning_manifest_digest(manifest),
        expected_p9b_assessment_sha256=P9B_ASSESSMENT_SHA,
        expected_selected_record_ids=RECORD_IDS,
        expected_selected_data_sha256=SELECTED_DATA_SHA,
        expected_principal_id=PRINCIPAL_ID,
        expected_task_id=TASK_ID,
        expected_grant_id=GRANT_ID,
        expected_base_model_id=base.model_id,
        expected_base_model_revision=base.revision,
        expected_base_model_artifact_sha256=base.artifact_sha256,
        expected_base_model_package_sha256=base.package_sha256,
        expected_tokenizer_sha256=base.tokenizer_sha256,
        expected_runtime_profile=base.runtime_profile,
        expected_adapter_order=ADAPTER_IDS,
        allowed_modes=(FineTuneMode.LORA, FineTuneMode.ADAPTER),
        allowed_serialization_formats=("safetensors",),
        expected_adapter_init_sha256_by_id={a.adapter_id: a.init_sha256 for a in adapters},
        allowed_target_modules=("q_proj", "k_proj", "v_proj", "o_proj"),
        max_adapter_rank=32,
        max_adapter_alpha_bps=6400,
        max_adapter_stack_depth=2,
        min_learning_rate_micros=50,
        max_learning_rate_micros=500,
        min_epochs_milli=500,
        max_epochs_milli=4000,
        max_batch_size=16,
        max_steps=2000,
        allowed_seeds=(17, 23),
        max_gradient_accumulation_steps=8,
        expected_output_artifact_id=OUTPUT_ID,
        max_manifest_age_seconds=300,
        max_future_skew_seconds=5,
    )
    request = FineTuningAdmissionRequest(
        manifest_id=MANIFEST_ID,
        manifest_sha256=fine_tuning_manifest_digest(manifest),
        dataset_id=DATASET_ID,
        dataset_version=DATASET_VERSION,
        evaluated_at_epoch=NOW,
        declared_selected_record_ids=RECORD_IDS,
        declared_selected_data_sha256=SELECTED_DATA_SHA,
        declared_base_model_artifact_sha256=BASE_ARTIFACT_SHA,
        declared_adapter_ids=ADAPTER_IDS,
        declared_authorized=True,
        declared_base_model_bound=True,
        declared_adapter_policy_safe=True,
        declared_training_admission_safe=True,
    )
    return {"manifest": manifest, "policy": policy, "request": request, "p9b": build_p9b_assessment()}


def rebind(fixture: dict[str, object], *, manifest=None, p9b=None, **request_updates) -> dict[str, object]:
    manifest = manifest or fixture["manifest"]
    p9b = p9b or fixture["p9b"]
    policy = fixture["policy"]
    request = fixture["request"]
    assert isinstance(manifest, FineTuningAdmissionManifest)
    assert isinstance(policy, FineTuningAdmissionPolicy)
    assert isinstance(request, FineTuningAdmissionRequest)
    digest = fine_tuning_manifest_digest(manifest)
    out = dict(fixture)
    out["manifest"] = manifest
    out["p9b"] = p9b
    out["policy"] = replace(policy, expected_manifest_sha256=digest)
    out["request"] = replace(
        request,
        manifest_sha256=digest,
        declared_selected_record_ids=tuple(sorted(manifest.selected_record_ids)),
        declared_selected_data_sha256=manifest.selected_data_sha256,
        declared_base_model_artifact_sha256=manifest.base_model.artifact_sha256,
        declared_adapter_ids=tuple(a.adapter_id for a in manifest.adapters),
        **request_updates,
    )
    return out
