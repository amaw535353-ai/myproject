from __future__ import annotations

import re

from .data_poisoning_types import P9B_ASSESSMENT_MODE, P9B_ASSESSMENT_SCHEMA_VERSION, PoisoningDecision
from .fine_tuning_types import *

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class FineTuningAdmissionAnalyzer:
    def __init__(self, policy: FineTuningAdmissionPolicy):
        self.policy = policy
        self._validate_policy()

    @staticmethod
    def _sha(value: str) -> bool:
        return bool(_SHA256_RE.fullmatch(str(value)))

    def _validate_policy(self) -> None:
        p = self.policy
        if p.policy_version != P9C_POLICY_VERSION:
            reject(FineTuneRejectReason.POLICY_INVALID, "unexpected policy version")
        if not all((p.expected_manifest_id, p.expected_dataset_id, p.expected_dataset_version, p.expected_principal_id, p.expected_task_id, p.expected_grant_id)):
            reject(FineTuneRejectReason.POLICY_INVALID, "identity pins are required")
        digest_values = (
            p.expected_manifest_sha256,
            p.expected_p9b_assessment_sha256,
            p.expected_selected_data_sha256,
            p.expected_base_model_artifact_sha256,
            p.expected_base_model_package_sha256,
            p.expected_tokenizer_sha256,
            *p.expected_adapter_init_sha256_by_id.values(),
        )
        if not all(self._sha(v) for v in digest_values):
            reject(FineTuneRejectReason.POLICY_INVALID, "digest pins must be sha256")
        if tuple(sorted(set(p.expected_selected_record_ids))) != tuple(sorted(p.expected_selected_record_ids)):
            reject(FineTuneRejectReason.POLICY_INVALID, "selected record IDs must be unique")
        if len(set(p.expected_adapter_order)) != len(p.expected_adapter_order):
            reject(FineTuneRejectReason.POLICY_INVALID, "adapter order must be unique")
        if set(p.expected_adapter_init_sha256_by_id) != set(p.expected_adapter_order):
            reject(FineTuneRejectReason.POLICY_INVALID, "adapter init pins must cover adapter order")
        if not p.allowed_modes or not p.allowed_serialization_formats or not p.allowed_target_modules:
            reject(FineTuneRejectReason.POLICY_INVALID, "adapter policy allowlists are required")
        if p.max_adapter_rank <= 0 or p.max_adapter_alpha_bps <= 0 or p.max_adapter_stack_depth <= 0:
            reject(FineTuneRejectReason.POLICY_INVALID, "adapter bounds must be positive")
        if not (0 < p.min_learning_rate_micros <= p.max_learning_rate_micros):
            reject(FineTuneRejectReason.POLICY_INVALID, "learning-rate bounds invalid")
        if not (0 < p.min_epochs_milli <= p.max_epochs_milli):
            reject(FineTuneRejectReason.POLICY_INVALID, "epoch bounds invalid")
        if p.max_batch_size <= 0 or p.max_steps <= 0 or p.max_gradient_accumulation_steps <= 0:
            reject(FineTuneRejectReason.POLICY_INVALID, "training bounds must be positive")
        if not p.allowed_seeds:
            reject(FineTuneRejectReason.POLICY_INVALID, "at least one deterministic seed is required")
        if p.max_manifest_age_seconds < 0 or p.max_future_skew_seconds < 0:
            reject(FineTuneRejectReason.POLICY_INVALID, "freshness bounds invalid")

    def _validate_manifest(self, manifest: FineTuningAdmissionManifest) -> None:
        if manifest.schema_version != P9C_SCHEMA_VERSION:
            reject(FineTuneRejectReason.MANIFEST_INVALID, "unexpected manifest schema")
        if manifest.manifest_id != self.policy.expected_manifest_id:
            reject(FineTuneRejectReason.MANIFEST_INVALID, "manifest identity mismatch")
        if manifest.dataset_id != self.policy.expected_dataset_id or manifest.dataset_version != self.policy.expected_dataset_version:
            reject(FineTuneRejectReason.MANIFEST_INVALID, "dataset identity mismatch")
        if not self._sha(manifest.p9b_assessment_sha256) or not self._sha(manifest.selected_data_sha256):
            reject(FineTuneRejectReason.MANIFEST_INVALID, "upstream/selected data digests invalid")
        if len(manifest.selected_record_ids) != len(set(manifest.selected_record_ids)):
            reject(FineTuneRejectReason.MANIFEST_INVALID, "duplicate selected record IDs")
        base = manifest.base_model
        if not all((base.model_id, base.revision, base.runtime_profile)):
            reject(FineTuneRejectReason.MANIFEST_INVALID, "base model identity incomplete")
        if not all(self._sha(v) for v in (base.artifact_sha256, base.package_sha256, base.tokenizer_sha256)):
            reject(FineTuneRejectReason.MANIFEST_INVALID, "base model digests invalid")
        adapter_ids = [a.adapter_id for a in manifest.adapters]
        if len(adapter_ids) != len(set(adapter_ids)):
            reject(FineTuneRejectReason.MANIFEST_INVALID, "duplicate adapter IDs")
        for adapter in manifest.adapters:
            if not adapter.adapter_id or not adapter.serialization_format or not self._sha(adapter.init_sha256):
                reject(FineTuneRejectReason.MANIFEST_INVALID, "invalid adapter evidence")
            if len(adapter.target_modules) != len(set(adapter.target_modules)) or len(adapter.parent_adapter_ids) != len(set(adapter.parent_adapter_ids)):
                reject(FineTuneRejectReason.MANIFEST_INVALID, "duplicate adapter target/parent IDs")
        auth = manifest.authorization
        if not all((auth.grant_id, auth.principal_id, auth.task_id)):
            reject(FineTuneRejectReason.MANIFEST_INVALID, "authorization identity incomplete")
        if not all(self._sha(v) for v in (auth.p9b_assessment_sha256, auth.base_model_artifact_sha256, auth.selected_data_sha256)):
            reject(FineTuneRejectReason.MANIFEST_INVALID, "authorization digests invalid")
        if auth.issued_at_epoch > auth.expires_at_epoch:
            reject(FineTuneRejectReason.MANIFEST_INVALID, "authorization validity window invalid")
        hp = manifest.hyperparameters
        if min(hp.learning_rate_micros, hp.epochs_milli, hp.batch_size, hp.max_steps, hp.gradient_accumulation_steps) <= 0:
            reject(FineTuneRejectReason.MANIFEST_INVALID, "training hyperparameters must be positive")
        if not manifest.planned_output_artifact_id:
            reject(FineTuneRejectReason.MANIFEST_INVALID, "planned output artifact identity required")

    def _upstream_ok(self, assessment) -> bool:
        flags = (
            getattr(assessment, "upstream_p9a_bound", False),
            getattr(assessment, "record_integrity_verified", False),
            getattr(assessment, "label_integrity_verified", False),
            getattr(assessment, "contributor_trust_verified", False),
            getattr(assessment, "poisoning_indicators_clear", False),
        )
        return (
            getattr(assessment, "decision", None) == PoisoningDecision.ALLOW
            and not getattr(assessment, "risks", ())
            and all(flags)
            and getattr(assessment, "dataset_id", None) == self.policy.expected_dataset_id
            and getattr(assessment, "dataset_version", None) == self.policy.expected_dataset_version
            and not getattr(assessment, "caller_declared_training_data_safety_trusted", True)
            and not getattr(assessment, "production_data_quality_platform_integrated", True)
            and not getattr(assessment, "semantic_poisoning_detection_validated", True)
            and not getattr(assessment, "human_review_identity_cryptographically_authenticated", True)
            and getattr(assessment, "assessment_schema_version", None) == P9B_ASSESSMENT_SCHEMA_VERSION
            and getattr(assessment, "assessment_mode", None) == P9B_ASSESSMENT_MODE
        )

    def derive(self, manifest: FineTuningAdmissionManifest, p9b_assessment, now: int) -> tuple[FineTuneRisk, ...]:
        self._validate_manifest(manifest)
        p = self.policy
        risks: set[FineTuneRisk] = set()

        if not self._upstream_ok(p9b_assessment):
            risks.add(FineTuneRisk.UPSTREAM_P9B_INVALID)
        actual_p9b_sha = getattr(p9b_assessment, "assessment_evidence_sha256", "")
        if (
            manifest.p9b_assessment_sha256.casefold() != p.expected_p9b_assessment_sha256.casefold()
            or actual_p9b_sha.casefold() != p.expected_p9b_assessment_sha256.casefold()
        ):
            risks.add(FineTuneRisk.UPSTREAM_BINDING_MISMATCH)

        upstream_included = tuple(sorted(getattr(p9b_assessment, "included_record_ids", ())))
        if tuple(sorted(manifest.selected_record_ids)) != tuple(sorted(p.expected_selected_record_ids)):
            risks.add(FineTuneRisk.SELECTED_DATA_MISMATCH)
        if tuple(sorted(manifest.selected_record_ids)) != upstream_included:
            risks.add(FineTuneRisk.SELECTED_DATA_MISMATCH)
        expected_selected_sha = selected_training_data_digest(manifest.p9b_assessment_sha256, manifest.selected_record_ids)
        if manifest.selected_data_sha256.casefold() != expected_selected_sha.casefold() or manifest.selected_data_sha256.casefold() != p.expected_selected_data_sha256.casefold():
            risks.add(FineTuneRisk.SELECTED_DATA_MISMATCH)

        auth = manifest.authorization
        if auth.grant_id != p.expected_grant_id:
            risks.add(FineTuneRisk.AUTHORIZATION_INVALID)
        if manifest.principal_id != p.expected_principal_id or manifest.task_id != p.expected_task_id:
            risks.add(FineTuneRisk.PRINCIPAL_TASK_MISMATCH)
        if auth.principal_id != manifest.principal_id or auth.task_id != manifest.task_id:
            risks.add(FineTuneRisk.PRINCIPAL_TASK_MISMATCH)
        if auth.p9b_assessment_sha256.casefold() != manifest.p9b_assessment_sha256.casefold():
            risks.add(FineTuneRisk.AUTHORIZATION_INVALID)
        if auth.selected_data_sha256.casefold() != manifest.selected_data_sha256.casefold():
            risks.add(FineTuneRisk.AUTHORIZATION_INVALID)
        if auth.base_model_artifact_sha256.casefold() != manifest.base_model.artifact_sha256.casefold():
            risks.add(FineTuneRisk.AUTHORIZATION_INVALID)
        if now < auth.issued_at_epoch - p.max_future_skew_seconds or now > auth.expires_at_epoch:
            risks.add(FineTuneRisk.AUTHORIZATION_EXPIRED)
        if not auth.allowed_modes or any(mode not in p.allowed_modes for mode in auth.allowed_modes):
            risks.add(FineTuneRisk.AUTHORIZATION_INVALID)

        base = manifest.base_model
        if base.model_id != p.expected_base_model_id or base.revision != p.expected_base_model_revision:
            risks.add(FineTuneRisk.BASE_MODEL_IDENTITY_MISMATCH)
        if (
            base.artifact_sha256.casefold() != p.expected_base_model_artifact_sha256.casefold()
            or base.package_sha256.casefold() != p.expected_base_model_package_sha256.casefold()
            or base.tokenizer_sha256.casefold() != p.expected_tokenizer_sha256.casefold()
        ):
            risks.add(FineTuneRisk.BASE_MODEL_DIGEST_MISMATCH)
        if base.runtime_profile != p.expected_runtime_profile:
            risks.add(FineTuneRisk.BASE_MODEL_RUNTIME_MISMATCH)

        adapter_ids = tuple(a.adapter_id for a in manifest.adapters)
        if adapter_ids != p.expected_adapter_order:
            risks.add(FineTuneRisk.ADAPTER_COVERAGE_MISMATCH)
        seen: set[str] = set()
        for adapter in manifest.adapters:
            if adapter.mode not in p.allowed_modes or adapter.mode not in auth.allowed_modes:
                risks.add(FineTuneRisk.MODE_UNAUTHORIZED)
            if adapter.serialization_format not in p.allowed_serialization_formats:
                risks.add(FineTuneRisk.ADAPTER_FORMAT_UNSAFE)
            if adapter.rank <= 0 or adapter.rank > p.max_adapter_rank:
                risks.add(FineTuneRisk.ADAPTER_RANK_INVALID)
            if adapter.alpha_bps <= 0 or adapter.alpha_bps > p.max_adapter_alpha_bps:
                risks.add(FineTuneRisk.ADAPTER_ALPHA_INVALID)
            if not adapter.target_modules or any(module not in p.allowed_target_modules for module in adapter.target_modules):
                risks.add(FineTuneRisk.ADAPTER_TARGET_UNAUTHORIZED)
            expected_init = p.expected_adapter_init_sha256_by_id.get(adapter.adapter_id)
            if expected_init is None or adapter.init_sha256.casefold() != expected_init.casefold():
                risks.add(FineTuneRisk.ADAPTER_INIT_MISMATCH)
            if adapter.remote_code or adapter.custom_code or adapter.native_extensions:
                risks.add(FineTuneRisk.REMOTE_OR_CUSTOM_CODE)
            if len(adapter.parent_adapter_ids) > p.max_adapter_stack_depth:
                risks.add(FineTuneRisk.ADAPTER_STACK_INVALID)
            if any(parent not in seen for parent in adapter.parent_adapter_ids):
                risks.add(FineTuneRisk.ADAPTER_STACK_INVALID)
            seen.add(adapter.adapter_id)
        if len(manifest.adapters) > p.max_adapter_stack_depth:
            risks.add(FineTuneRisk.ADAPTER_STACK_INVALID)

        hp = manifest.hyperparameters
        if not (p.min_learning_rate_micros <= hp.learning_rate_micros <= p.max_learning_rate_micros):
            risks.add(FineTuneRisk.HYPERPARAMETER_OUT_OF_POLICY)
        if not (p.min_epochs_milli <= hp.epochs_milli <= p.max_epochs_milli):
            risks.add(FineTuneRisk.HYPERPARAMETER_OUT_OF_POLICY)
        if hp.batch_size > p.max_batch_size or hp.max_steps > p.max_steps:
            risks.add(FineTuneRisk.HYPERPARAMETER_OUT_OF_POLICY)
        if hp.seed not in p.allowed_seeds or hp.gradient_accumulation_steps > p.max_gradient_accumulation_steps:
            risks.add(FineTuneRisk.HYPERPARAMETER_OUT_OF_POLICY)

        if manifest.planned_output_artifact_id != p.expected_output_artifact_id:
            risks.add(FineTuneRisk.OUTPUT_IDENTITY_MISMATCH)

        return tuple(sorted(risks, key=lambda risk: risk.value))

    def evaluate(self, request: FineTuningAdmissionRequest, manifest: FineTuningAdmissionManifest, p9b_assessment) -> VerifiedFineTuningAdmissionAssessment:
        self._validate_manifest(manifest)
        actual_manifest_sha = fine_tuning_manifest_digest(manifest)
        if actual_manifest_sha.casefold() != self.policy.expected_manifest_sha256.casefold():
            reject(FineTuneRejectReason.MANIFEST_DIGEST_MISMATCH, "manifest differs from policy-pinned evidence")
        if request.manifest_id != manifest.manifest_id or request.manifest_sha256.casefold() != actual_manifest_sha.casefold():
            reject(FineTuneRejectReason.REQUEST_INVALID, "request manifest binding mismatch")
        if request.dataset_id != manifest.dataset_id or request.dataset_version != manifest.dataset_version:
            reject(FineTuneRejectReason.REQUEST_INVALID, "request dataset identity mismatch")
        if request.evaluated_at_epoch < manifest.created_at_epoch - self.policy.max_future_skew_seconds:
            reject(FineTuneRejectReason.REQUEST_INVALID, "evaluation predates manifest beyond allowed skew")
        if request.evaluated_at_epoch > manifest.created_at_epoch + self.policy.max_manifest_age_seconds:
            reject(FineTuneRejectReason.REQUEST_INVALID, "manifest is stale")

        risks = self.derive(manifest, p9b_assessment, request.evaluated_at_epoch)
        decision = FineTuneDecision.DENY if risks else FineTuneDecision.ALLOW
        adapter_ids = tuple(a.adapter_id for a in manifest.adapters)
        expected_safe = decision == FineTuneDecision.ALLOW
        risk_set = set(risks)
        authorization_ok = not bool(risk_set & {
            FineTuneRisk.AUTHORIZATION_INVALID,
            FineTuneRisk.AUTHORIZATION_EXPIRED,
            FineTuneRisk.PRINCIPAL_TASK_MISMATCH,
        })
        base_ok = not bool(risk_set & {
            FineTuneRisk.BASE_MODEL_IDENTITY_MISMATCH,
            FineTuneRisk.BASE_MODEL_DIGEST_MISMATCH,
            FineTuneRisk.BASE_MODEL_RUNTIME_MISMATCH,
        })
        adapter_ok = not bool(risk_set & {
            FineTuneRisk.MODE_UNAUTHORIZED,
            FineTuneRisk.ADAPTER_COVERAGE_MISMATCH,
            FineTuneRisk.ADAPTER_FORMAT_UNSAFE,
            FineTuneRisk.ADAPTER_RANK_INVALID,
            FineTuneRisk.ADAPTER_ALPHA_INVALID,
            FineTuneRisk.ADAPTER_TARGET_UNAUTHORIZED,
            FineTuneRisk.ADAPTER_INIT_MISMATCH,
            FineTuneRisk.ADAPTER_STACK_INVALID,
            FineTuneRisk.REMOTE_OR_CUSTOM_CODE,
        })
        hp_ok = FineTuneRisk.HYPERPARAMETER_OUT_OF_POLICY not in risk_set

        if tuple(sorted(request.declared_selected_record_ids)) != tuple(sorted(manifest.selected_record_ids)):
            reject(FineTuneRejectReason.DECLARED_SUMMARY_MISMATCH, "declared selected records differ from evidence")
        if request.declared_selected_data_sha256.casefold() != manifest.selected_data_sha256.casefold():
            reject(FineTuneRejectReason.DECLARED_SUMMARY_MISMATCH, "declared selected data digest differs from evidence")
        if request.declared_base_model_artifact_sha256.casefold() != manifest.base_model.artifact_sha256.casefold():
            reject(FineTuneRejectReason.DECLARED_SUMMARY_MISMATCH, "declared base model digest differs from evidence")
        if request.declared_adapter_ids != adapter_ids:
            reject(FineTuneRejectReason.DECLARED_SUMMARY_MISMATCH, "declared adapter IDs differ from evidence")
        if request.declared_authorized != authorization_ok:
            reject(FineTuneRejectReason.DECLARED_SUMMARY_MISMATCH, "declared authorization differs from evidence")
        if request.declared_base_model_bound != base_ok:
            reject(FineTuneRejectReason.DECLARED_SUMMARY_MISMATCH, "declared base binding differs from evidence")
        if request.declared_adapter_policy_safe != adapter_ok:
            reject(FineTuneRejectReason.DECLARED_SUMMARY_MISMATCH, "declared adapter safety differs from evidence")
        if request.declared_training_admission_safe != expected_safe:
            reject(FineTuneRejectReason.DECLARED_SUMMARY_MISMATCH, "declared admission safety differs from evidence")

        assessment_sha = digest_json({
            "manifest_id": manifest.manifest_id,
            "p9b_assessment_sha256": manifest.p9b_assessment_sha256,
            "decision": decision,
            "risks": risks,
            "principal_id": manifest.principal_id,
            "task_id": manifest.task_id,
            "selected_data_sha256": manifest.selected_data_sha256,
            "base_model_artifact_sha256": manifest.base_model.artifact_sha256,
            "adapter_ids": adapter_ids,
            "planned_output_artifact_id": manifest.planned_output_artifact_id,
            "schema": P9C_ASSESSMENT_SCHEMA_VERSION,
            "mode": P9C_ASSESSMENT_MODE,
        })
        return VerifiedFineTuningAdmissionAssessment(
            manifest_id=manifest.manifest_id,
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            decision=decision,
            risks=risks,
            principal_id=manifest.principal_id,
            task_id=manifest.task_id,
            selected_record_ids=tuple(sorted(manifest.selected_record_ids)),
            selected_data_sha256=manifest.selected_data_sha256,
            base_model_id=manifest.base_model.model_id,
            base_model_revision=manifest.base_model.revision,
            base_model_artifact_sha256=manifest.base_model.artifact_sha256,
            adapter_ids=adapter_ids,
            planned_output_artifact_id=manifest.planned_output_artifact_id,
            upstream_p9b_bound=not bool(risk_set & {FineTuneRisk.UPSTREAM_P9B_INVALID, FineTuneRisk.UPSTREAM_BINDING_MISMATCH}),
            authorization_verified=authorization_ok,
            base_model_binding_verified=base_ok,
            adapter_policy_verified=adapter_ok,
            hyperparameter_policy_verified=hp_ok,
            caller_declared_safety_trusted=False,
            production_training_runtime_integrated=False,
            production_identity_provider_integrated=False,
            proof_of_training_execution=False,
            assessment_schema_version=P9C_ASSESSMENT_SCHEMA_VERSION,
            assessment_mode=P9C_ASSESSMENT_MODE,
            assessment_evidence_sha256=assessment_sha,
        )
