from __future__ import annotations

import re

from .evaluation_governance_types import (
    P9F_ASSESSMENT_MODE,
    P9F_ASSESSMENT_SCHEMA_VERSION,
    EvaluationDecision,
)
from .sensitive_data_types import *

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class SensitiveDataGovernanceAnalyzer:
    def __init__(self, policy: SensitiveDataGovernancePolicy):
        self.policy = policy
        self._validate_policy()

    @staticmethod
    def _sha(value: str) -> bool:
        return bool(_SHA256_RE.fullmatch(str(value)))

    def _validate_policy(self) -> None:
        p = self.policy
        if p.policy_version != P9G_POLICY_VERSION:
            reject(SensitiveDataRejectReason.POLICY_INVALID, "unexpected policy version")
        if not all((p.expected_governance_id, p.expected_evaluation_id, p.expected_checkpoint_id)):
            reject(SensitiveDataRejectReason.POLICY_INVALID, "identity pins are required")
        digests = (
            p.expected_manifest_sha256,
            p.expected_p9f_assessment_sha256,
            p.expected_scanner_profile_sha256,
            p.expected_canary_registry_sha256,
            p.expected_output_batch_sha256,
            *p.expected_content_sha256_by_record_id.values(),
            *p.expected_sanitized_content_sha256_by_record_id.values(),
            *p.expected_finding_digest_by_id.values(),
        )
        if not all(self._sha(v) for v in digests):
            reject(SensitiveDataRejectReason.POLICY_INVALID, "digest pins must be sha256")
        ids = p.expected_record_order
        if not ids or len(ids) != len(set(ids)):
            reject(SensitiveDataRejectReason.POLICY_INVALID, "record order must be non-empty and unique")
        maps = (
            p.expected_surface_by_record_id,
            p.expected_content_sha256_by_record_id,
            p.expected_sanitized_content_sha256_by_record_id,
            p.expected_sensitivity_by_record_id,
            p.expected_disposition_by_record_id,
            p.expected_included_by_record_id,
            p.expected_finding_ids_by_record_id,
        )
        if any(set(m) != set(ids) for m in maps):
            reject(SensitiveDataRejectReason.POLICY_INVALID, "record pin maps must exactly cover record order")
        finding_ids = tuple(fid for rid in ids for fid in p.expected_finding_ids_by_record_id[rid])
        if len(finding_ids) != len(set(finding_ids)) or set(finding_ids) != set(p.expected_finding_digest_by_id):
            reject(SensitiveDataRejectReason.POLICY_INVALID, "finding pin maps must exactly cover unique finding IDs")
        if len(p.expected_included_training_record_ids) != len(set(p.expected_included_training_record_ids)):
            reject(SensitiveDataRejectReason.POLICY_INVALID, "included training record IDs must be unique")
        if len(p.expected_output_record_ids) != len(set(p.expected_output_record_ids)):
            reject(SensitiveDataRejectReason.POLICY_INVALID, "output record IDs must be unique")
        if p.max_manifest_age_seconds < 0 or p.max_future_skew_seconds < 0:
            reject(SensitiveDataRejectReason.POLICY_INVALID, "freshness bounds invalid")

    def _validate_manifest(self, manifest: SensitiveDataGovernanceManifest) -> None:
        if manifest.schema_version != P9G_SCHEMA_VERSION:
            reject(SensitiveDataRejectReason.MANIFEST_INVALID, "unexpected manifest schema")
        if not all((manifest.governance_id, manifest.evaluation_id, manifest.checkpoint_id)):
            reject(SensitiveDataRejectReason.MANIFEST_INVALID, "governance identity incomplete")
        for digest in (
            manifest.p9f_assessment_sha256,
            manifest.scanner_profile_sha256,
            manifest.canary_registry_sha256,
            manifest.output_batch_sha256,
        ):
            if not self._sha(digest):
                reject(SensitiveDataRejectReason.MANIFEST_INVALID, "manifest digest field invalid")
        ids = tuple(record.record_id for record in manifest.records)
        if not ids or len(ids) != len(set(ids)):
            reject(SensitiveDataRejectReason.MANIFEST_INVALID, "record IDs must be non-empty and unique")
        all_finding_ids: list[str] = []
        for record in manifest.records:
            if not record.record_id:
                reject(SensitiveDataRejectReason.MANIFEST_INVALID, "record ID required")
            if not self._sha(record.content_sha256) or not self._sha(record.sanitized_content_sha256):
                reject(SensitiveDataRejectReason.MANIFEST_INVALID, "record digest invalid")
            finding_ids = tuple(f.finding_id for f in record.findings)
            if len(finding_ids) != len(set(finding_ids)):
                reject(SensitiveDataRejectReason.MANIFEST_INVALID, "duplicate finding ID within record")
            all_finding_ids.extend(finding_ids)
            for finding in record.findings:
                if not all((finding.finding_id, finding.detector_rule_id)):
                    reject(SensitiveDataRejectReason.MANIFEST_INVALID, "finding identity incomplete")
                if not self._sha(finding.detector_rule_sha256) or not self._sha(finding.token_fingerprint_sha256):
                    reject(SensitiveDataRejectReason.MANIFEST_INVALID, "finding digest invalid")
                if finding.start_offset < 0 or finding.end_offset <= finding.start_offset:
                    reject(SensitiveDataRejectReason.MANIFEST_INVALID, "finding offsets invalid")
        if len(all_finding_ids) != len(set(all_finding_ids)):
            reject(SensitiveDataRejectReason.MANIFEST_INVALID, "finding IDs must be globally unique")
        if len(manifest.included_training_record_ids) != len(set(manifest.included_training_record_ids)):
            reject(SensitiveDataRejectReason.MANIFEST_INVALID, "duplicate included training record")
        if len(manifest.output_record_ids) != len(set(manifest.output_record_ids)):
            reject(SensitiveDataRejectReason.MANIFEST_INVALID, "duplicate output record")
        if manifest.network_operations < 0:
            reject(SensitiveDataRejectReason.MANIFEST_INVALID, "network operation count invalid")

    def _upstream_ok(self, assessment) -> bool:
        flags = (
            getattr(assessment, "upstream_p9e_bound", False),
            getattr(assessment, "benchmark_provenance_verified", False),
            getattr(assessment, "contamination_checks_clear", False),
            getattr(assessment, "protocol_verified", False),
            getattr(assessment, "result_evidence_bound", False),
            getattr(assessment, "performance_claim_admissible", False),
        )
        return (
            getattr(assessment, "decision", None) == EvaluationDecision.ALLOW
            and not getattr(assessment, "risks", ())
            and all(flags)
            and not getattr(assessment, "caller_declared_safety_trusted", True)
            and not getattr(assessment, "production_benchmark_registry_integrated", True)
            and not getattr(assessment, "semantic_near_duplicate_detection_validated", True)
            and not getattr(assessment, "score_recomputed_from_model_outputs", True)
            and not getattr(assessment, "hidden_benchmark_secrecy_proven", True)
            and getattr(assessment, "assessment_schema_version", None) == P9F_ASSESSMENT_SCHEMA_VERSION
            and getattr(assessment, "assessment_mode", None) == P9F_ASSESSMENT_MODE
        )

    @staticmethod
    def _derived_sensitivity(record: SensitiveRecordEvidence) -> SensitivityClass:
        kinds = {finding.kind for finding in record.findings}
        if SensitiveKind.CANARY_TOKEN in kinds:
            return SensitivityClass.CANARY
        if SensitiveKind.API_SECRET in kinds:
            return SensitivityClass.SECRET
        if kinds & {SensitiveKind.PII_EMAIL, SensitiveKind.PII_PHONE}:
            return SensitivityClass.PERSONAL
        return SensitivityClass.PUBLIC

    def derive(self, manifest: SensitiveDataGovernanceManifest, p9f_assessment) -> tuple[SensitiveDataRisk, ...]:
        self._validate_manifest(manifest)
        p = self.policy
        risks: set[SensitiveDataRisk] = set()

        if not self._upstream_ok(p9f_assessment):
            risks.add(SensitiveDataRisk.UPSTREAM_P9F_INVALID)
        actual_upstream_sha = getattr(p9f_assessment, "assessment_evidence_sha256", "")
        if (
            manifest.p9f_assessment_sha256.casefold() != p.expected_p9f_assessment_sha256.casefold()
            or actual_upstream_sha.casefold() != p.expected_p9f_assessment_sha256.casefold()
        ):
            risks.add(SensitiveDataRisk.UPSTREAM_BINDING_MISMATCH)
        if (
            manifest.evaluation_id != p.expected_evaluation_id
            or manifest.checkpoint_id != p.expected_checkpoint_id
            or getattr(p9f_assessment, "evaluation_id", None) != p.expected_evaluation_id
            or getattr(p9f_assessment, "checkpoint_id", None) != p.expected_checkpoint_id
        ):
            risks.add(SensitiveDataRisk.EVALUATION_IDENTITY_MISMATCH)
        if manifest.scanner_profile_sha256.casefold() != p.expected_scanner_profile_sha256.casefold():
            risks.add(SensitiveDataRisk.SCANNER_PROFILE_MISMATCH)
        if manifest.canary_registry_sha256.casefold() != p.expected_canary_registry_sha256.casefold():
            risks.add(SensitiveDataRisk.CANARY_REGISTRY_MISMATCH)

        ids = tuple(record.record_id for record in manifest.records)
        if ids != p.expected_record_order:
            risks.add(SensitiveDataRisk.RECORD_COVERAGE_MISMATCH)

        for record in manifest.records:
            expected_surface = p.expected_surface_by_record_id.get(record.record_id)
            if expected_surface is None or record.surface != expected_surface:
                risks.add(SensitiveDataRisk.RECORD_SURFACE_MISMATCH)
            expected_content = p.expected_content_sha256_by_record_id.get(record.record_id)
            expected_sanitized = p.expected_sanitized_content_sha256_by_record_id.get(record.record_id)
            if (
                expected_content is None
                or expected_sanitized is None
                or record.content_sha256.casefold() != expected_content.casefold()
                or record.sanitized_content_sha256.casefold() != expected_sanitized.casefold()
            ):
                risks.add(SensitiveDataRisk.RECORD_DIGEST_MISMATCH)

            derived_sensitivity = self._derived_sensitivity(record)
            expected_sensitivity = p.expected_sensitivity_by_record_id.get(record.record_id)
            if expected_sensitivity is None or record.sensitivity != expected_sensitivity or record.sensitivity != derived_sensitivity:
                risks.add(SensitiveDataRisk.CLASSIFICATION_MISMATCH)

            finding_ids = tuple(f.finding_id for f in record.findings)
            expected_finding_ids = p.expected_finding_ids_by_record_id.get(record.record_id)
            if expected_finding_ids is None or finding_ids != expected_finding_ids:
                risks.add(SensitiveDataRisk.FINDING_COVERAGE_MISMATCH)
            for finding in record.findings:
                expected_digest = p.expected_finding_digest_by_id.get(finding.finding_id)
                if expected_digest is None or sensitive_finding_digest(finding).casefold() != expected_digest.casefold():
                    risks.add(SensitiveDataRisk.FINDING_EVIDENCE_MISMATCH)

            expected_disposition = p.expected_disposition_by_record_id.get(record.record_id)
            if expected_disposition is None or record.disposition != expected_disposition:
                if record.disposition == DataDisposition.REDACT or expected_disposition == DataDisposition.REDACT:
                    risks.add(SensitiveDataRisk.REDACTION_POLICY_MISMATCH)
                else:
                    risks.add(SensitiveDataRisk.QUARANTINE_POLICY_MISMATCH)
            expected_included = p.expected_included_by_record_id.get(record.record_id)
            if expected_included is None or record.included != expected_included:
                risks.add(SensitiveDataRisk.TRAINING_INCLUSION_MISMATCH)

            kinds = {finding.kind for finding in record.findings}
            pii = bool(kinds & {SensitiveKind.PII_EMAIL, SensitiveKind.PII_PHONE})
            high_secret = bool(kinds & {SensitiveKind.API_SECRET, SensitiveKind.CANARY_TOKEN})

            if record.surface in (DataSurface.TRAINING_INPUT, DataSurface.EVALUATION_INPUT):
                if pii:
                    if (
                        record.disposition != DataDisposition.REDACT
                        or record.sanitized_content_sha256.casefold() == record.content_sha256.casefold()
                        or not record.included
                    ):
                        risks.add(SensitiveDataRisk.REDACTION_POLICY_MISMATCH)
                elif high_secret:
                    if record.disposition != DataDisposition.QUARANTINE or record.included:
                        risks.add(SensitiveDataRisk.QUARANTINE_POLICY_MISMATCH)
                else:
                    if (
                        record.disposition != DataDisposition.ALLOW
                        or record.sanitized_content_sha256.casefold() != record.content_sha256.casefold()
                    ):
                        risks.add(SensitiveDataRisk.REDACTION_POLICY_MISMATCH)
            elif record.surface == DataSurface.MODEL_OUTPUT:
                if record.findings:
                    risks.add(SensitiveDataRisk.OUTPUT_SENSITIVE_REPRODUCTION)

        derived_training_ids = tuple(
            record.record_id
            for record in manifest.records
            if record.surface == DataSurface.TRAINING_INPUT and record.included
        )
        if (
            manifest.included_training_record_ids != derived_training_ids
            or manifest.included_training_record_ids != p.expected_included_training_record_ids
        ):
            risks.add(SensitiveDataRisk.TRAINING_INCLUSION_MISMATCH)

        derived_output_ids = tuple(
            record.record_id for record in manifest.records if record.surface == DataSurface.MODEL_OUTPUT
        )
        if manifest.output_record_ids != derived_output_ids or manifest.output_record_ids != p.expected_output_record_ids:
            risks.add(SensitiveDataRisk.OUTPUT_BATCH_MISMATCH)
        batch_sha = sensitive_output_batch_digest(manifest.records)
        if (
            manifest.output_batch_sha256.casefold() != batch_sha.casefold()
            or manifest.output_batch_sha256.casefold() != p.expected_output_batch_sha256.casefold()
        ):
            risks.add(SensitiveDataRisk.OUTPUT_BATCH_MISMATCH)
        if manifest.network_operations != 0:
            risks.add(SensitiveDataRisk.NETWORK_OPERATION_UNEXPECTED)

        return tuple(sorted(risks, key=lambda risk: risk.value))

    def evaluate(
        self,
        request: SensitiveDataGovernanceRequest,
        manifest: SensitiveDataGovernanceManifest,
        p9f_assessment,
    ) -> VerifiedSensitiveDataGovernanceAssessment:
        self._validate_manifest(manifest)
        actual_manifest_sha = sensitive_data_manifest_digest(manifest)
        if actual_manifest_sha.casefold() != self.policy.expected_manifest_sha256.casefold():
            reject(SensitiveDataRejectReason.MANIFEST_DIGEST_MISMATCH, "manifest differs from policy-pinned evidence")
        if request.governance_id != manifest.governance_id or request.manifest_sha256.casefold() != actual_manifest_sha.casefold():
            reject(SensitiveDataRejectReason.REQUEST_INVALID, "request manifest binding mismatch")
        if request.evaluated_at_epoch < manifest.created_at_epoch - self.policy.max_future_skew_seconds:
            reject(SensitiveDataRejectReason.REQUEST_INVALID, "evaluation predates manifest beyond allowed skew")
        if request.evaluated_at_epoch > manifest.created_at_epoch + self.policy.max_manifest_age_seconds:
            reject(SensitiveDataRejectReason.REQUEST_INVALID, "manifest evidence is stale")
        if (
            request.declared_evaluation_id != manifest.evaluation_id
            or request.declared_checkpoint_id != manifest.checkpoint_id
            or request.declared_record_ids != tuple(record.record_id for record in manifest.records)
            or request.declared_included_training_record_ids != manifest.included_training_record_ids
            or request.declared_output_record_ids != manifest.output_record_ids
        ):
            reject(SensitiveDataRejectReason.DECLARED_SUMMARY_MISMATCH, "caller-declared identities disagree with manifest")

        risks = self.derive(manifest, p9f_assessment)
        decision = SensitiveDataDecision.ALLOW if not risks else SensitiveDataDecision.DENY
        upstream_bound = not any(r in risks for r in (
            SensitiveDataRisk.UPSTREAM_P9F_INVALID,
            SensitiveDataRisk.UPSTREAM_BINDING_MISMATCH,
            SensitiveDataRisk.EVALUATION_IDENTITY_MISMATCH,
        ))
        input_verified = not any(r in risks for r in (
            SensitiveDataRisk.RECORD_COVERAGE_MISMATCH,
            SensitiveDataRisk.RECORD_SURFACE_MISMATCH,
            SensitiveDataRisk.RECORD_DIGEST_MISMATCH,
            SensitiveDataRisk.CLASSIFICATION_MISMATCH,
            SensitiveDataRisk.FINDING_COVERAGE_MISMATCH,
            SensitiveDataRisk.FINDING_EVIDENCE_MISMATCH,
            SensitiveDataRisk.REDACTION_POLICY_MISMATCH,
            SensitiveDataRisk.QUARANTINE_POLICY_MISMATCH,
            SensitiveDataRisk.TRAINING_INCLUSION_MISMATCH,
            SensitiveDataRisk.SCANNER_PROFILE_MISMATCH,
            SensitiveDataRisk.CANARY_REGISTRY_MISMATCH,
        ))
        output_verified = not any(r in risks for r in (
            SensitiveDataRisk.OUTPUT_SENSITIVE_REPRODUCTION,
            SensitiveDataRisk.OUTPUT_BATCH_MISMATCH,
            SensitiveDataRisk.RECORD_DIGEST_MISMATCH,
            SensitiveDataRisk.FINDING_COVERAGE_MISMATCH,
            SensitiveDataRisk.FINDING_EVIDENCE_MISMATCH,
        ))
        canary_clear = not any(
            record.surface == DataSurface.MODEL_OUTPUT
            and any(finding.kind == SensitiveKind.CANARY_TOKEN for finding in record.findings)
            for record in manifest.records
        )
        policy_verified = decision == SensitiveDataDecision.ALLOW

        declared = (
            request.declared_upstream_bound,
            request.declared_input_governance_valid,
            request.declared_output_governance_valid,
            request.declared_canary_free,
            request.declared_sensitive_data_safe,
        )
        derived = (upstream_bound, input_verified, output_verified, canary_clear, policy_verified)
        if declared != derived:
            reject(SensitiveDataRejectReason.DECLARED_SUMMARY_MISMATCH, "caller-declared safety summary disagrees with derived evidence")

        evidence = digest_json({
            "governance_id": manifest.governance_id,
            "evaluation_id": manifest.evaluation_id,
            "checkpoint_id": manifest.checkpoint_id,
            "decision": decision,
            "risks": risks,
            "manifest_sha256": actual_manifest_sha,
            "p9f_assessment_sha256": manifest.p9f_assessment_sha256,
            "record_ids": tuple(record.record_id for record in manifest.records),
            "included_training_record_ids": manifest.included_training_record_ids,
            "output_record_ids": manifest.output_record_ids,
            "upstream_p9f_bound": upstream_bound,
            "input_governance_verified": input_verified,
            "output_governance_verified": output_verified,
            "canary_reproduction_clear": canary_clear,
            "sensitive_data_policy_verified": policy_verified,
            "assessment_schema_version": P9G_ASSESSMENT_SCHEMA_VERSION,
            "assessment_mode": P9G_ASSESSMENT_MODE,
        })
        return VerifiedSensitiveDataGovernanceAssessment(
            governance_id=manifest.governance_id,
            evaluation_id=manifest.evaluation_id,
            checkpoint_id=manifest.checkpoint_id,
            decision=decision,
            risks=risks,
            p9f_assessment_sha256=manifest.p9f_assessment_sha256,
            record_ids=tuple(record.record_id for record in manifest.records),
            included_training_record_ids=manifest.included_training_record_ids,
            output_record_ids=manifest.output_record_ids,
            upstream_p9f_bound=upstream_bound,
            input_governance_verified=input_verified,
            output_governance_verified=output_verified,
            canary_reproduction_clear=canary_clear,
            sensitive_data_policy_verified=policy_verified,
            caller_declared_safety_trusted=False,
            production_dlp_integrated=False,
            comprehensive_pii_detection_validated=False,
            legal_compliance_verified=False,
            differential_privacy_verified=False,
            memorization_absence_proven=False,
            assessment_schema_version=P9G_ASSESSMENT_SCHEMA_VERSION,
            assessment_mode=P9G_ASSESSMENT_MODE,
            assessment_evidence_sha256=evidence,
        )
