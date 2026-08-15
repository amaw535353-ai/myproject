from __future__ import annotations

from dataclasses import replace
import hashlib

from aegis.training.evaluation_governance_types import (
    P9F_ASSESSMENT_MODE,
    P9F_ASSESSMENT_SCHEMA_VERSION,
    EvaluationDecision,
    VerifiedEvaluationBenchmarkAssessment,
)
from aegis.training.sensitive_data_types import *

NOW = 1_800_050_000
GOVERNANCE_ID = "p9g-sensitive-data-governance-001"
EVALUATION_ID = "p9f-evaluation-001"
CHECKPOINT_ID = "ckpt-0800"
P9F_ASSESSMENT_SHA = "53247ee9ca6297451a63910cbb9fdca19588d6fa76d1bd8b50b3ccabcab0ac03"

RECORD_IDS = (
    "train-public-01",
    "train-pii-01",
    "train-secret-01",
    "train-canary-01",
    "eval-public-01",
    "eval-pii-01",
    "output-public-01",
    "output-public-02",
)


def h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_p9f_assessment() -> VerifiedEvaluationBenchmarkAssessment:
    return VerifiedEvaluationBenchmarkAssessment(
        evaluation_id=EVALUATION_ID,
        checkpoint_lineage_id="p9e-checkpoint-lineage-001",
        checkpoint_id=CHECKPOINT_ID,
        decision=EvaluationDecision.ALLOW,
        risks=(),
        p9e_assessment_sha256=h("p9e-clean-assessment:p9f-bound"),
        benchmark_id="aegisdesk-heldout-security",
        benchmark_version="2026.08-p9f",
        benchmark_split="test",
        evaluated_record_ids=tuple(f"eval-{i:02d}" for i in range(1, 7)),
        score_basis_points=8333,
        upstream_p9e_bound=True,
        benchmark_provenance_verified=True,
        contamination_checks_clear=True,
        protocol_verified=True,
        result_evidence_bound=True,
        performance_claim_admissible=True,
        caller_declared_safety_trusted=False,
        production_benchmark_registry_integrated=False,
        semantic_near_duplicate_detection_validated=False,
        score_recomputed_from_model_outputs=False,
        hidden_benchmark_secrecy_proven=False,
        assessment_schema_version=P9F_ASSESSMENT_SCHEMA_VERSION,
        assessment_mode=P9F_ASSESSMENT_MODE,
        assessment_evidence_sha256=P9F_ASSESSMENT_SHA,
    )


def finding(fid: str, kind: SensitiveKind, token: str, start: int = 5, end: int = 15) -> SensitiveFindingEvidence:
    return SensitiveFindingEvidence(
        finding_id=fid,
        kind=kind,
        detector_rule_id=f"rule:{kind.value}:v1",
        detector_rule_sha256=h(f"rule:{kind.value}:v1"),
        token_fingerprint_sha256=h(f"token-fingerprint:{token}"),
        start_offset=start,
        end_offset=end,
    )


def _records() -> tuple[SensitiveRecordEvidence, ...]:
    email = finding("finding-email-01", SensitiveKind.PII_EMAIL, "email@example.invalid")
    secret = finding("finding-secret-01", SensitiveKind.API_SECRET, "sk-synthetic-secret")
    canary = finding("finding-canary-01", SensitiveKind.CANARY_TOKEN, "AEGIS-CANARY-001")
    phone = finding("finding-phone-01", SensitiveKind.PII_PHONE, "+1-555-0100")
    return (
        SensitiveRecordEvidence(
            record_id="train-public-01",
            surface=DataSurface.TRAINING_INPUT,
            content_sha256=h("train-public-01:content"),
            sanitized_content_sha256=h("train-public-01:content"),
            sensitivity=SensitivityClass.PUBLIC,
            findings=(),
            disposition=DataDisposition.ALLOW,
            included=True,
        ),
        SensitiveRecordEvidence(
            record_id="train-pii-01",
            surface=DataSurface.TRAINING_INPUT,
            content_sha256=h("train-pii-01:raw-email"),
            sanitized_content_sha256=h("train-pii-01:redacted-email"),
            sensitivity=SensitivityClass.PERSONAL,
            findings=(email,),
            disposition=DataDisposition.REDACT,
            included=True,
        ),
        SensitiveRecordEvidence(
            record_id="train-secret-01",
            surface=DataSurface.TRAINING_INPUT,
            content_sha256=h("train-secret-01:raw-secret"),
            sanitized_content_sha256=h("train-secret-01:quarantined"),
            sensitivity=SensitivityClass.SECRET,
            findings=(secret,),
            disposition=DataDisposition.QUARANTINE,
            included=False,
        ),
        SensitiveRecordEvidence(
            record_id="train-canary-01",
            surface=DataSurface.TRAINING_INPUT,
            content_sha256=h("train-canary-01:raw-canary"),
            sanitized_content_sha256=h("train-canary-01:quarantined"),
            sensitivity=SensitivityClass.CANARY,
            findings=(canary,),
            disposition=DataDisposition.QUARANTINE,
            included=False,
        ),
        SensitiveRecordEvidence(
            record_id="eval-public-01",
            surface=DataSurface.EVALUATION_INPUT,
            content_sha256=h("eval-public-01:content"),
            sanitized_content_sha256=h("eval-public-01:content"),
            sensitivity=SensitivityClass.PUBLIC,
            findings=(),
            disposition=DataDisposition.ALLOW,
            included=True,
        ),
        SensitiveRecordEvidence(
            record_id="eval-pii-01",
            surface=DataSurface.EVALUATION_INPUT,
            content_sha256=h("eval-pii-01:raw-phone"),
            sanitized_content_sha256=h("eval-pii-01:redacted-phone"),
            sensitivity=SensitivityClass.PERSONAL,
            findings=(phone,),
            disposition=DataDisposition.REDACT,
            included=True,
        ),
        SensitiveRecordEvidence(
            record_id="output-public-01",
            surface=DataSurface.MODEL_OUTPUT,
            content_sha256=h("output-public-01:content"),
            sanitized_content_sha256=h("output-public-01:content"),
            sensitivity=SensitivityClass.PUBLIC,
            findings=(),
            disposition=DataDisposition.ALLOW,
            included=False,
        ),
        SensitiveRecordEvidence(
            record_id="output-public-02",
            surface=DataSurface.MODEL_OUTPUT,
            content_sha256=h("output-public-02:content"),
            sanitized_content_sha256=h("output-public-02:content"),
            sensitivity=SensitivityClass.PUBLIC,
            findings=(),
            disposition=DataDisposition.ALLOW,
            included=False,
        ),
    )


def build_fixture() -> dict[str, object]:
    records = _records()
    included_training = tuple(
        r.record_id for r in records if r.surface == DataSurface.TRAINING_INPUT and r.included
    )
    output_ids = tuple(r.record_id for r in records if r.surface == DataSurface.MODEL_OUTPUT)
    output_batch_sha = sensitive_output_batch_digest(records)
    manifest = SensitiveDataGovernanceManifest(
        schema_version=P9G_SCHEMA_VERSION,
        governance_id=GOVERNANCE_ID,
        created_at_epoch=NOW,
        p9f_assessment_sha256=P9F_ASSESSMENT_SHA,
        evaluation_id=EVALUATION_ID,
        checkpoint_id=CHECKPOINT_ID,
        scanner_profile_sha256=h("p9g-scanner-profile:v1"),
        canary_registry_sha256=h("p9g-canary-registry:v1"),
        records=records,
        included_training_record_ids=included_training,
        output_record_ids=output_ids,
        output_batch_sha256=output_batch_sha,
        network_operations=0,
    )
    finding_digests = {
        finding.finding_id: sensitive_finding_digest(finding)
        for record in records for finding in record.findings
    }
    policy = SensitiveDataGovernancePolicy(
        policy_version=P9G_POLICY_VERSION,
        expected_governance_id=GOVERNANCE_ID,
        expected_manifest_sha256=sensitive_data_manifest_digest(manifest),
        expected_p9f_assessment_sha256=P9F_ASSESSMENT_SHA,
        expected_evaluation_id=EVALUATION_ID,
        expected_checkpoint_id=CHECKPOINT_ID,
        expected_scanner_profile_sha256=manifest.scanner_profile_sha256,
        expected_canary_registry_sha256=manifest.canary_registry_sha256,
        expected_record_order=tuple(r.record_id for r in records),
        expected_surface_by_record_id={r.record_id: r.surface for r in records},
        expected_content_sha256_by_record_id={r.record_id: r.content_sha256 for r in records},
        expected_sanitized_content_sha256_by_record_id={r.record_id: r.sanitized_content_sha256 for r in records},
        expected_sensitivity_by_record_id={r.record_id: r.sensitivity for r in records},
        expected_disposition_by_record_id={r.record_id: r.disposition for r in records},
        expected_included_by_record_id={r.record_id: r.included for r in records},
        expected_finding_ids_by_record_id={r.record_id: tuple(f.finding_id for f in r.findings) for r in records},
        expected_finding_digest_by_id=finding_digests,
        expected_included_training_record_ids=included_training,
        expected_output_record_ids=output_ids,
        expected_output_batch_sha256=output_batch_sha,
        max_manifest_age_seconds=300,
        max_future_skew_seconds=5,
    )
    request = SensitiveDataGovernanceRequest(
        governance_id=GOVERNANCE_ID,
        manifest_sha256=sensitive_data_manifest_digest(manifest),
        evaluated_at_epoch=NOW,
        declared_evaluation_id=EVALUATION_ID,
        declared_checkpoint_id=CHECKPOINT_ID,
        declared_record_ids=tuple(r.record_id for r in records),
        declared_included_training_record_ids=included_training,
        declared_output_record_ids=output_ids,
        declared_upstream_bound=True,
        declared_input_governance_valid=True,
        declared_output_governance_valid=True,
        declared_canary_free=True,
        declared_sensitive_data_safe=True,
    )
    return {"manifest": manifest, "policy": policy, "request": request, "p9f": build_p9f_assessment()}


def rebind(
    fixture: dict[str, object],
    *,
    manifest=None,
    p9f=None,
    preserve_declarations: bool = True,
    **request_updates,
) -> dict[str, object]:
    manifest = manifest or fixture["manifest"]
    p9f = p9f or fixture["p9f"]
    policy = fixture["policy"]
    request = fixture["request"]
    assert isinstance(manifest, SensitiveDataGovernanceManifest)
    assert isinstance(policy, SensitiveDataGovernancePolicy)
    assert isinstance(request, SensitiveDataGovernanceRequest)
    digest = sensitive_data_manifest_digest(manifest)
    out = dict(fixture)
    out["manifest"] = manifest
    out["p9f"] = p9f
    out["policy"] = replace(policy, expected_manifest_sha256=digest)
    identity_updates = {}
    if not preserve_declarations:
        identity_updates = dict(
            declared_evaluation_id=manifest.evaluation_id,
            declared_checkpoint_id=manifest.checkpoint_id,
            declared_record_ids=tuple(r.record_id for r in manifest.records),
            declared_included_training_record_ids=manifest.included_training_record_ids,
            declared_output_record_ids=manifest.output_record_ids,
        )
    identity_updates.update(request_updates)
    out["request"] = replace(request, manifest_sha256=digest, **identity_updates)
    return out
