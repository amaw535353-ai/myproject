from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import hashlib
import json
from typing import Any, Mapping

P9I_EXIT_POLICY_VERSION = "phase9-integrated-training-exit-policy-v1"
P9I_EXIT_SCHEMA_VERSION = "aegis-phase9-integrated-exit-manifest-v1"
P9I_ASSESSMENT_SCHEMA_VERSION = "aegis-phase9-integrated-exit-assessment-v1"
P9I_ASSESSMENT_MODE = (
    "deterministic-evidence-lineage-compromise-and-verification-aware-phase9-exit-v1"
)
ZERO_SHA256 = "0" * 64

MILESTONE_ORDER = (
    "P9-A",
    "P9-B",
    "P9-C",
    "P9-D",
    "P9-E",
    "P9-F",
    "P9-G",
    "P9-H",
)

MILESTONE_DOMAINS = {
    "P9-A": "dataset-provenance-holdout-isolation",
    "P9-B": "poisoning-label-integrity-contributor-trust",
    "P9-C": "fine-tuning-admission-base-binding",
    "P9-D": "training-execution-provenance-least-privilege",
    "P9-E": "checkpoint-resume-integrity-rollback",
    "P9-F": "evaluation-leakage-contamination-governance",
    "P9-G": "sensitive-data-canary-governance",
    "P9-H": "model-registry-promotion-phase5-handoff",
}

SCENARIO_ORDER = (
    "dataset-poisoning-to-promotion",
    "unauthorized-adapter-base-swap",
    "execution-secret-capability-escalation",
    "checkpoint-rollback-substitution",
    "benchmark-contamination-score-inflation",
    "sensitive-data-canary-reproduction",
    "registry-artifact-reference-substitution",
    "upstream-assessment-replay-at-promotion",
)

REQUIRED_SYNTHETIC_ASSUMPTIONS = (
    "deterministic-synthetic-fixtures",
    "single-process-local-evaluator",
    "sha256-integrity-not-authentication",
    "no-production-data-platform",
    "no-production-training-runtime",
    "no-production-scheduler-iam-kms",
    "no-production-checkpoint-store",
    "no-hidden-benchmark-service",
    "no-production-dlp-privacy-assurance",
    "no-production-model-registry-write",
    "no-cryptographic-attestation",
)

PRODUCTION_CLAIM_FIELDS = (
    "production_data_platform_integrated",
    "production_training_runtime_validated",
    "production_scheduler_iam_kms_integrated",
    "production_checkpoint_store_integrated",
    "production_hidden_benchmark_service_integrated",
    "production_privacy_compliance_verified",
    "production_model_registry_integrated",
    "cryptographic_attestation_verified",
)


class Phase9VerificationStatus(str, Enum):
    LOCAL_FOCUSED_PASS = "LOCAL_FOCUSED_PASS"
    LOCAL_FULL_PASS = "LOCAL_FULL_PASS"
    REMOTE_CI_PASS = "REMOTE_CI_PASS"
    REMOTE_CI_BLOCKED = "REMOTE_CI_BLOCKED"
    REMOTE_CI_FAIL = "REMOTE_CI_FAIL"
    NOT_RUN = "NOT_RUN"


class Phase9ExitDecision(str, Enum):
    PASS = "PASS"
    PASS_WITH_EXTERNAL_CI_LIMITATION = "PASS_WITH_EXTERNAL_CI_LIMITATION"
    FAIL = "FAIL"


class Phase9ExitRisk(str, Enum):
    MILESTONE_COVERAGE_INVALID = "milestone_coverage_invalid"
    MILESTONE_ORDER_INVALID = "milestone_order_invalid"
    DOMAIN_BINDING_MISMATCH = "domain_binding_mismatch"
    LINEAGE_MISMATCH = "lineage_mismatch"
    EVIDENCE_CHAIN_BROKEN = "evidence_chain_broken"
    EVIDENCE_DIGEST_MISMATCH = "evidence_digest_mismatch"
    UPSTREAM_SAFETY_FAILED = "upstream_safety_failed"
    CALLER_DECLARED_SAFETY_TRUSTED = "caller_declared_safety_trusted"
    NETWORK_SIDE_EFFECT_REPORTED = "network_side_effect_reported"
    COMPROMISE_SCENARIO_COVERAGE_INVALID = "compromise_scenario_coverage_invalid"
    COMPROMISE_SCENARIO_ORDER_INVALID = "compromise_scenario_order_invalid"
    COMPROMISE_SCENARIO_BINDING_MISMATCH = "compromise_scenario_binding_mismatch"
    COMPROMISE_NOT_DETECTED = "compromise_not_detected"
    PROMOTION_FAIL_OPEN = "promotion_fail_open"
    LOCAL_VERIFICATION_INCOMPLETE = "local_verification_incomplete"
    REMOTE_CI_INVALID = "remote_ci_invalid"
    REMOTE_CI_EXECUTION_FAILED = "remote_ci_execution_failed"
    SYNTHETIC_ASSUMPTION_MISSING = "synthetic_assumption_missing"
    UNSUPPORTED_PRODUCTION_CLAIM = "unsupported_production_claim"


class Phase9ExitRejectReason(str, Enum):
    POLICY_INVALID = "policy_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    REQUEST_INVALID = "request_invalid"
    DECLARED_DECISION_MISMATCH = "declared_decision_mismatch"
    DECLARED_EVIDENCE_MISMATCH = "declared_evidence_mismatch"
    DECLARED_SCENARIO_MISMATCH = "declared_scenario_mismatch"
    DECLARED_VERIFICATION_MISMATCH = "declared_verification_mismatch"


class Phase9ExitRejected(ValueError):
    def __init__(self, reason: Phase9ExitRejectReason, message: str):
        self.reason = reason
        self.message = message
        super().__init__(f"{reason.value}: {message}")


@dataclass(frozen=True)
class Phase9MilestoneEvidence:
    milestone_id: str
    control_domain: str
    step_index: int
    training_lineage_id: str
    manifest_sha256: str
    assessment_sha256: str
    predecessor_assessment_sha256: str
    input_state_sha256: str
    output_state_sha256: str
    assessment_schema_version: str
    assessment_mode: str
    safe: bool
    caller_declared_safety_trusted: bool
    network_operations: int


@dataclass(frozen=True)
class CompromiseExerciseEvidence:
    scenario_id: str
    attack_class: str
    entry_milestone_id: str
    propagation_path: tuple[str, ...]
    attack_input_sha256: str
    detection_milestone_id: str
    detected: bool
    promotion_blocked: bool
    recovery_state_sha256: str
    network_operations: int = 0


@dataclass(frozen=True)
class Phase9VerificationRecord:
    verification_id: str
    scope: str
    status: Phase9VerificationStatus
    evidence_sha256: str
    runner_started: bool
    steps_executed: int
    reason_code: str = ""


@dataclass(frozen=True)
class Phase9ClaimProfile:
    production_data_platform_integrated: bool = False
    production_training_runtime_validated: bool = False
    production_scheduler_iam_kms_integrated: bool = False
    production_checkpoint_store_integrated: bool = False
    production_hidden_benchmark_service_integrated: bool = False
    production_privacy_compliance_verified: bool = False
    production_model_registry_integrated: bool = False
    cryptographic_attestation_verified: bool = False


@dataclass(frozen=True)
class Phase9ExitManifest:
    manifest_id: str
    schema_version: str
    created_at_epoch: int
    training_lineage_id: str
    milestone_evidence: tuple[Phase9MilestoneEvidence, ...]
    compromise_exercises: tuple[CompromiseExerciseEvidence, ...]
    verification_records: tuple[Phase9VerificationRecord, ...]
    synthetic_assumptions: tuple[str, ...]
    claim_profile: Phase9ClaimProfile


@dataclass(frozen=True)
class Phase9ExitPolicy:
    policy_version: str
    expected_manifest_id: str
    expected_manifest_sha256: str
    expected_training_lineage_id: str
    expected_assessment_sha256_by_milestone: Mapping[str, str]
    expected_manifest_sha256_by_milestone: Mapping[str, str]
    expected_output_state_sha256_by_milestone: Mapping[str, str]
    expected_assessment_schema_by_milestone: Mapping[str, str]
    expected_assessment_mode_by_milestone: Mapping[str, str]
    expected_scenario_order: tuple[str, ...]
    expected_attack_class_by_scenario: Mapping[str, str]
    expected_entry_milestone_by_scenario: Mapping[str, str]
    expected_propagation_path_by_scenario: Mapping[str, tuple[str, ...]]
    expected_attack_input_sha256_by_scenario: Mapping[str, str]
    expected_detection_milestone_by_scenario: Mapping[str, str]
    expected_recovery_state_sha256_by_scenario: Mapping[str, str]
    required_local_verification_scopes: tuple[str, ...]
    allowed_external_ci_block_reasons: tuple[str, ...]
    max_manifest_age_seconds: int = 3600
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class Phase9ExitRequest:
    manifest_id: str
    manifest_sha256: str
    policy_version: str
    evaluated_at_epoch: int
    declared_exit_decision: Phase9ExitDecision
    declared_assessment_sha256_by_milestone: Mapping[str, str]
    declared_scenario_detection_by_id: Mapping[str, bool]
    declared_scenario_promotion_blocked_by_id: Mapping[str, bool]
    declared_verification_status_by_id: Mapping[str, str]


@dataclass(frozen=True)
class Phase9ExitAssessment:
    manifest_id: str
    training_lineage_id: str
    milestone_count: int
    compromise_scenario_count: int
    local_verification_count: int
    remote_ci_status: str
    risks: tuple[Phase9ExitRisk, ...]
    decision: Phase9ExitDecision
    all_milestones_evidence_bound: bool
    compromise_exercises_passed: bool
    promotion_fail_closed_verified: bool
    upstream_safety_derived: bool
    caller_declared_safety_trusted: bool
    local_security_validation_passed: bool
    remote_ci_execution_verified: bool
    remote_ci_external_limitation: bool
    synthetic_assumptions_explicit: bool
    unsupported_production_claims_present: bool
    production_data_platform_integrated: bool
    production_training_runtime_validated: bool
    production_scheduler_iam_kms_integrated: bool
    production_checkpoint_store_integrated: bool
    production_hidden_benchmark_service_integrated: bool
    production_privacy_compliance_verified: bool
    production_model_registry_integrated: bool
    cryptographic_attestation_verified: bool
    network_operations: int
    assessment_schema_version: str
    assessment_mode: str
    assessment_evidence_sha256: str


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {
            str(key): _jsonable(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    if isinstance(value, set):
        return sorted(_jsonable(item) for item in value)
    return value


def _digest_json(value: Any) -> str:
    payload = json.dumps(
        _jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def canonical_phase9_exit_manifest_bytes(manifest: Phase9ExitManifest) -> bytes:
    return json.dumps(
        _jsonable(manifest), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def phase9_exit_manifest_digest(manifest: Phase9ExitManifest) -> str:
    return hashlib.sha256(canonical_phase9_exit_manifest_bytes(manifest)).hexdigest()


def reject(reason: Phase9ExitRejectReason, message: str) -> None:
    raise Phase9ExitRejected(reason, message)
