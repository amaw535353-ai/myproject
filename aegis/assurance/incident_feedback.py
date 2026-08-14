from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping

from aegis.model_serving.abuse_response import (
    AbuseSignalType,
    IncidentAction,
    VerifiedIncidentDecision,
)

from .corpus_evolution import (
    P6C_CHANGE_MANIFEST_SCHEMA_VERSION,
    CorpusChangeManifest,
    CorpusChangeType,
    VerifiedCorpusEvolution,
    change_manifest_digest,
)
from .regression import (
    P6A_CORPUS_SCHEMA_VERSION,
    AssuranceCase,
    AssuranceCorpus,
    AssuranceExpectation,
    AssuranceSeverity,
    case_definition_digest,
    corpus_digest,
)


P6F_FEEDBACK_POLICY_VERSION = "incident-to-assurance-feedback-v1"
P6F_FEEDBACK_SCHEMA_VERSION = "aegis-incident-assurance-feedback-v1"
P6F_LEDGER_SCHEMA_VERSION = "aegis-incident-coverage-ledger-v1"
P6F_FEEDBACK_MODE = "deterministic-threat-informed-regression-feedback-v1"


class IncidentFeedbackRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    INCIDENT_UNVERIFIED = "incident_unverified"
    INCIDENT_NOT_ACTIONABLE = "incident_not_actionable"
    INCIDENT_IDENTITY_MISMATCH = "incident_identity_mismatch"
    CORPUS_INVALID = "corpus_invalid"
    BASELINE_DIGEST_MISMATCH = "baseline_digest_mismatch"
    CANDIDATE_DIGEST_MISMATCH = "candidate_digest_mismatch"
    EVOLUTION_UNVERIFIED = "evolution_unverified"
    EVOLUTION_BINDING_MISMATCH = "evolution_binding_mismatch"
    LEDGER_INVALID = "ledger_invalid"
    LEDGER_DIGEST_MISMATCH = "ledger_digest_mismatch"
    LEDGER_VERSION_INVALID = "ledger_version_invalid"
    OBLIGATION_DUPLICATE = "obligation_duplicate"
    OBLIGATION_DROPPED = "obligation_dropped"
    OBLIGATION_MUTATED = "obligation_mutated"
    CURRENT_OBLIGATION_MISSING = "current_obligation_missing"
    FEEDBACK_INVALID = "feedback_invalid"
    FEEDBACK_DIGEST_MISMATCH = "feedback_digest_mismatch"
    FEEDBACK_DUPLICATE = "feedback_duplicate"
    SIGNAL_SCOPE_MISMATCH = "signal_scope_mismatch"
    CASE_LINK_MISSING = "case_link_missing"
    CASE_LINK_DUPLICATE = "case_link_duplicate"
    CASE_DEFINITION_MISMATCH = "case_definition_mismatch"
    CASE_NOT_SECURITY_BLOCK = "case_not_security_block"
    CASE_SEVERITY_INSUFFICIENT = "case_severity_insufficient"
    CASE_BOUNDARY_DISALLOWED = "case_boundary_disallowed"
    CASE_ATTACK_CLASS_MISMATCH = "case_attack_class_mismatch"
    INCIDENT_TRACE_MISSING = "incident_trace_missing"
    CHANGE_RECORD_MISSING = "change_record_missing"
    CHANGE_TYPE_INVALID = "change_type_invalid"
    CHANGE_OWNER_UNTRUSTED = "change_owner_untrusted"
    CHANGE_REASON_MISMATCH = "change_reason_mismatch"
    HISTORICAL_COVERAGE_MISSING = "historical_coverage_missing"


class IncidentFeedbackRejected(ValueError):
    def __init__(
        self,
        reason: IncidentFeedbackRejectReason,
        message: str,
        *,
        incident_id: str | None = None,
        case_id: str | None = None,
        obligation_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.incident_id = incident_id
        self.case_id = case_id
        self.obligation_id = obligation_id


@dataclass(frozen=True)
class IncidentCoverageObligation:
    obligation_id: str
    incident_id: str
    incident_batch_sha256: str
    required_min_severity: AssuranceSeverity
    required_signal_types: tuple[str, ...]
    created_in_corpus_version: str
    trace_sha256: str


@dataclass(frozen=True)
class IncidentCoverageLedger:
    ledger_id: str
    version: int
    previous_ledger_sha256: str
    obligations: tuple[IncidentCoverageObligation, ...]
    schema_version: str = P6F_LEDGER_SCHEMA_VERSION


@dataclass(frozen=True)
class IncidentCaseLink:
    case_id: str
    case_definition_sha256: str
    change_id: str
    signal_types: tuple[str, ...]


@dataclass(frozen=True)
class IncidentAssuranceFeedback:
    feedback_id: str
    incident_id: str
    deployment_id: str
    incident_batch_sha256: str
    incident_action: IncidentAction
    incident_risk_points: int
    incident_signal_counts: tuple[tuple[str, int], ...]
    baseline_corpus_sha256: str
    candidate_corpus_sha256: str
    change_manifest_sha256: str
    previous_ledger_sha256: str
    candidate_ledger_sha256: str
    links: tuple[IncidentCaseLink, ...]
    created_at_epoch: int
    schema_version: str = P6F_FEEDBACK_SCHEMA_VERSION


@dataclass(frozen=True)
class IncidentFeedbackRequest:
    feedback_id: str
    feedback_sha256: str
    incident_id: str
    incident_batch_sha256: str
    candidate_corpus_sha256: str
    candidate_ledger_sha256: str
    evolution_evidence_sha256: str


@dataclass(frozen=True)
class IncidentFeedbackPolicy:
    expected_baseline_corpus_id: str
    expected_baseline_corpus_sha256: str
    expected_previous_ledger_sha256: str
    trusted_change_owner_ids: frozenset[str]
    allowed_target_boundaries: frozenset[str]
    required_attack_class: str = "incident_derived_serving_abuse"
    material_actions: frozenset[IncidentAction] = frozenset(
        {IncidentAction.QUARANTINE, IncidentAction.REVOKE_DEPLOYMENT}
    )
    minimum_severity_by_action: Mapping[IncidentAction, AssuranceSeverity] | None = None

    def severity_map(self) -> Mapping[IncidentAction, AssuranceSeverity]:
        if self.minimum_severity_by_action is not None:
            return self.minimum_severity_by_action
        return {
            IncidentAction.QUARANTINE: AssuranceSeverity.HIGH,
            IncidentAction.REVOKE_DEPLOYMENT: AssuranceSeverity.CRITICAL,
        }


@dataclass(frozen=True)
class VerifiedIncidentFeedback:
    feedback_id: str
    incident_id: str
    deployment_id: str
    incident_batch_sha256: str
    incident_action: IncidentAction
    incident_risk_points: int
    baseline_corpus_sha256: str
    candidate_corpus_sha256: str
    change_manifest_sha256: str
    previous_ledger_sha256: str
    candidate_ledger_sha256: str
    current_obligation_id: str
    current_obligation_trace_sha256: str
    linked_case_ids: tuple[str, ...]
    covered_signal_types: tuple[str, ...]
    active_obligation_ids: tuple[str, ...]
    feedback_sha256: str
    evidence_sha256: str
    incident_integrity_verified: bool = True
    exact_incident_binding_verified: bool = True
    exact_evolution_binding_verified: bool = True
    append_only_obligation_ledger_verified: bool = True
    exact_case_links_verified: bool = True
    threat_signal_coverage_verified: bool = True
    historical_incident_coverage_verified: bool = True
    p6c_future_removal_governance_required: bool = True
    semantic_equivalence_proven: bool = False
    automatic_test_generation: bool = False
    production_incident_management: bool = False
    rollback_resistant_ledger: bool = False
    network_operations: int = 0
    policy_version: str = P6F_FEEDBACK_POLICY_VERSION
    feedback_mode: str = P6F_FEEDBACK_MODE


def _reject(
    reason: IncidentFeedbackRejectReason,
    message: str,
    *,
    incident_id: str | None = None,
    case_id: str | None = None,
    obligation_id: str | None = None,
) -> None:
    raise IncidentFeedbackRejected(
        reason,
        message,
        incident_id=incident_id,
        case_id=case_id,
        obligation_id=obligation_id,
    )


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def _severity_rank(severity: AssuranceSeverity) -> int:
    return {
        AssuranceSeverity.LOW: 1,
        AssuranceSeverity.MEDIUM: 2,
        AssuranceSeverity.HIGH: 3,
        AssuranceSeverity.CRITICAL: 4,
    }[severity]


def _canonical_signal_counts(signal_counts: tuple[tuple[str, int], ...]) -> tuple[tuple[str, int], ...]:
    return tuple(sorted((str(signal), int(count)) for signal, count in signal_counts))


def incident_trace_digest(
    incident: VerifiedIncidentDecision,
    *,
    required_min_severity: AssuranceSeverity,
) -> str:
    document = {
        "action": incident.action.value if isinstance(incident.action, IncidentAction) else str(incident.action),
        "batch_sha256": incident.batch_sha256.casefold(),
        "deployment_id": incident.deployment_id,
        "incident_id": incident.incident_id,
        "required_min_severity": required_min_severity.value,
        "risk_points": incident.risk_points,
        "signal_counts": list(_canonical_signal_counts(incident.signal_counts)),
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def canonical_incident_coverage_ledger_bytes(ledger: IncidentCoverageLedger) -> bytes:
    document = {
        "ledger_id": ledger.ledger_id,
        "obligations": [
            {
                "created_in_corpus_version": item.created_in_corpus_version,
                "incident_batch_sha256": item.incident_batch_sha256.casefold(),
                "incident_id": item.incident_id,
                "obligation_id": item.obligation_id,
                "required_min_severity": item.required_min_severity.value
                if isinstance(item.required_min_severity, AssuranceSeverity)
                else str(item.required_min_severity),
                "required_signal_types": sorted(item.required_signal_types),
                "trace_sha256": item.trace_sha256.casefold(),
            }
            for item in sorted(ledger.obligations, key=lambda item: item.obligation_id)
        ],
        "previous_ledger_sha256": ledger.previous_ledger_sha256.casefold(),
        "schema_version": ledger.schema_version,
        "version": ledger.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def incident_coverage_ledger_digest(ledger: IncidentCoverageLedger) -> str:
    return hashlib.sha256(canonical_incident_coverage_ledger_bytes(ledger)).hexdigest()


def canonical_incident_feedback_bytes(feedback: IncidentAssuranceFeedback) -> bytes:
    document = asdict(feedback)
    document["incident_action"] = (
        feedback.incident_action.value
        if isinstance(feedback.incident_action, IncidentAction)
        else str(feedback.incident_action)
    )
    document["incident_batch_sha256"] = feedback.incident_batch_sha256.casefold()
    document["baseline_corpus_sha256"] = feedback.baseline_corpus_sha256.casefold()
    document["candidate_corpus_sha256"] = feedback.candidate_corpus_sha256.casefold()
    document["change_manifest_sha256"] = feedback.change_manifest_sha256.casefold()
    document["previous_ledger_sha256"] = feedback.previous_ledger_sha256.casefold()
    document["candidate_ledger_sha256"] = feedback.candidate_ledger_sha256.casefold()
    document["incident_signal_counts"] = list(_canonical_signal_counts(feedback.incident_signal_counts))
    document["links"] = [
        {
            "case_definition_sha256": link.case_definition_sha256.casefold(),
            "case_id": link.case_id,
            "change_id": link.change_id,
            "signal_types": sorted(link.signal_types),
        }
        for link in sorted(feedback.links, key=lambda item: item.case_id)
    ]
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def incident_feedback_digest(feedback: IncidentAssuranceFeedback) -> str:
    return hashlib.sha256(canonical_incident_feedback_bytes(feedback)).hexdigest()


def _expected_change_reason(
    *,
    feedback_id: str,
    incident_id: str,
    batch_sha256: str,
) -> str:
    return f"incident-feedback:{feedback_id}:{incident_id}:{batch_sha256.casefold()}"


def _validate_policy(policy: IncidentFeedbackPolicy) -> None:
    severity_map = policy.severity_map()
    if (
        not policy.expected_baseline_corpus_id
        or not _is_sha256(policy.expected_baseline_corpus_sha256)
        or not _is_sha256(policy.expected_previous_ledger_sha256)
        or not policy.trusted_change_owner_ids
        or not policy.allowed_target_boundaries
        or not policy.required_attack_class
        or not policy.material_actions
        or set(severity_map) != set(policy.material_actions)
        or any(not isinstance(action, IncidentAction) for action in policy.material_actions)
        or any(not isinstance(severity, AssuranceSeverity) for severity in severity_map.values())
    ):
        _reject(IncidentFeedbackRejectReason.POLICY_INVALID, "incident feedback policy is invalid")


def _validate_corpus(corpus: AssuranceCorpus, *, label: str) -> dict[str, AssuranceCase]:
    if (
        corpus.schema_version != P6A_CORPUS_SCHEMA_VERSION
        or not corpus.corpus_id
        or not corpus.version
        or not corpus.cases
    ):
        _reject(IncidentFeedbackRejectReason.CORPUS_INVALID, f"{label} assurance corpus metadata is invalid")
    case_map: dict[str, AssuranceCase] = {}
    for case in corpus.cases:
        if (
            not case.case_id
            or not case.boundary
            or not case.attack_class
            or not case.invariant
            or not isinstance(case.severity, AssuranceSeverity)
            or not isinstance(case.expectation, AssuranceExpectation)
            or case.case_id in case_map
        ):
            _reject(
                IncidentFeedbackRejectReason.CORPUS_INVALID,
                f"{label} assurance corpus contains an invalid or duplicate case",
                case_id=case.case_id or None,
            )
        case_map[case.case_id] = case
    return case_map


def _validate_incident(
    incident: VerifiedIncidentDecision,
    policy: IncidentFeedbackPolicy,
) -> tuple[AssuranceSeverity, tuple[str, ...]]:
    if (
        not incident.incident_id
        or not incident.deployment_id
        or not _is_sha256(incident.batch_sha256)
        or not isinstance(incident.action, IncidentAction)
        or incident.risk_points < 0
        or not incident.telemetry_signature_verified
        or not incident.telemetry_chain_verified
        or not incident.telemetry_complete
        or incident.network_operations != 0
    ):
        _reject(
            IncidentFeedbackRejectReason.INCIDENT_UNVERIFIED,
            "incident feedback requires an intact P5-I verified incident decision",
            incident_id=incident.incident_id or None,
        )
    if incident.action not in policy.material_actions:
        _reject(
            IncidentFeedbackRejectReason.INCIDENT_NOT_ACTIONABLE,
            "incident action does not meet the policy threshold for durable regression feedback",
            incident_id=incident.incident_id,
        )

    signal_seen: set[str] = set()
    material_signals: list[str] = []
    for signal, count in incident.signal_counts:
        try:
            signal_type = AbuseSignalType(str(signal))
        except ValueError:
            _reject(
                IncidentFeedbackRejectReason.INCIDENT_UNVERIFIED,
                "incident contains an unknown serving-abuse signal",
                incident_id=incident.incident_id,
            )
        signal_value = signal_type.value
        if signal_value in signal_seen or not isinstance(count, int) or count <= 0:
            _reject(
                IncidentFeedbackRejectReason.INCIDENT_UNVERIFIED,
                "incident signal counts are duplicate or invalid",
                incident_id=incident.incident_id,
            )
        signal_seen.add(signal_value)
        if signal_type != AbuseSignalType.NORMAL_QUERY:
            material_signals.append(signal_value)
    if not material_signals:
        _reject(
            IncidentFeedbackRejectReason.INCIDENT_UNVERIFIED,
            "material incident has no non-benign threat signals",
            incident_id=incident.incident_id,
        )
    return policy.severity_map()[incident.action], tuple(sorted(material_signals))


def _validate_evolution(
    evolution: VerifiedCorpusEvolution,
    *,
    baseline: AssuranceCorpus,
    candidate: AssuranceCorpus,
    manifest: CorpusChangeManifest,
    baseline_sha: str,
    candidate_sha: str,
) -> str:
    manifest_sha = change_manifest_digest(manifest)
    if (
        manifest.schema_version != P6C_CHANGE_MANIFEST_SCHEMA_VERSION
        or not evolution.exact_change_coverage_verified
        or not evolution.removal_tombstones_verified
        or not evolution.coverage_floors_verified
        or not evolution.weakening_prevented
        or not evolution.silent_coverage_shrink_prevented
        or evolution.network_operations != 0
        or not _is_sha256(evolution.evidence_sha256)
    ):
        _reject(
            IncidentFeedbackRejectReason.EVOLUTION_UNVERIFIED,
            "incident feedback requires intact P6-C corpus-evolution evidence",
        )
    block_count = sum(case.expectation == AssuranceExpectation.BLOCK for case in candidate.cases)
    allow_count = sum(case.expectation == AssuranceExpectation.ALLOW for case in candidate.cases)
    critical_count = sum(
        case.expectation == AssuranceExpectation.BLOCK and case.severity == AssuranceSeverity.CRITICAL
        for case in candidate.cases
    )
    high_critical_count = sum(
        case.expectation == AssuranceExpectation.BLOCK
        and case.severity in {AssuranceSeverity.HIGH, AssuranceSeverity.CRITICAL}
        for case in candidate.cases
    )
    if (
        evolution.corpus_id != candidate.corpus_id
        or evolution.baseline_version != baseline.version
        or evolution.candidate_version != candidate.version
        or not hmac.compare_digest(evolution.baseline_corpus_sha256.casefold(), baseline_sha)
        or not hmac.compare_digest(evolution.candidate_corpus_sha256.casefold(), candidate_sha)
        or not hmac.compare_digest(evolution.change_manifest_sha256.casefold(), manifest_sha)
        or evolution.candidate_case_count != len(candidate.cases)
        or evolution.candidate_block_case_count != block_count
        or evolution.candidate_allow_case_count != allow_count
        or evolution.candidate_critical_block_count != critical_count
        or evolution.candidate_high_or_critical_block_count != high_critical_count
    ):
        _reject(
            IncidentFeedbackRejectReason.EVOLUTION_BINDING_MISMATCH,
            "P6-C evolution evidence does not bind to the exact current corpus transition",
        )
    return manifest_sha


def _validate_ledger(
    ledger: IncidentCoverageLedger,
    *,
    label: str,
) -> dict[str, IncidentCoverageObligation]:
    if (
        ledger.schema_version != P6F_LEDGER_SCHEMA_VERSION
        or not ledger.ledger_id
        or ledger.version < 0
        or not _is_sha256(ledger.previous_ledger_sha256)
    ):
        _reject(IncidentFeedbackRejectReason.LEDGER_INVALID, f"{label} incident coverage ledger is invalid")
    obligations: dict[str, IncidentCoverageObligation] = {}
    trace_ids: set[str] = set()
    incident_ids: set[str] = set()
    for item in ledger.obligations:
        if (
            not item.obligation_id
            or not item.incident_id
            or not _is_sha256(item.incident_batch_sha256)
            or not isinstance(item.required_min_severity, AssuranceSeverity)
            or not item.required_signal_types
            or len(set(item.required_signal_types)) != len(item.required_signal_types)
            or not item.created_in_corpus_version
            or not _is_sha256(item.trace_sha256)
        ):
            _reject(
                IncidentFeedbackRejectReason.LEDGER_INVALID,
                f"{label} ledger contains an invalid obligation",
                obligation_id=item.obligation_id or None,
            )
        if (
            item.obligation_id in obligations
            or item.trace_sha256.casefold() in trace_ids
            or item.incident_id in incident_ids
        ):
            _reject(
                IncidentFeedbackRejectReason.OBLIGATION_DUPLICATE,
                f"{label} ledger contains duplicate incident obligations",
                obligation_id=item.obligation_id,
            )
        obligations[item.obligation_id] = item
        trace_ids.add(item.trace_sha256.casefold())
        incident_ids.add(item.incident_id)
    return obligations


def _obligation_identity(item: IncidentCoverageObligation) -> tuple[object, ...]:
    return (
        item.obligation_id,
        item.incident_id,
        item.incident_batch_sha256.casefold(),
        item.required_min_severity,
        tuple(sorted(item.required_signal_types)),
        item.created_in_corpus_version,
        item.trace_sha256.casefold(),
    )


def _validate_ledger_transition(
    previous: IncidentCoverageLedger,
    candidate: IncidentCoverageLedger,
    *,
    policy: IncidentFeedbackPolicy,
    incident: VerifiedIncidentDecision,
    required_min_severity: AssuranceSeverity,
    material_signals: tuple[str, ...],
    candidate_corpus_version: str,
) -> IncidentCoverageObligation:
    previous_map = _validate_ledger(previous, label="previous")
    candidate_map = _validate_ledger(candidate, label="candidate")
    previous_sha = incident_coverage_ledger_digest(previous)
    if not hmac.compare_digest(previous_sha, policy.expected_previous_ledger_sha256.casefold()):
        _reject(
            IncidentFeedbackRejectReason.LEDGER_DIGEST_MISMATCH,
            "previous incident coverage ledger digest does not match policy",
        )
    if (
        candidate.ledger_id != previous.ledger_id
        or candidate.version != previous.version + 1
        or not hmac.compare_digest(candidate.previous_ledger_sha256.casefold(), previous_sha)
    ):
        _reject(
            IncidentFeedbackRejectReason.LEDGER_VERSION_INVALID,
            "candidate incident coverage ledger does not extend the exact previous ledger",
        )
    for obligation_id, prior in previous_map.items():
        current = candidate_map.get(obligation_id)
        if current is None:
            _reject(
                IncidentFeedbackRejectReason.OBLIGATION_DROPPED,
                "candidate ledger dropped a historical incident coverage obligation",
                obligation_id=obligation_id,
            )
        if _obligation_identity(current) != _obligation_identity(prior):
            _reject(
                IncidentFeedbackRejectReason.OBLIGATION_MUTATED,
                "candidate ledger mutated a historical incident coverage obligation",
                obligation_id=obligation_id,
            )

    new_ids = set(candidate_map) - set(previous_map)
    if len(new_ids) != 1:
        _reject(
            IncidentFeedbackRejectReason.CURRENT_OBLIGATION_MISSING,
            "candidate ledger must append exactly one obligation for the current incident",
            incident_id=incident.incident_id,
        )
    current = candidate_map[next(iter(new_ids))]
    expected_trace = incident_trace_digest(
        incident,
        required_min_severity=required_min_severity,
    )
    if (
        current.incident_id != incident.incident_id
        or not hmac.compare_digest(current.incident_batch_sha256.casefold(), incident.batch_sha256.casefold())
        or current.required_min_severity != required_min_severity
        or tuple(sorted(current.required_signal_types)) != tuple(sorted(material_signals))
        or current.created_in_corpus_version != candidate_corpus_version
        or not hmac.compare_digest(current.trace_sha256.casefold(), expected_trace)
    ):
        _reject(
            IncidentFeedbackRejectReason.CURRENT_OBLIGATION_MISSING,
            "new ledger obligation does not exactly represent the current verified incident",
            incident_id=incident.incident_id,
            obligation_id=current.obligation_id,
        )
    return current


def _find_obligation_coverage(
    candidate_cases: Mapping[str, AssuranceCase],
    obligation: IncidentCoverageObligation,
) -> tuple[str, ...]:
    marker = f"incident_trace_sha256={obligation.trace_sha256.casefold()}"
    covered = tuple(
        sorted(
            case.case_id
            for case in candidate_cases.values()
            if marker in case.invariant
            and case.expectation == AssuranceExpectation.BLOCK
            and _severity_rank(case.severity) >= _severity_rank(obligation.required_min_severity)
        )
    )
    return covered


class IncidentToAssuranceFeedbackGate:
    """Bind material P5-I incidents to append-only threat-informed P6-A regression coverage.

    The gate verifies exact incident, corpus-evolution, ledger, change-record, and case-definition
    bindings. It does not infer semantic equivalence between an operational incident and a test
    case, automatically generate tests, operate incident-management systems, or provide durable
    rollback-resistant storage.
    """

    def __init__(self, policy: IncidentFeedbackPolicy) -> None:
        self._policy = policy
        self._seen_feedback_ids: set[str] = set()

    def evaluate(
        self,
        request: IncidentFeedbackRequest,
        feedback: IncidentAssuranceFeedback,
        incident: VerifiedIncidentDecision,
        baseline_corpus: AssuranceCorpus,
        candidate_corpus: AssuranceCorpus,
        manifest: CorpusChangeManifest,
        evolution: VerifiedCorpusEvolution,
        previous_ledger: IncidentCoverageLedger,
        candidate_ledger: IncidentCoverageLedger,
    ) -> VerifiedIncidentFeedback:
        _validate_policy(self._policy)
        required_min_severity, material_signals = _validate_incident(incident, self._policy)

        _validate_corpus(baseline_corpus, label="baseline")
        candidate_cases = _validate_corpus(candidate_corpus, label="candidate")
        baseline_sha = corpus_digest(baseline_corpus)
        candidate_sha = corpus_digest(candidate_corpus)
        if (
            baseline_corpus.corpus_id != self._policy.expected_baseline_corpus_id
            or not hmac.compare_digest(baseline_sha, self._policy.expected_baseline_corpus_sha256.casefold())
        ):
            _reject(
                IncidentFeedbackRejectReason.BASELINE_DIGEST_MISMATCH,
                "baseline assurance corpus does not match the policy-pinned release",
            )
        if candidate_corpus.corpus_id != baseline_corpus.corpus_id:
            _reject(
                IncidentFeedbackRejectReason.CANDIDATE_DIGEST_MISMATCH,
                "candidate assurance corpus is from a different lineage",
            )

        manifest_sha = _validate_evolution(
            evolution,
            baseline=baseline_corpus,
            candidate=candidate_corpus,
            manifest=manifest,
            baseline_sha=baseline_sha,
            candidate_sha=candidate_sha,
        )
        current_obligation = _validate_ledger_transition(
            previous_ledger,
            candidate_ledger,
            policy=self._policy,
            incident=incident,
            required_min_severity=required_min_severity,
            material_signals=material_signals,
            candidate_corpus_version=candidate_corpus.version,
        )
        previous_ledger_sha = incident_coverage_ledger_digest(previous_ledger)
        candidate_ledger_sha = incident_coverage_ledger_digest(candidate_ledger)

        if (
            feedback.schema_version != P6F_FEEDBACK_SCHEMA_VERSION
            or not feedback.feedback_id
            or not feedback.incident_id
            or not feedback.deployment_id
            or not _is_sha256(feedback.incident_batch_sha256)
            or not isinstance(feedback.incident_action, IncidentAction)
            or feedback.incident_risk_points < 0
            or not _is_sha256(feedback.baseline_corpus_sha256)
            or not _is_sha256(feedback.candidate_corpus_sha256)
            or not _is_sha256(feedback.change_manifest_sha256)
            or not _is_sha256(feedback.previous_ledger_sha256)
            or not _is_sha256(feedback.candidate_ledger_sha256)
            or not feedback.links
            or feedback.created_at_epoch <= 0
        ):
            _reject(
                IncidentFeedbackRejectReason.FEEDBACK_INVALID,
                "incident assurance feedback metadata is invalid",
                incident_id=feedback.incident_id or None,
            )
        if feedback.feedback_id in self._seen_feedback_ids:
            _reject(
                IncidentFeedbackRejectReason.FEEDBACK_DUPLICATE,
                "incident assurance feedback ID was already processed",
                incident_id=feedback.incident_id,
            )
        if (
            feedback.incident_id != incident.incident_id
            or feedback.deployment_id != incident.deployment_id
            or not hmac.compare_digest(feedback.incident_batch_sha256.casefold(), incident.batch_sha256.casefold())
            or feedback.incident_action != incident.action
            or feedback.incident_risk_points != incident.risk_points
            or _canonical_signal_counts(feedback.incident_signal_counts)
            != _canonical_signal_counts(incident.signal_counts)
        ):
            _reject(
                IncidentFeedbackRejectReason.INCIDENT_IDENTITY_MISMATCH,
                "feedback does not bind to the exact verified P5-I incident",
                incident_id=feedback.incident_id,
            )
        if (
            not hmac.compare_digest(feedback.baseline_corpus_sha256.casefold(), baseline_sha)
            or not hmac.compare_digest(feedback.candidate_corpus_sha256.casefold(), candidate_sha)
            or not hmac.compare_digest(feedback.change_manifest_sha256.casefold(), manifest_sha)
            or not hmac.compare_digest(feedback.previous_ledger_sha256.casefold(), previous_ledger_sha)
            or not hmac.compare_digest(feedback.candidate_ledger_sha256.casefold(), candidate_ledger_sha)
        ):
            _reject(
                IncidentFeedbackRejectReason.FEEDBACK_DIGEST_MISMATCH,
                "feedback does not bind to exact corpus/change/ledger evidence",
                incident_id=feedback.incident_id,
            )

        feedback_sha = incident_feedback_digest(feedback)
        if (
            not request.feedback_id
            or not _is_sha256(request.feedback_sha256)
            or not request.incident_id
            or not _is_sha256(request.incident_batch_sha256)
            or not _is_sha256(request.candidate_corpus_sha256)
            or not _is_sha256(request.candidate_ledger_sha256)
            or not _is_sha256(request.evolution_evidence_sha256)
        ):
            _reject(
                IncidentFeedbackRejectReason.FEEDBACK_INVALID,
                "incident feedback request metadata is invalid",
                incident_id=request.incident_id or None,
            )
        if (
            request.feedback_id != feedback.feedback_id
            or request.incident_id != incident.incident_id
            or not hmac.compare_digest(request.feedback_sha256.casefold(), feedback_sha)
            or not hmac.compare_digest(request.incident_batch_sha256.casefold(), incident.batch_sha256.casefold())
            or not hmac.compare_digest(request.candidate_corpus_sha256.casefold(), candidate_sha)
            or not hmac.compare_digest(request.candidate_ledger_sha256.casefold(), candidate_ledger_sha)
            or not hmac.compare_digest(request.evolution_evidence_sha256.casefold(), evolution.evidence_sha256.casefold())
        ):
            _reject(
                IncidentFeedbackRejectReason.FEEDBACK_DIGEST_MISMATCH,
                "feedback request does not bind to exact incident/corpus/ledger/evolution evidence",
                incident_id=request.incident_id,
            )

        manifest_changes = {change.case_id: change for change in manifest.changes}
        if len(manifest_changes) != len(manifest.changes):
            _reject(
                IncidentFeedbackRejectReason.CHANGE_RECORD_MISSING,
                "change manifest contains duplicate case records",
            )
        link_case_ids: set[str] = set()
        link_change_ids: set[str] = set()
        linked_signals: set[str] = set()
        linked_case_ids: list[str] = []
        expected_reason = _expected_change_reason(
            feedback_id=feedback.feedback_id,
            incident_id=incident.incident_id,
            batch_sha256=incident.batch_sha256,
        )
        current_marker = f"incident_trace_sha256={current_obligation.trace_sha256.casefold()}"

        for link in feedback.links:
            if (
                not link.case_id
                or not _is_sha256(link.case_definition_sha256)
                or not link.change_id
                or not link.signal_types
                or len(set(link.signal_types)) != len(link.signal_types)
            ):
                _reject(
                    IncidentFeedbackRejectReason.FEEDBACK_INVALID,
                    "incident case link is invalid",
                    incident_id=incident.incident_id,
                    case_id=link.case_id or None,
                )
            if link.case_id in link_case_ids or link.change_id in link_change_ids:
                _reject(
                    IncidentFeedbackRejectReason.CASE_LINK_DUPLICATE,
                    "incident feedback contains duplicate case/change links",
                    incident_id=incident.incident_id,
                    case_id=link.case_id,
                )
            link_case_ids.add(link.case_id)
            link_change_ids.add(link.change_id)

            case = candidate_cases.get(link.case_id)
            if case is None:
                _reject(
                    IncidentFeedbackRejectReason.CASE_LINK_MISSING,
                    "incident feedback references a case absent from the candidate corpus",
                    incident_id=incident.incident_id,
                    case_id=link.case_id,
                )
            if not hmac.compare_digest(link.case_definition_sha256.casefold(), case_definition_digest(case)):
                _reject(
                    IncidentFeedbackRejectReason.CASE_DEFINITION_MISMATCH,
                    "incident case link does not bind to the exact candidate case definition",
                    incident_id=incident.incident_id,
                    case_id=link.case_id,
                )
            if case.expectation != AssuranceExpectation.BLOCK:
                _reject(
                    IncidentFeedbackRejectReason.CASE_NOT_SECURITY_BLOCK,
                    "incident-derived regression coverage must remain an attack-blocking case",
                    incident_id=incident.incident_id,
                    case_id=link.case_id,
                )
            if _severity_rank(case.severity) < _severity_rank(required_min_severity):
                _reject(
                    IncidentFeedbackRejectReason.CASE_SEVERITY_INSUFFICIENT,
                    "incident-derived case severity is below the action-derived minimum",
                    incident_id=incident.incident_id,
                    case_id=link.case_id,
                )
            if case.boundary not in self._policy.allowed_target_boundaries:
                _reject(
                    IncidentFeedbackRejectReason.CASE_BOUNDARY_DISALLOWED,
                    "incident-derived case targets a boundary outside feedback policy",
                    incident_id=incident.incident_id,
                    case_id=link.case_id,
                )
            if case.attack_class != self._policy.required_attack_class:
                _reject(
                    IncidentFeedbackRejectReason.CASE_ATTACK_CLASS_MISMATCH,
                    "incident-derived case does not use the policy-required attack class",
                    incident_id=incident.incident_id,
                    case_id=link.case_id,
                )
            if current_marker not in case.invariant:
                _reject(
                    IncidentFeedbackRejectReason.INCIDENT_TRACE_MISSING,
                    "incident-derived case invariant is missing the exact incident trace digest",
                    incident_id=incident.incident_id,
                    case_id=link.case_id,
                )

            change = manifest_changes.get(link.case_id)
            if change is None or change.change_id != link.change_id:
                _reject(
                    IncidentFeedbackRejectReason.CHANGE_RECORD_MISSING,
                    "incident-derived case lacks the exact P6-C change record",
                    incident_id=incident.incident_id,
                    case_id=link.case_id,
                )
            if change.change_type not in {CorpusChangeType.ADD, CorpusChangeType.MODIFY}:
                _reject(
                    IncidentFeedbackRejectReason.CHANGE_TYPE_INVALID,
                    "incident feedback can only bind to added or strengthened cases",
                    incident_id=incident.incident_id,
                    case_id=link.case_id,
                )
            if change.owner_id not in self._policy.trusted_change_owner_ids:
                _reject(
                    IncidentFeedbackRejectReason.CHANGE_OWNER_UNTRUSTED,
                    "incident-derived P6-C change owner is not trusted",
                    incident_id=incident.incident_id,
                    case_id=link.case_id,
                )
            if (
                not _is_sha256(change.new_case_definition_sha256)
                or not hmac.compare_digest(change.new_case_definition_sha256.casefold(), case_definition_digest(case))
            ):
                _reject(
                    IncidentFeedbackRejectReason.CASE_DEFINITION_MISMATCH,
                    "P6-C change record does not bind to the incident-derived case definition",
                    incident_id=incident.incident_id,
                    case_id=link.case_id,
                )
            if change.reason != expected_reason:
                _reject(
                    IncidentFeedbackRejectReason.CHANGE_REASON_MISMATCH,
                    "P6-C change reason is not explicitly bound to the incident feedback record",
                    incident_id=incident.incident_id,
                    case_id=link.case_id,
                )
            for signal in link.signal_types:
                if signal not in material_signals:
                    _reject(
                        IncidentFeedbackRejectReason.SIGNAL_SCOPE_MISMATCH,
                        "incident case link claims a signal not present in the verified incident",
                        incident_id=incident.incident_id,
                        case_id=link.case_id,
                    )
                linked_signals.add(signal)
            linked_case_ids.append(link.case_id)

        if linked_signals != set(material_signals):
            _reject(
                IncidentFeedbackRejectReason.SIGNAL_SCOPE_MISMATCH,
                "incident-derived case links do not cover every material verified incident signal",
                incident_id=incident.incident_id,
            )
        if not set(linked_case_ids).issubset(
            set(evolution.added_case_ids) | set(evolution.modified_case_ids)
        ):
            _reject(
                IncidentFeedbackRejectReason.CHANGE_RECORD_MISSING,
                "incident-derived links are not reflected in P6-C added/modified evidence",
                incident_id=incident.incident_id,
            )

        for obligation in candidate_ledger.obligations:
            covered = _find_obligation_coverage(candidate_cases, obligation)
            if not covered:
                _reject(
                    IncidentFeedbackRejectReason.HISTORICAL_COVERAGE_MISSING,
                    "candidate corpus no longer contains qualifying coverage for an active incident obligation",
                    incident_id=obligation.incident_id,
                    obligation_id=obligation.obligation_id,
                )

        if not set(linked_case_ids).issubset(set(_find_obligation_coverage(candidate_cases, current_obligation))):
            _reject(
                IncidentFeedbackRejectReason.CASE_LINK_MISSING,
                "explicit incident links are not qualifying coverage for the current obligation",
                incident_id=incident.incident_id,
            )

        self._seen_feedback_ids.add(feedback.feedback_id)
        evidence_document = {
            "active_obligation_ids": sorted(item.obligation_id for item in candidate_ledger.obligations),
            "candidate_corpus_sha256": candidate_sha,
            "candidate_ledger_sha256": candidate_ledger_sha,
            "feedback_sha256": feedback_sha,
            "incident_batch_sha256": incident.batch_sha256.casefold(),
            "incident_id": incident.incident_id,
            "linked_case_ids": sorted(linked_case_ids),
            "material_signals": sorted(material_signals),
            "previous_ledger_sha256": previous_ledger_sha,
        }
        evidence_sha = hashlib.sha256(
            json.dumps(evidence_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        return VerifiedIncidentFeedback(
            feedback_id=feedback.feedback_id,
            incident_id=incident.incident_id,
            deployment_id=incident.deployment_id,
            incident_batch_sha256=incident.batch_sha256.casefold(),
            incident_action=incident.action,
            incident_risk_points=incident.risk_points,
            baseline_corpus_sha256=baseline_sha,
            candidate_corpus_sha256=candidate_sha,
            change_manifest_sha256=manifest_sha,
            previous_ledger_sha256=previous_ledger_sha,
            candidate_ledger_sha256=candidate_ledger_sha,
            current_obligation_id=current_obligation.obligation_id,
            current_obligation_trace_sha256=current_obligation.trace_sha256.casefold(),
            linked_case_ids=tuple(sorted(linked_case_ids)),
            covered_signal_types=tuple(sorted(material_signals)),
            active_obligation_ids=tuple(sorted(item.obligation_id for item in candidate_ledger.obligations)),
            feedback_sha256=feedback_sha,
            evidence_sha256=evidence_sha,
        )
