from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import StrEnum


P6A_ASSURANCE_POLICY_VERSION = "continuous-ai-security-assurance-v1"
P6A_CORPUS_SCHEMA_VERSION = "aegis-cross-boundary-corpus-v1"
P6A_EVIDENCE_SCHEMA_VERSION = "aegis-security-regression-evidence-v1"
P6A_ASSURANCE_MODE = "deterministic-cross-boundary-regression-gate-v1"


class AssuranceExpectation(StrEnum):
    BLOCK = "block"
    ALLOW = "allow"


class AssuranceSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssuranceRejectReason(StrEnum):
    CORPUS_INVALID = "corpus_invalid"
    CORPUS_DIGEST_MISMATCH = "corpus_digest_mismatch"
    BOUNDARY_COVERAGE_MISMATCH = "boundary_coverage_mismatch"
    EVIDENCE_INVALID = "evidence_invalid"
    EVIDENCE_IDENTITY_MISMATCH = "evidence_identity_mismatch"
    RUNNER_UNTRUSTED = "runner_untrusted"
    CASE_COVERAGE_MISMATCH = "case_coverage_mismatch"
    CASE_DUPLICATE = "case_duplicate"
    CASE_DEFINITION_MISMATCH = "case_definition_mismatch"
    BASELINE_IDENTITY_MISMATCH = "baseline_identity_mismatch"
    BASELINE_NOT_SECURE = "baseline_not_secure"
    SECURITY_REGRESSION = "security_regression"
    SAFE_TASK_REGRESSION = "safe_task_regression"


class AssuranceRejected(ValueError):
    def __init__(self, reason: AssuranceRejectReason, message: str, *, case_id: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.case_id = case_id


@dataclass(frozen=True)
class AssuranceCase:
    case_id: str
    boundary: str
    attack_class: str
    severity: AssuranceSeverity
    expectation: AssuranceExpectation
    invariant: str


@dataclass(frozen=True)
class AssuranceCorpus:
    corpus_id: str
    version: str
    cases: tuple[AssuranceCase, ...]
    schema_version: str = P6A_CORPUS_SCHEMA_VERSION


@dataclass(frozen=True)
class CaseObservation:
    case_id: str
    case_definition_sha256: str
    observed_outcome: AssuranceExpectation


@dataclass(frozen=True)
class ReleaseAssuranceEvidence:
    release_id: str
    commit_sha: str
    package_version: str
    corpus_sha256: str
    runner_id: str
    results: tuple[CaseObservation, ...]
    schema_version: str = P6A_EVIDENCE_SCHEMA_VERSION


@dataclass(frozen=True)
class AssuranceRequest:
    candidate_release_id: str
    candidate_commit_sha: str
    candidate_package_version: str
    corpus_sha256: str


@dataclass(frozen=True)
class AssurancePolicy:
    expected_corpus_sha256: str
    baseline_release_id: str
    baseline_commit_sha: str
    baseline_package_version: str
    trusted_runner_ids: frozenset[str]
    required_boundaries: frozenset[str]
    max_regressions: int = 0
    max_safe_task_regressions: int = 0


@dataclass(frozen=True)
class VerifiedAssuranceEvidence:
    candidate_release_id: str
    candidate_commit_sha: str
    candidate_package_version: str
    baseline_release_id: str
    baseline_commit_sha: str
    corpus_id: str
    corpus_version: str
    corpus_sha256: str
    case_count: int
    attack_case_count: int
    safe_task_case_count: int
    regression_count: int
    safe_task_regression_count: int
    passed_case_ids: tuple[str, ...]
    evidence_sha256: str
    exact_case_coverage_verified: bool = True
    case_definitions_verified: bool = True
    required_boundaries_verified: bool = True
    baseline_verified: bool = True
    candidate_verified: bool = True
    aggregate_score_only: bool = False
    formal_verification: bool = False
    exhaustive_attack_coverage: bool = False
    production_ci_attestation: bool = False
    network_operations: int = 0
    policy_version: str = P6A_ASSURANCE_POLICY_VERSION
    assurance_mode: str = P6A_ASSURANCE_MODE


def _reject(reason: AssuranceRejectReason, message: str, *, case_id: str | None = None) -> None:
    raise AssuranceRejected(reason, message, case_id=case_id)


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def canonical_case_bytes(case: AssuranceCase) -> bytes:
    return json.dumps({
        "attack_class": case.attack_class,
        "boundary": case.boundary,
        "case_id": case.case_id,
        "expectation": case.expectation.value,
        "invariant": case.invariant,
        "severity": case.severity.value,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def case_definition_digest(case: AssuranceCase) -> str:
    return hashlib.sha256(canonical_case_bytes(case)).hexdigest()


def canonical_corpus_bytes(corpus: AssuranceCorpus) -> bytes:
    document = {
        "cases": [json.loads(canonical_case_bytes(case).decode("utf-8")) for case in sorted(corpus.cases, key=lambda item: item.case_id)],
        "corpus_id": corpus.corpus_id,
        "schema_version": corpus.schema_version,
        "version": corpus.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def corpus_digest(corpus: AssuranceCorpus) -> str:
    return hashlib.sha256(canonical_corpus_bytes(corpus)).hexdigest()


def canonical_release_evidence_bytes(evidence: ReleaseAssuranceEvidence) -> bytes:
    document = {
        "commit_sha": evidence.commit_sha.casefold(),
        "corpus_sha256": evidence.corpus_sha256.casefold(),
        "package_version": evidence.package_version,
        "release_id": evidence.release_id,
        "results": [{
            "case_definition_sha256": item.case_definition_sha256.casefold(),
            "case_id": item.case_id,
            "observed_outcome": item.observed_outcome.value if isinstance(item.observed_outcome, AssuranceExpectation) else str(item.observed_outcome),
        } for item in sorted(evidence.results, key=lambda item: item.case_id)],
        "runner_id": evidence.runner_id,
        "schema_version": evidence.schema_version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def release_evidence_digest(evidence: ReleaseAssuranceEvidence) -> str:
    return hashlib.sha256(canonical_release_evidence_bytes(evidence)).hexdigest()


def _validate_corpus(corpus: AssuranceCorpus, policy: AssurancePolicy) -> dict[str, AssuranceCase]:
    if corpus.schema_version != P6A_CORPUS_SCHEMA_VERSION or not corpus.corpus_id or not corpus.version or not corpus.cases:
        _reject(AssuranceRejectReason.CORPUS_INVALID, "assurance corpus metadata is invalid")
    case_map: dict[str, AssuranceCase] = {}
    for case in corpus.cases:
        if not case.case_id or not case.boundary or not case.attack_class or not case.invariant or not isinstance(case.severity, AssuranceSeverity) or not isinstance(case.expectation, AssuranceExpectation):
            _reject(AssuranceRejectReason.CORPUS_INVALID, "assurance corpus contains an invalid case definition", case_id=case.case_id or None)
        if case.case_id in case_map:
            _reject(AssuranceRejectReason.CORPUS_INVALID, "assurance corpus contains duplicate case IDs", case_id=case.case_id)
        case_map[case.case_id] = case
    actual_digest = corpus_digest(corpus)
    expected_digest = policy.expected_corpus_sha256.casefold()
    if not _is_sha256(expected_digest) or not hmac.compare_digest(actual_digest, expected_digest):
        _reject(AssuranceRejectReason.CORPUS_DIGEST_MISMATCH, "assurance corpus does not match the policy-pinned digest")
    actual_boundaries = frozenset(case.boundary for case in corpus.cases)
    if not policy.required_boundaries or not policy.required_boundaries.issubset(actual_boundaries):
        _reject(AssuranceRejectReason.BOUNDARY_COVERAGE_MISMATCH, "versioned assurance corpus does not cover every policy-required boundary")
    if policy.max_regressions < 0 or policy.max_safe_task_regressions < 0:
        _reject(AssuranceRejectReason.CORPUS_INVALID, "regression budgets may not be negative")
    return case_map


def _validate_evidence(*, evidence: ReleaseAssuranceEvidence, corpus_sha256: str, case_map: dict[str, AssuranceCase], trusted_runner_ids: frozenset[str]) -> dict[str, CaseObservation]:
    if evidence.schema_version != P6A_EVIDENCE_SCHEMA_VERSION or not evidence.release_id or not evidence.package_version or not _is_sha256(evidence.commit_sha) or not _is_sha256(evidence.corpus_sha256):
        _reject(AssuranceRejectReason.EVIDENCE_INVALID, "release assurance evidence metadata is invalid")
    if not hmac.compare_digest(evidence.corpus_sha256.casefold(), corpus_sha256.casefold()):
        _reject(AssuranceRejectReason.EVIDENCE_IDENTITY_MISMATCH, "release evidence does not bind to the exact versioned corpus digest")
    if evidence.runner_id not in trusted_runner_ids:
        _reject(AssuranceRejectReason.RUNNER_UNTRUSTED, "assurance evidence was produced by an untrusted deterministic runner ID")
    observations: dict[str, CaseObservation] = {}
    for result in evidence.results:
        if result.case_id in observations:
            _reject(AssuranceRejectReason.CASE_DUPLICATE, "release evidence contains a duplicate case result", case_id=result.case_id)
        if result.case_id not in case_map:
            _reject(AssuranceRejectReason.CASE_COVERAGE_MISMATCH, "release evidence contains an unknown case ID", case_id=result.case_id)
        if not isinstance(result.observed_outcome, AssuranceExpectation):
            _reject(AssuranceRejectReason.EVIDENCE_INVALID, "case result has an invalid observed outcome", case_id=result.case_id)
        expected_definition_digest = case_definition_digest(case_map[result.case_id])
        if not _is_sha256(result.case_definition_sha256) or not hmac.compare_digest(result.case_definition_sha256.casefold(), expected_definition_digest):
            _reject(AssuranceRejectReason.CASE_DEFINITION_MISMATCH, "case result does not bind to the immutable case definition", case_id=result.case_id)
        observations[result.case_id] = result
    if set(observations) != set(case_map):
        _reject(AssuranceRejectReason.CASE_COVERAGE_MISMATCH, "release evidence must contain exact one-to-one corpus case coverage")
    return observations


def _mismatching_cases(case_map: dict[str, AssuranceCase], observations: dict[str, CaseObservation]) -> list[AssuranceCase]:
    return [case for case_id, case in sorted(case_map.items()) if observations[case_id].observed_outcome != case.expectation]


class ContinuousSecurityAssuranceGate:
    """Fail closed on cross-boundary security regressions for an exact corpus release.

    This lab validates deterministic evidence. It does not execute attacks, orchestrate CI,
    attest runners, or claim that the corpus is exhaustive.
    """

    def __init__(self, *, corpus: AssuranceCorpus, policy: AssurancePolicy) -> None:
        self._corpus = corpus
        self._policy = policy

    def evaluate(self, *, request: AssuranceRequest, baseline: ReleaseAssuranceEvidence, candidate: ReleaseAssuranceEvidence) -> VerifiedAssuranceEvidence:
        case_map = _validate_corpus(self._corpus, self._policy)
        exact_corpus_sha256 = corpus_digest(self._corpus)
        if request.corpus_sha256.casefold() != exact_corpus_sha256 or not _is_sha256(request.candidate_commit_sha) or not request.candidate_release_id or not request.candidate_package_version:
            _reject(AssuranceRejectReason.EVIDENCE_IDENTITY_MISMATCH, "assurance request does not bind to the exact candidate/corpus identity")
        baseline_results = _validate_evidence(evidence=baseline, corpus_sha256=exact_corpus_sha256, case_map=case_map, trusted_runner_ids=self._policy.trusted_runner_ids)
        if baseline.release_id != self._policy.baseline_release_id or baseline.commit_sha.casefold() != self._policy.baseline_commit_sha.casefold() or baseline.package_version != self._policy.baseline_package_version:
            _reject(AssuranceRejectReason.BASELINE_IDENTITY_MISMATCH, "baseline evidence does not match the policy-pinned release identity")
        baseline_mismatches = _mismatching_cases(case_map, baseline_results)
        if baseline_mismatches:
            _reject(AssuranceRejectReason.BASELINE_NOT_SECURE, "policy baseline does not satisfy every corpus expectation", case_id=baseline_mismatches[0].case_id)
        candidate_results = _validate_evidence(evidence=candidate, corpus_sha256=exact_corpus_sha256, case_map=case_map, trusted_runner_ids=self._policy.trusted_runner_ids)
        if candidate.release_id != request.candidate_release_id or candidate.commit_sha.casefold() != request.candidate_commit_sha.casefold() or candidate.package_version != request.candidate_package_version:
            _reject(AssuranceRejectReason.EVIDENCE_IDENTITY_MISMATCH, "candidate evidence does not match the requested release identity")
        mismatches = _mismatching_cases(case_map, candidate_results)
        attack_regressions = [case for case in mismatches if case.expectation == AssuranceExpectation.BLOCK]
        safe_task_regressions = [case for case in mismatches if case.expectation == AssuranceExpectation.ALLOW]
        if len(attack_regressions) > self._policy.max_regressions:
            _reject(AssuranceRejectReason.SECURITY_REGRESSION, "candidate release regressed one or more attack-blocking expectations", case_id=attack_regressions[0].case_id)
        if len(safe_task_regressions) > self._policy.max_safe_task_regressions:
            _reject(AssuranceRejectReason.SAFE_TASK_REGRESSION, "candidate release regressed one or more benign safe-task expectations", case_id=safe_task_regressions[0].case_id)
        passed_case_ids = tuple(sorted(case_map))
        evidence_document = {
            "baseline_evidence_sha256": release_evidence_digest(baseline),
            "candidate_evidence_sha256": release_evidence_digest(candidate),
            "corpus_sha256": exact_corpus_sha256,
            "policy_version": P6A_ASSURANCE_POLICY_VERSION,
            "request": asdict(request),
        }
        evidence_sha256 = hashlib.sha256(json.dumps(evidence_document, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        return VerifiedAssuranceEvidence(
            candidate_release_id=candidate.release_id,
            candidate_commit_sha=candidate.commit_sha.casefold(),
            candidate_package_version=candidate.package_version,
            baseline_release_id=baseline.release_id,
            baseline_commit_sha=baseline.commit_sha.casefold(),
            corpus_id=self._corpus.corpus_id,
            corpus_version=self._corpus.version,
            corpus_sha256=exact_corpus_sha256,
            case_count=len(case_map),
            attack_case_count=sum(1 for case in case_map.values() if case.expectation == AssuranceExpectation.BLOCK),
            safe_task_case_count=sum(1 for case in case_map.values() if case.expectation == AssuranceExpectation.ALLOW),
            regression_count=len(attack_regressions),
            safe_task_regression_count=len(safe_task_regressions),
            passed_case_ids=passed_case_ids,
            evidence_sha256=evidence_sha256,
        )
