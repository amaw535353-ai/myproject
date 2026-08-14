from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping

from .corpus_evolution import VerifiedCorpusEvolution
from .regression import (
    P6A_CORPUS_SCHEMA_VERSION,
    AssuranceCase,
    AssuranceCorpus,
    AssuranceExpectation,
    AssuranceSeverity,
    corpus_digest,
)
from .waiver_governance import VerifiedWaiverGovernance


P6D_POSTURE_POLICY_VERSION = "ai-security-posture-control-coverage-v1"
P6D_CONTROL_CATALOG_SCHEMA_VERSION = "aegis-ai-security-control-catalog-v1"
P6D_POSTURE_EVIDENCE_SCHEMA_VERSION = "aegis-ai-security-posture-evidence-v1"
P6D_POSTURE_MODE = "deterministic-evidence-derived-control-posture-v1"


class ControlStatus(StrEnum):
    SATISFIED = "satisfied"
    EXCEPTIONED = "exceptioned"
    NOT_EVALUATED = "not_evaluated"


class PostureRating(StrEnum):
    GREEN = "green"
    AMBER = "amber"
    RED = "red"


class PostureRejectReason(StrEnum):
    CATALOG_INVALID = "catalog_invalid"
    CATALOG_DIGEST_MISMATCH = "catalog_digest_mismatch"
    CONTROL_DUPLICATE = "control_duplicate"
    CONTROL_MAPPING_INVALID = "control_mapping_invalid"
    REQUIRED_CONTROL_MISSING = "required_control_missing"
    REQUIRED_RISK_DOMAIN_MISSING = "required_risk_domain_missing"
    REQUEST_INVALID = "request_invalid"
    RELEASE_IDENTITY_MISMATCH = "release_identity_mismatch"
    CORPUS_INVALID = "corpus_invalid"
    CORPUS_DIGEST_MISMATCH = "corpus_digest_mismatch"
    WAIVER_GOVERNANCE_UNVERIFIED = "waiver_governance_unverified"
    CORPUS_EVOLUTION_UNVERIFIED = "corpus_evolution_unverified"
    EVIDENCE_BINDING_MISMATCH = "evidence_binding_mismatch"
    WAIVER_SCOPE_MISMATCH = "waiver_scope_mismatch"
    UPSTREAM_COUNT_MISMATCH = "upstream_count_mismatch"
    DECLARED_POSTURE_MISMATCH = "declared_posture_mismatch"


class SecurityPostureRejected(ValueError):
    def __init__(
        self,
        reason: PostureRejectReason,
        message: str,
        *,
        control_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.control_id = control_id


@dataclass(frozen=True)
class SecurityControlObjective:
    control_id: str
    risk_domain: str
    title: str
    severity: AssuranceSeverity
    mapped_case_ids: tuple[str, ...]
    required_boundaries: tuple[str, ...]
    exception_permitted: bool = True


@dataclass(frozen=True)
class SecurityControlCatalog:
    catalog_id: str
    version: str
    controls: tuple[SecurityControlObjective, ...]
    schema_version: str = P6D_CONTROL_CATALOG_SCHEMA_VERSION


@dataclass(frozen=True)
class SecurityPostureRequest:
    candidate_release_id: str
    candidate_commit_sha: str
    candidate_package_version: str
    corpus_sha256: str
    control_catalog_sha256: str
    waiver_governance_evidence_sha256: str
    corpus_evolution_evidence_sha256: str
    declared_rating: PostureRating | None = None


@dataclass(frozen=True)
class SecurityPosturePolicy:
    expected_control_catalog_sha256: str
    required_control_ids: frozenset[str]
    required_risk_domains: frozenset[str]
    critical_exception_is_red: bool = True
    high_or_critical_not_evaluated_is_red: bool = True


@dataclass(frozen=True)
class ControlPostureAssessment:
    control_id: str
    risk_domain: str
    severity: AssuranceSeverity
    status: ControlStatus
    mapped_case_ids: tuple[str, ...]
    exception_case_ids: tuple[str, ...]
    missing_case_ids: tuple[str, ...]
    missing_boundaries: tuple[str, ...]
    evidence_sha256: str


@dataclass(frozen=True)
class VerifiedSecurityPosture:
    candidate_release_id: str
    candidate_commit_sha: str
    candidate_package_version: str
    corpus_id: str
    corpus_version: str
    corpus_sha256: str
    control_catalog_id: str
    control_catalog_version: str
    control_catalog_sha256: str
    waiver_governance_evidence_sha256: str
    corpus_evolution_evidence_sha256: str
    overall_rating: PostureRating
    control_count: int
    satisfied_control_ids: tuple[str, ...]
    exceptioned_control_ids: tuple[str, ...]
    not_evaluated_control_ids: tuple[str, ...]
    assessments: tuple[ControlPostureAssessment, ...]
    posture_evidence_sha256: str
    exact_release_identity_verified: bool = True
    exact_upstream_evidence_binding_verified: bool = True
    control_catalog_verified: bool = True
    status_derived_from_evidence: bool = True
    missing_evidence_visible: bool = True
    exception_scope_visible: bool = True
    caller_declared_green_trusted: bool = False
    regulatory_certification: bool = False
    production_grc_integration: bool = False
    compliance_attestation: bool = False
    external_audit_evidence: bool = False
    network_operations: int = 0
    schema_version: str = P6D_POSTURE_EVIDENCE_SCHEMA_VERSION
    policy_version: str = P6D_POSTURE_POLICY_VERSION
    posture_mode: str = P6D_POSTURE_MODE


def _reject(
    reason: PostureRejectReason,
    message: str,
    *,
    control_id: str | None = None,
) -> None:
    raise SecurityPostureRejected(reason, message, control_id=control_id)


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def _canonical_control(control: SecurityControlObjective) -> dict[str, object]:
    return {
        "control_id": control.control_id,
        "exception_permitted": control.exception_permitted,
        "mapped_case_ids": sorted(control.mapped_case_ids),
        "required_boundaries": sorted(control.required_boundaries),
        "risk_domain": control.risk_domain,
        "severity": control.severity.value
        if isinstance(control.severity, AssuranceSeverity)
        else str(control.severity),
        "title": control.title,
    }


def canonical_control_catalog_bytes(catalog: SecurityControlCatalog) -> bytes:
    document = {
        "catalog_id": catalog.catalog_id,
        "controls": [
            _canonical_control(control)
            for control in sorted(catalog.controls, key=lambda item: item.control_id)
        ],
        "schema_version": catalog.schema_version,
        "version": catalog.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def control_catalog_digest(catalog: SecurityControlCatalog) -> str:
    return hashlib.sha256(canonical_control_catalog_bytes(catalog)).hexdigest()


def _validate_catalog(
    catalog: SecurityControlCatalog,
    policy: SecurityPosturePolicy,
) -> dict[str, SecurityControlObjective]:
    if (
        catalog.schema_version != P6D_CONTROL_CATALOG_SCHEMA_VERSION
        or not catalog.catalog_id
        or not catalog.version
        or not catalog.controls
    ):
        _reject(PostureRejectReason.CATALOG_INVALID, "control catalog metadata is invalid")
    controls: dict[str, SecurityControlObjective] = {}
    for control in catalog.controls:
        if (
            not control.control_id
            or not control.risk_domain
            or not control.title
            or not isinstance(control.severity, AssuranceSeverity)
            or not control.mapped_case_ids
            or not control.required_boundaries
        ):
            _reject(
                PostureRejectReason.CONTROL_MAPPING_INVALID,
                "control objective metadata is invalid",
                control_id=control.control_id or None,
            )
        if control.control_id in controls:
            _reject(
                PostureRejectReason.CONTROL_DUPLICATE,
                "control catalog contains duplicate control IDs",
                control_id=control.control_id,
            )
        if (
            len(set(control.mapped_case_ids)) != len(control.mapped_case_ids)
            or len(set(control.required_boundaries)) != len(control.required_boundaries)
            or any(not item for item in control.mapped_case_ids)
            or any(not item for item in control.required_boundaries)
        ):
            _reject(
                PostureRejectReason.CONTROL_MAPPING_INVALID,
                "control mappings contain duplicates or empty identifiers",
                control_id=control.control_id,
            )
        controls[control.control_id] = control

    actual_digest = control_catalog_digest(catalog)
    if (
        not _is_sha256(policy.expected_control_catalog_sha256)
        or not hmac.compare_digest(
            actual_digest,
            policy.expected_control_catalog_sha256.casefold(),
        )
    ):
        _reject(
            PostureRejectReason.CATALOG_DIGEST_MISMATCH,
            "control catalog does not match the policy-pinned digest",
        )
    missing_controls = sorted(policy.required_control_ids - set(controls))
    if missing_controls:
        _reject(
            PostureRejectReason.REQUIRED_CONTROL_MISSING,
            "control catalog omits a policy-required control",
            control_id=missing_controls[0],
        )
    present_domains = {control.risk_domain for control in controls.values()}
    if not policy.required_risk_domains.issubset(present_domains):
        _reject(
            PostureRejectReason.REQUIRED_RISK_DOMAIN_MISSING,
            "control catalog omits a policy-required risk domain",
        )
    return controls


def _validate_corpus(corpus: AssuranceCorpus) -> dict[str, AssuranceCase]:
    if (
        corpus.schema_version != P6A_CORPUS_SCHEMA_VERSION
        or not corpus.corpus_id
        or not corpus.version
        or not corpus.cases
    ):
        _reject(PostureRejectReason.CORPUS_INVALID, "assurance corpus metadata is invalid")
    cases: dict[str, AssuranceCase] = {}
    for case in corpus.cases:
        if (
            not case.case_id
            or not case.boundary
            or not case.attack_class
            or not case.invariant
            or not isinstance(case.severity, AssuranceSeverity)
            or not isinstance(case.expectation, AssuranceExpectation)
        ):
            _reject(
                PostureRejectReason.CORPUS_INVALID,
                "assurance corpus contains an invalid case",
            )
        if case.case_id in cases:
            _reject(
                PostureRejectReason.CORPUS_INVALID,
                "assurance corpus contains duplicate case IDs",
            )
        cases[case.case_id] = case
    return cases


def _validate_request(
    request: SecurityPostureRequest,
    *,
    catalog_sha256: str,
    corpus_sha256: str,
    waiver_governance: VerifiedWaiverGovernance,
    corpus_evolution: VerifiedCorpusEvolution,
) -> None:
    if (
        not request.candidate_release_id
        or not _is_sha256(request.candidate_commit_sha)
        or not request.candidate_package_version
        or not _is_sha256(request.corpus_sha256)
        or not _is_sha256(request.control_catalog_sha256)
        or not _is_sha256(request.waiver_governance_evidence_sha256)
        or not _is_sha256(request.corpus_evolution_evidence_sha256)
        or (
            request.declared_rating is not None
            and not isinstance(request.declared_rating, PostureRating)
        )
    ):
        _reject(PostureRejectReason.REQUEST_INVALID, "security posture request metadata is invalid")
    if (
        request.candidate_release_id != waiver_governance.candidate_release_id
        or request.candidate_commit_sha.casefold()
        != waiver_governance.candidate_commit_sha.casefold()
        or request.candidate_package_version
        != waiver_governance.candidate_package_version
    ):
        _reject(
            PostureRejectReason.RELEASE_IDENTITY_MISMATCH,
            "posture request does not match the exact governed candidate release identity",
        )
    if not hmac.compare_digest(request.corpus_sha256.casefold(), corpus_sha256):
        _reject(
            PostureRejectReason.CORPUS_DIGEST_MISMATCH,
            "posture request does not bind to the exact assurance corpus digest",
        )
    if not hmac.compare_digest(
        request.control_catalog_sha256.casefold(),
        catalog_sha256,
    ):
        _reject(
            PostureRejectReason.CATALOG_DIGEST_MISMATCH,
            "posture request does not bind to the exact control catalog digest",
        )
    if (
        not hmac.compare_digest(
            request.waiver_governance_evidence_sha256.casefold(),
            waiver_governance.governance_evidence_sha256.casefold(),
        )
        or not hmac.compare_digest(
            request.corpus_evolution_evidence_sha256.casefold(),
            corpus_evolution.evidence_sha256.casefold(),
        )
    ):
        _reject(
            PostureRejectReason.EVIDENCE_BINDING_MISMATCH,
            "posture request does not bind to exact upstream assurance evidence digests",
        )


def _validate_waiver_governance(
    waiver: VerifiedWaiverGovernance,
    *,
    corpus_sha256: str,
) -> None:
    required_flags = (
        waiver.invariant_definitions_verified,
        waiver.invariant_ownership_verified,
        waiver.exact_regression_scope_verified,
        waiver.expiry_verified,
        waiver.approval_roles_verified,
        waiver.severity_downgrade_prevented,
    )
    if (
        not all(required_flags)
        or not _is_sha256(waiver.candidate_commit_sha)
        or not _is_sha256(waiver.corpus_sha256)
        or not _is_sha256(waiver.registry_sha256)
        or not _is_sha256(waiver.candidate_evidence_sha256)
        or not _is_sha256(waiver.governance_evidence_sha256)
    ):
        _reject(
            PostureRejectReason.WAIVER_GOVERNANCE_UNVERIFIED,
            "waiver governance handle is incomplete or no longer verified",
        )
    if not hmac.compare_digest(waiver.corpus_sha256.casefold(), corpus_sha256):
        _reject(
            PostureRejectReason.EVIDENCE_BINDING_MISMATCH,
            "waiver governance evidence is bound to a different assurance corpus",
        )
    regressions = tuple(waiver.regression_case_ids)
    waived_cases = tuple(waiver.approved_waived_case_ids)
    waiver_ids = tuple(waiver.approved_waiver_ids)
    if (
        len(set(regressions)) != len(regressions)
        or len(set(waived_cases)) != len(waived_cases)
        or len(set(waiver_ids)) != len(waiver_ids)
        or not set(waived_cases).issubset(set(regressions))
        or waiver.waiver_count != len(waived_cases)
        or waiver.waiver_count != len(waiver_ids)
        or (
            waiver.high_waiver_count
            + waiver.medium_waiver_count
            + waiver.low_waiver_count
            + waiver.critical_waiver_count
            != waiver.waiver_count
        )
        or (not waiver.critical_waivers_permitted and waiver.critical_waiver_count != 0)
    ):
        _reject(
            PostureRejectReason.WAIVER_SCOPE_MISMATCH,
            "waiver governance summary has inconsistent regression or waiver scope",
        )


def _validate_corpus_evolution(
    evolution: VerifiedCorpusEvolution,
    *,
    corpus: AssuranceCorpus,
    corpus_sha256: str,
    case_map: Mapping[str, AssuranceCase],
) -> None:
    required_flags = (
        evolution.exact_change_coverage_verified,
        evolution.removal_tombstones_verified,
        evolution.coverage_floors_verified,
        evolution.weakening_prevented,
        evolution.silent_coverage_shrink_prevented,
    )
    if (
        not all(required_flags)
        or not _is_sha256(evolution.baseline_corpus_sha256)
        or not _is_sha256(evolution.candidate_corpus_sha256)
        or not _is_sha256(evolution.change_manifest_sha256)
        or not _is_sha256(evolution.evidence_sha256)
    ):
        _reject(
            PostureRejectReason.CORPUS_EVOLUTION_UNVERIFIED,
            "corpus evolution handle is incomplete or no longer verified",
        )
    if (
        evolution.corpus_id != corpus.corpus_id
        or evolution.candidate_version != corpus.version
        or not hmac.compare_digest(
            evolution.candidate_corpus_sha256.casefold(),
            corpus_sha256,
        )
    ):
        _reject(
            PostureRejectReason.EVIDENCE_BINDING_MISMATCH,
            "corpus evolution evidence does not bind to the current assurance corpus",
        )
    block_cases = [
        case for case in case_map.values()
        if case.expectation == AssuranceExpectation.BLOCK
    ]
    allow_cases = [
        case for case in case_map.values()
        if case.expectation == AssuranceExpectation.ALLOW
    ]
    critical = sum(case.severity == AssuranceSeverity.CRITICAL for case in block_cases)
    high_or_critical = sum(
        case.severity in {AssuranceSeverity.HIGH, AssuranceSeverity.CRITICAL}
        for case in block_cases
    )
    if (
        evolution.candidate_case_count != len(case_map)
        or evolution.candidate_block_case_count != len(block_cases)
        or evolution.candidate_allow_case_count != len(allow_cases)
        or evolution.candidate_critical_block_count != critical
        or evolution.candidate_high_or_critical_block_count != high_or_critical
    ):
        _reject(
            PostureRejectReason.UPSTREAM_COUNT_MISMATCH,
            "corpus evolution summary counts do not match the current corpus",
        )


def _assessment_digest(
    *,
    control: SecurityControlObjective,
    status: ControlStatus,
    exception_case_ids: tuple[str, ...],
    missing_case_ids: tuple[str, ...],
    missing_boundaries: tuple[str, ...],
    corpus_sha256: str,
    waiver_evidence_sha256: str,
    evolution_evidence_sha256: str,
) -> str:
    document = {
        "control": _canonical_control(control),
        "corpus_sha256": corpus_sha256,
        "corpus_evolution_evidence_sha256": evolution_evidence_sha256.casefold(),
        "exception_case_ids": list(exception_case_ids),
        "missing_boundaries": list(missing_boundaries),
        "missing_case_ids": list(missing_case_ids),
        "status": status.value,
        "waiver_governance_evidence_sha256": waiver_evidence_sha256.casefold(),
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


class AISecurityPostureReporter:
    """Derive release control posture from exact assurance evidence.

    The reporter is deterministic and inert. It does not certify compliance, query
    external GRC systems, or trust caller-declared posture labels.
    """

    def __init__(
        self,
        *,
        catalog: SecurityControlCatalog,
        policy: SecurityPosturePolicy,
    ) -> None:
        self._catalog = catalog
        self._policy = policy

    def evaluate(
        self,
        *,
        request: SecurityPostureRequest,
        corpus: AssuranceCorpus,
        waiver_governance: VerifiedWaiverGovernance,
        corpus_evolution: VerifiedCorpusEvolution,
    ) -> VerifiedSecurityPosture:
        controls = _validate_catalog(self._catalog, self._policy)
        case_map = _validate_corpus(corpus)
        exact_catalog_sha256 = control_catalog_digest(self._catalog)
        exact_corpus_sha256 = corpus_digest(corpus)

        _validate_waiver_governance(
            waiver_governance,
            corpus_sha256=exact_corpus_sha256,
        )
        _validate_corpus_evolution(
            corpus_evolution,
            corpus=corpus,
            corpus_sha256=exact_corpus_sha256,
            case_map=case_map,
        )
        _validate_request(
            request,
            catalog_sha256=exact_catalog_sha256,
            corpus_sha256=exact_corpus_sha256,
            waiver_governance=waiver_governance,
            corpus_evolution=corpus_evolution,
        )

        regression_cases = set(waiver_governance.regression_case_ids)
        waived_cases = set(waiver_governance.approved_waived_case_ids)
        unknown_regressions = regression_cases - set(case_map)
        unknown_waivers = waived_cases - set(case_map)
        if unknown_regressions or unknown_waivers:
            _reject(
                PostureRejectReason.WAIVER_SCOPE_MISMATCH,
                "upstream regression or waiver scope references a case outside the current corpus",
            )

        corpus_boundaries = {case.boundary for case in case_map.values()}
        assessments: list[ControlPostureAssessment] = []
        for control in sorted(controls.values(), key=lambda item: item.control_id):
            missing_case_ids = tuple(
                sorted(case_id for case_id in control.mapped_case_ids if case_id not in case_map)
            )
            missing_boundaries = tuple(
                sorted(boundary for boundary in control.required_boundaries if boundary not in corpus_boundaries)
            )
            exception_case_ids = tuple(
                sorted(case_id for case_id in control.mapped_case_ids if case_id in waived_cases)
            )
            if missing_case_ids or missing_boundaries:
                status = ControlStatus.NOT_EVALUATED
            elif exception_case_ids:
                status = ControlStatus.EXCEPTIONED
            else:
                status = ControlStatus.SATISFIED

            if exception_case_ids and not control.exception_permitted:
                status = ControlStatus.EXCEPTIONED

            evidence_sha256 = _assessment_digest(
                control=control,
                status=status,
                exception_case_ids=exception_case_ids,
                missing_case_ids=missing_case_ids,
                missing_boundaries=missing_boundaries,
                corpus_sha256=exact_corpus_sha256,
                waiver_evidence_sha256=waiver_governance.governance_evidence_sha256,
                evolution_evidence_sha256=corpus_evolution.evidence_sha256,
            )
            assessments.append(
                ControlPostureAssessment(
                    control_id=control.control_id,
                    risk_domain=control.risk_domain,
                    severity=control.severity,
                    status=status,
                    mapped_case_ids=tuple(sorted(control.mapped_case_ids)),
                    exception_case_ids=exception_case_ids,
                    missing_case_ids=missing_case_ids,
                    missing_boundaries=missing_boundaries,
                    evidence_sha256=evidence_sha256,
                )
            )

        red = False
        amber = False
        for assessment in assessments:
            if assessment.status == ControlStatus.EXCEPTIONED:
                control = controls[assessment.control_id]
                if (
                    not control.exception_permitted
                    or (
                        self._policy.critical_exception_is_red
                        and assessment.severity == AssuranceSeverity.CRITICAL
                    )
                ):
                    red = True
                else:
                    amber = True
            elif assessment.status == ControlStatus.NOT_EVALUATED:
                if (
                    self._policy.high_or_critical_not_evaluated_is_red
                    and assessment.severity
                    in {AssuranceSeverity.HIGH, AssuranceSeverity.CRITICAL}
                ):
                    red = True
                else:
                    amber = True

        overall_rating = (
            PostureRating.RED
            if red
            else PostureRating.AMBER
            if amber
            else PostureRating.GREEN
        )
        if (
            request.declared_rating is not None
            and request.declared_rating != overall_rating
        ):
            _reject(
                PostureRejectReason.DECLARED_POSTURE_MISMATCH,
                "caller-declared posture does not match evidence-derived posture",
            )

        satisfied_control_ids = tuple(
            item.control_id
            for item in assessments
            if item.status == ControlStatus.SATISFIED
        )
        exceptioned_control_ids = tuple(
            item.control_id
            for item in assessments
            if item.status == ControlStatus.EXCEPTIONED
        )
        not_evaluated_control_ids = tuple(
            item.control_id
            for item in assessments
            if item.status == ControlStatus.NOT_EVALUATED
        )
        evidence_document = {
            "assessments": [
                {
                    "control_id": item.control_id,
                    "evidence_sha256": item.evidence_sha256,
                    "status": item.status.value,
                }
                for item in assessments
            ],
            "catalog_sha256": exact_catalog_sha256,
            "corpus_evolution_evidence_sha256": corpus_evolution.evidence_sha256,
            "corpus_sha256": exact_corpus_sha256,
            "overall_rating": overall_rating.value,
            "policy_version": P6D_POSTURE_POLICY_VERSION,
            "release": {
                "commit_sha": request.candidate_commit_sha.casefold(),
                "package_version": request.candidate_package_version,
                "release_id": request.candidate_release_id,
            },
            "waiver_governance_evidence_sha256": waiver_governance.governance_evidence_sha256,
        }
        posture_evidence_sha256 = hashlib.sha256(
            json.dumps(evidence_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        return VerifiedSecurityPosture(
            candidate_release_id=request.candidate_release_id,
            candidate_commit_sha=request.candidate_commit_sha.casefold(),
            candidate_package_version=request.candidate_package_version,
            corpus_id=corpus.corpus_id,
            corpus_version=corpus.version,
            corpus_sha256=exact_corpus_sha256,
            control_catalog_id=self._catalog.catalog_id,
            control_catalog_version=self._catalog.version,
            control_catalog_sha256=exact_catalog_sha256,
            waiver_governance_evidence_sha256=waiver_governance.governance_evidence_sha256,
            corpus_evolution_evidence_sha256=corpus_evolution.evidence_sha256,
            overall_rating=overall_rating,
            control_count=len(assessments),
            satisfied_control_ids=satisfied_control_ids,
            exceptioned_control_ids=exceptioned_control_ids,
            not_evaluated_control_ids=not_evaluated_control_ids,
            assessments=tuple(assessments),
            posture_evidence_sha256=posture_evidence_sha256,
        )
