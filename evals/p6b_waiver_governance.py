from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from typing import Any

from aegis.assurance.regression import (
    AssuranceCase,
    AssuranceCorpus,
    AssuranceExpectation,
    AssuranceSeverity,
    CaseObservation,
    ReleaseAssuranceEvidence,
    case_definition_digest,
    corpus_digest,
    release_evidence_digest,
)
from aegis.assurance.waiver_governance import (
    InvariantRecord,
    InvariantRegistry,
    SecurityInvariantWaiverGovernanceGate,
    SecurityWaiver,
    WaiverApproval,
    WaiverGovernancePolicy,
    WaiverGovernanceRejectReason,
    WaiverGovernanceRejected,
    WaiverGovernanceRequest,
    invariant_registry_digest,
)
from aegis.vulnerable.waiver_governance import VulnerableDeclaredWaiverGate


CANDIDATE_RELEASE = "aegisdesk-v0.56.0"
CANDIDATE_COMMIT = "c" * 64
CANDIDATE_VERSION = "0.56.0"
RUNNER_ID = "aegis-deterministic-assurance-runner-v1"
ALT_RUNNER_ID = "aegis-secondary-assurance-runner-v1"
EVALUATED_AT_EPOCH = 2_000_000_000


def build_corpus() -> AssuranceCorpus:
    cases = (
        AssuranceCase("P6A-C01", "p5a-artifact-provenance", "artifact-digest-substitution", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "signed artifact payload remains digest-bound"),
        AssuranceCase("P6A-C02", "p5b-package-provenance", "transitive-adapter-substitution", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "package closure remains exact and publisher-authorized"),
        AssuranceCase("P6A-C03", "p5c-registry-acquisition", "mutable-tag-drift", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "mutable aliases cannot escape immutable release pins"),
        AssuranceCase("P6A-C04", "p5d-key-lifecycle", "revoked-signing-key", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "revoked provenance signing keys remain rejected"),
        AssuranceCase("P6A-C05", "p5e-runtime-isolation", "remote-code-request", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "runtime admission continues to deny remote or dynamic code"),
        AssuranceCase("P6A-C06", "p5e-runtime-isolation", "host-capability-escalation", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "runtime admission continues to deny host privilege expansion"),
        AssuranceCase("P6A-C07", "p5f-model-scanning", "poisoning-indicator", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "release-scoped model-content indicators remain policy-gated"),
        AssuranceCase("P6A-C08", "p5f-model-scanning", "backdoor-probe-trigger", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "required backdoor-probe indicators remain below policy thresholds"),
        AssuranceCase("P6A-C09", "p5g-model-privacy", "raw-logit-extraction", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "high-fidelity inference internals remain unavailable"),
        AssuranceCase("P6A-C10", "p5g-model-privacy", "training-canary-leak", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "modeled training canary leakage remains denied"),
        AssuranceCase("P6A-C11", "p5h-deployment-attestation", "environment-measurement-substitution", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "deployment evidence remains bound to policy-pinned measurements"),
        AssuranceCase("P6A-C12", "p5h-deployment-attestation", "stale-attestation-replay", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "stale signed deployment evidence remains unusable"),
        AssuranceCase("P6A-C13", "p5i-serving-response", "telemetry-chain-fork", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "serving telemetry remains sequence and hash-chain bound"),
        AssuranceCase("P6A-C14", "p5i-serving-response", "privacy-budget-abuse", AssuranceSeverity.HIGH, AssuranceExpectation.BLOCK, "serving abuse evidence continues to trigger policy-owned response"),
        AssuranceCase("P6A-C15", "p5i-serving-response", "canary-incident-suppression", AssuranceSeverity.CRITICAL, AssuranceExpectation.BLOCK, "canary-leak incidents cannot be silently downgraded"),
        AssuranceCase("P6A-C16", "p5e-runtime-isolation", "benign-static-runtime-plan", AssuranceSeverity.LOW, AssuranceExpectation.ALLOW, "approved inert runtime plans remain admissible"),
        AssuranceCase("P6A-C17", "p5g-model-privacy", "benign-bounded-answer", AssuranceSeverity.LOW, AssuranceExpectation.ALLOW, "bounded privacy-safe inference remains usable"),
        AssuranceCase("P6A-C18", "p5i-serving-response", "benign-observe-telemetry", AssuranceSeverity.LOW, AssuranceExpectation.ALLOW, "benign telemetry remains non-disruptive"),
    )
    return AssuranceCorpus(
        corpus_id="aegisdesk-cross-boundary-security-corpus",
        version="2026.08-p6a.1",
        cases=cases,
    )


def owner_map(corpus: AssuranceCorpus) -> dict[str, str]:
    return {
        case.case_id: f"owner-{case.boundary.split('-', 1)[0]}-{case.case_id.casefold()}"
        for case in corpus.cases
    }


def build_registry(corpus: AssuranceCorpus) -> InvariantRegistry:
    owners = owner_map(corpus)
    return InvariantRegistry(
        registry_id="aegisdesk-security-invariants",
        version="2026.08-p6b.1",
        corpus_sha256=corpus_digest(corpus),
        records=tuple(
            InvariantRecord(
                case_id=case.case_id,
                case_definition_sha256=case_definition_digest(case),
                owner_id=owners[case.case_id],
                severity=case.severity,
            )
            for case in corpus.cases
        ),
    )


def build_policy(corpus: AssuranceCorpus, registry: InvariantRegistry) -> WaiverGovernancePolicy:
    owners = owner_map(corpus)
    return WaiverGovernancePolicy(
        expected_corpus_sha256=corpus_digest(corpus),
        expected_registry_sha256=invariant_registry_digest(registry),
        expected_owner_by_case=owners,
        trusted_runner_ids=frozenset({RUNNER_ID, ALT_RUNNER_ID}),
        trusted_approvers_by_role={
            "invariant_owner": frozenset(owners.values()),
            "security_lead": frozenset({"sec-lead-1", "sec-lead-2"}),
            "security_reviewer": frozenset({"sec-reviewer-1"}),
            "risk_owner": frozenset({"risk-owner-1"}),
        },
        required_roles_by_severity={
            AssuranceSeverity.CRITICAL: frozenset({"invariant_owner", "security_lead", "risk_owner"}),
            AssuranceSeverity.HIGH: frozenset({"invariant_owner", "security_lead"}),
            AssuranceSeverity.MEDIUM: frozenset({"invariant_owner", "security_reviewer"}),
            AssuranceSeverity.LOW: frozenset({"invariant_owner"}),
        },
        max_waiver_seconds_by_severity={
            AssuranceSeverity.CRITICAL: 86_400,
            AssuranceSeverity.HIGH: 7 * 86_400,
            AssuranceSeverity.MEDIUM: 14 * 86_400,
            AssuranceSeverity.LOW: 30 * 86_400,
        },
        waivable_severities=frozenset({
            AssuranceSeverity.HIGH,
            AssuranceSeverity.MEDIUM,
            AssuranceSeverity.LOW,
        }),
    )


def evidence_for(
    corpus: AssuranceCorpus,
    *,
    overrides: dict[str, AssuranceExpectation] | None = None,
    release_id: str = CANDIDATE_RELEASE,
    commit_sha: str = CANDIDATE_COMMIT,
    package_version: str = CANDIDATE_VERSION,
    runner_id: str = RUNNER_ID,
    result_ids: list[str] | None = None,
    definition_overrides: dict[str, str] | None = None,
) -> ReleaseAssuranceEvidence:
    overrides = overrides or {}
    definition_overrides = definition_overrides or {}
    by_id = {case.case_id: case for case in corpus.cases}
    ids = result_ids or [case.case_id for case in corpus.cases]
    return ReleaseAssuranceEvidence(
        release_id=release_id,
        commit_sha=commit_sha,
        package_version=package_version,
        corpus_sha256=corpus_digest(corpus),
        runner_id=runner_id,
        results=tuple(
            CaseObservation(
                case_id=case_id,
                case_definition_sha256=definition_overrides.get(
                    case_id,
                    case_definition_digest(by_id[case_id]),
                ),
                observed_outcome=overrides.get(case_id, by_id[case_id].expectation),
            )
            for case_id in ids
        ),
    )


def request_for(corpus: AssuranceCorpus, candidate: ReleaseAssuranceEvidence) -> WaiverGovernanceRequest:
    return WaiverGovernanceRequest(
        candidate_release_id=candidate.release_id,
        candidate_commit_sha=candidate.commit_sha,
        candidate_package_version=candidate.package_version,
        corpus_sha256=corpus_digest(corpus),
        candidate_evidence_sha256=release_evidence_digest(candidate),
        evaluated_at_epoch=EVALUATED_AT_EPOCH,
    )


def approvals_for(
    *,
    owner_id: str,
    severity: AssuranceSeverity,
    security_lead: str = "sec-lead-1",
) -> tuple[WaiverApproval, ...]:
    approvals = [
        WaiverApproval(owner_id, "invariant_owner", EVALUATED_AT_EPOCH - 4_000),
    ]
    if severity in {AssuranceSeverity.HIGH, AssuranceSeverity.CRITICAL}:
        approvals.append(
            WaiverApproval(security_lead, "security_lead", EVALUATED_AT_EPOCH - 3_900)
        )
    if severity == AssuranceSeverity.MEDIUM:
        approvals.append(
            WaiverApproval("sec-reviewer-1", "security_reviewer", EVALUATED_AT_EPOCH - 3_900)
        )
    if severity == AssuranceSeverity.CRITICAL:
        approvals.append(
            WaiverApproval("risk-owner-1", "risk_owner", EVALUATED_AT_EPOCH - 3_800)
        )
    return tuple(approvals)


def waiver_for(
    corpus: AssuranceCorpus,
    candidate: ReleaseAssuranceEvidence,
    case_id: str,
    *,
    waiver_id: str | None = None,
    security_lead: str = "sec-lead-1",
) -> SecurityWaiver:
    case = {item.case_id: item for item in corpus.cases}[case_id]
    owner_id = owner_map(corpus)[case_id]
    return SecurityWaiver(
        waiver_id=waiver_id or f"waiver-{case_id.casefold()}",
        case_id=case_id,
        case_definition_sha256=case_definition_digest(case),
        owner_id=owner_id,
        severity=case.severity,
        candidate_release_id=candidate.release_id,
        candidate_commit_sha=candidate.commit_sha,
        candidate_package_version=candidate.package_version,
        corpus_sha256=corpus_digest(corpus),
        candidate_evidence_sha256=release_evidence_digest(candidate),
        reason="Temporary exception while the blocking control is remediated.",
        tracking_ref=f"SEC-{case_id[-2:]}-2026",
        issued_at_epoch=EVALUATED_AT_EPOCH - 3_600,
        expires_at_epoch=EVALUATED_AT_EPOCH + 3 * 86_400,
        approvals=approvals_for(owner_id=owner_id, severity=case.severity, security_lead=security_lead),
    )


def default_fixture() -> dict[str, Any]:
    corpus = build_corpus()
    registry = build_registry(corpus)
    policy = build_policy(corpus, registry)
    candidate = evidence_for(corpus)
    request = request_for(corpus, candidate)
    return {
        "corpus": corpus,
        "registry": registry,
        "policy": policy,
        "candidate": candidate,
        "request": request,
    }


def _serializable(value: Any) -> Any:
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, frozenset):
        return sorted(_serializable(item) for item in value)
    if isinstance(value, tuple):
        return [_serializable(item) for item in value]
    if isinstance(value, dict):
        return {
            str(_serializable(key)): _serializable(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if hasattr(value, "__dataclass_fields__"):
        return {key: _serializable(item) for key, item in asdict(value).items()}
    return value


def fixture_digest() -> str:
    fixture = default_fixture()
    document = {
        "corpus": _serializable(fixture["corpus"]),
        "registry": _serializable(fixture["registry"]),
        "policy": _serializable(fixture["policy"]),
        "request": _serializable(fixture["request"]),
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def adversarial_cases() -> list[tuple[str, WaiverGovernanceRejectReason, dict[str, Any]]]:
    base = default_fixture()
    corpus: AssuranceCorpus = base["corpus"]
    registry: InvariantRegistry = base["registry"]
    policy: WaiverGovernancePolicy = base["policy"]
    clean_candidate: ReleaseAssuranceEvidence = base["candidate"]
    clean_request: WaiverGovernanceRequest = base["request"]
    ids = [case.case_id for case in corpus.cases]

    high_candidate = evidence_for(corpus, overrides={"P6A-C09": AssuranceExpectation.ALLOW})
    high_request = request_for(corpus, high_candidate)
    high_waiver = waiver_for(corpus, high_candidate, "P6A-C09")

    critical_candidate = evidence_for(corpus, overrides={"P6A-C10": AssuranceExpectation.ALLOW})
    critical_request = request_for(corpus, critical_candidate)
    critical_waiver = waiver_for(corpus, critical_candidate, "P6A-C10")

    safe_candidate = evidence_for(corpus, overrides={"P6A-C17": AssuranceExpectation.BLOCK})
    safe_request = request_for(corpus, safe_candidate)

    mutated_definition_record = replace(registry.records[0], case_definition_sha256="0" * 64)
    definition_registry = replace(registry, records=(mutated_definition_record,) + registry.records[1:])
    definition_policy = replace(policy, expected_registry_sha256=invariant_registry_digest(definition_registry))

    mutated_severity_record = replace(registry.records[2], severity=AssuranceSeverity.LOW)
    severity_registry = replace(registry, records=registry.records[:2] + (mutated_severity_record,) + registry.records[3:])
    severity_policy = replace(policy, expected_registry_sha256=invariant_registry_digest(severity_registry))

    owner_records = list(registry.records)
    owner_records[8] = replace(owner_records[8], owner_id=owner_map(corpus)["P6A-C08"])
    owner_registry = replace(registry, records=tuple(owner_records))
    owner_policy = replace(policy, expected_registry_sha256=invariant_registry_digest(owner_registry))

    missing_candidate = evidence_for(corpus, result_ids=ids[:-1])
    bad_definition_candidate = evidence_for(corpus, definition_overrides={"P6A-C09": "f" * 64})

    extra_clean_waiver = waiver_for(corpus, clean_candidate, "P6A-C09")
    duplicate_waiver = replace(high_waiver, waiver_id="waiver-duplicate")
    wrong_case_digest = replace(high_waiver, case_definition_sha256="a" * 64)
    wrong_commit = replace(high_waiver, candidate_commit_sha="d" * 64)
    expired = replace(high_waiver, expires_at_epoch=EVALUATED_AT_EPOCH)
    future = replace(high_waiver, issued_at_epoch=EVALUATED_AT_EPOCH + 1)
    too_long = replace(
        high_waiver,
        expires_at_epoch=high_waiver.issued_at_epoch + 8 * 86_400,
    )
    severity_downgrade = replace(high_waiver, severity=AssuranceSeverity.LOW)
    missing_lead = replace(
        high_waiver,
        approvals=tuple(item for item in high_waiver.approvals if item.role != "security_lead"),
    )
    untrusted_lead = replace(
        high_waiver,
        approvals=tuple(
            replace(item, approver_id="unknown-security-lead") if item.role == "security_lead" else item
            for item in high_waiver.approvals
        ),
    )
    alternate_owner = owner_map(corpus)["P6A-C08"]
    wrong_owner_approval = replace(
        high_waiver,
        approvals=tuple(
            replace(item, approver_id=alternate_owner) if item.role == "invariant_owner" else item
            for item in high_waiver.approvals
        ),
    )

    return [
        ("P6B-A01 corpus digest substitution", WaiverGovernanceRejectReason.CORPUS_DIGEST_MISMATCH, {"policy": replace(policy, expected_corpus_sha256="0" * 64)}),
        ("P6B-A02 registry digest substitution", WaiverGovernanceRejectReason.REGISTRY_DIGEST_MISMATCH, {"policy": replace(policy, expected_registry_sha256="1" * 64)}),
        ("P6B-A03 registry case omission", WaiverGovernanceRejectReason.INVARIANT_DRIFT, {"registry": replace(registry, records=registry.records[:-1])}),
        ("P6B-A04 invariant definition drift under repinned registry", WaiverGovernanceRejectReason.INVARIANT_DRIFT, {"registry": definition_registry, "policy": definition_policy}),
        ("P6B-A05 invariant severity downgrade under repinned registry", WaiverGovernanceRejectReason.INVARIANT_DRIFT, {"registry": severity_registry, "policy": severity_policy}),
        ("P6B-A06 invariant owner substitution under repinned registry", WaiverGovernanceRejectReason.INVARIANT_OWNER_MISMATCH, {"registry": owner_registry, "policy": owner_policy}),
        ("P6B-A07 untrusted assurance runner", WaiverGovernanceRejectReason.RUNNER_UNTRUSTED, {"candidate": replace(clean_candidate, runner_id="untrusted-runner")}),
        ("P6B-A08 candidate case omission", WaiverGovernanceRejectReason.CASE_COVERAGE_MISMATCH, {"candidate": missing_candidate, "request": request_for(corpus, missing_candidate)}),
        ("P6B-A09 candidate case-definition substitution", WaiverGovernanceRejectReason.CASE_DEFINITION_MISMATCH, {"candidate": bad_definition_candidate, "request": request_for(corpus, bad_definition_candidate)}),
        ("P6B-A10 candidate release substitution", WaiverGovernanceRejectReason.CANDIDATE_IDENTITY_MISMATCH, {"candidate": replace(clean_candidate, release_id="wrong-release")}),
        ("P6B-A11 candidate evidence-digest substitution", WaiverGovernanceRejectReason.CANDIDATE_IDENTITY_MISMATCH, {"request": replace(clean_request, candidate_evidence_sha256="2" * 64)}),
        ("P6B-A12 waiver for a non-regressed case", WaiverGovernanceRejectReason.WAIVER_SCOPE_MISMATCH, {"waivers": (extra_clean_waiver,)}),
        ("P6B-A13 duplicate waiver for one regression", WaiverGovernanceRejectReason.WAIVER_DUPLICATE, {"candidate": high_candidate, "request": high_request, "waivers": (high_waiver, duplicate_waiver)}),
        ("P6B-A14 waiver case-definition substitution", WaiverGovernanceRejectReason.WAIVER_SCOPE_MISMATCH, {"candidate": high_candidate, "request": high_request, "waivers": (wrong_case_digest,)}),
        ("P6B-A15 waiver candidate-commit substitution", WaiverGovernanceRejectReason.WAIVER_SCOPE_MISMATCH, {"candidate": high_candidate, "request": high_request, "waivers": (wrong_commit,)}),
        ("P6B-A16 expired high-severity waiver", WaiverGovernanceRejectReason.WAIVER_EXPIRED, {"candidate": high_candidate, "request": high_request, "waivers": (expired,)}),
        ("P6B-A17 future-issued waiver", WaiverGovernanceRejectReason.WAIVER_NOT_YET_VALID, {"candidate": high_candidate, "request": high_request, "waivers": (future,)}),
        ("P6B-A18 severity-duration escape", WaiverGovernanceRejectReason.WAIVER_DURATION_EXCEEDED, {"candidate": high_candidate, "request": high_request, "waivers": (too_long,)}),
        ("P6B-A19 waiver severity downgrade", WaiverGovernanceRejectReason.WAIVER_SEVERITY_DOWNGRADE, {"candidate": high_candidate, "request": high_request, "waivers": (severity_downgrade,)}),
        ("P6B-A20 critical regression waiver attempt", WaiverGovernanceRejectReason.WAIVER_NOT_PERMITTED, {"candidate": critical_candidate, "request": critical_request, "waivers": (critical_waiver,)}),
        ("P6B-A21 high waiver missing security-lead approval", WaiverGovernanceRejectReason.APPROVAL_INSUFFICIENT, {"candidate": high_candidate, "request": high_request, "waivers": (missing_lead,)}),
        ("P6B-A22 untrusted high-waiver approver", WaiverGovernanceRejectReason.APPROVER_UNTRUSTED, {"candidate": high_candidate, "request": high_request, "waivers": (untrusted_lead,)}),
        ("P6B-A23 invariant-owner approval substitution", WaiverGovernanceRejectReason.OWNER_APPROVAL_MISMATCH, {"candidate": high_candidate, "request": high_request, "waivers": (wrong_owner_approval,)}),
        ("P6B-A24 unwaived high regression", WaiverGovernanceRejectReason.REGRESSION_UNWAIVED, {"candidate": high_candidate, "request": high_request, "waivers": ()}),
        ("P6B-A25 safe-task regression waiver masking", WaiverGovernanceRejectReason.SAFE_TASK_REGRESSION, {"candidate": safe_candidate, "request": safe_request, "waivers": ()}),
    ]


def benign_cases() -> list[tuple[str, ReleaseAssuranceEvidence, WaiverGovernanceRequest, tuple[SecurityWaiver, ...]]]:
    corpus = build_corpus()
    clean_candidate = evidence_for(corpus)
    high_candidate = evidence_for(corpus, overrides={"P6A-C09": AssuranceExpectation.ALLOW})
    high_waiver = waiver_for(corpus, high_candidate, "P6A-C09")
    alt_candidate = evidence_for(
        corpus,
        overrides={"P6A-C12": AssuranceExpectation.ALLOW},
        runner_id=ALT_RUNNER_ID,
    )
    alt_waiver = waiver_for(
        corpus,
        alt_candidate,
        "P6A-C12",
        waiver_id="waiver-alt-high",
        security_lead="sec-lead-2",
    )
    alt_waiver = replace(alt_waiver, approvals=tuple(reversed(alt_waiver.approvals)))
    return [
        ("P6B-B1 clean candidate needs no waiver", clean_candidate, request_for(corpus, clean_candidate), ()),
        ("P6B-B2 scoped high regression with owner and security-lead approval", high_candidate, request_for(corpus, high_candidate), (high_waiver,)),
        ("P6B-B3 alternate trusted runner and approver order", alt_candidate, request_for(corpus, alt_candidate), (alt_waiver,)),
    ]


def dataset_digest() -> str:
    document = {
        "adversarial": [
            {"name": name, "reason": reason.value}
            for name, reason, _ in adversarial_cases()
        ],
        "benign": [name for name, *_ in benign_cases()],
        "corpus_cases": [
            {
                "case_id": case.case_id,
                "severity": case.severity.value,
                "expectation": case.expectation.value,
                "invariant": case.invariant,
            }
            for case in build_corpus().cases
        ],
    }
    return hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def run_evaluation() -> dict[str, Any]:
    fixture = default_fixture()
    corpus: AssuranceCorpus = fixture["corpus"]
    registry: InvariantRegistry = fixture["registry"]
    policy: WaiverGovernancePolicy = fixture["policy"]
    candidate: ReleaseAssuranceEvidence = fixture["candidate"]
    request: WaiverGovernanceRequest = fixture["request"]
    vulnerable = VulnerableDeclaredWaiverGate()

    adversarial_results: list[dict[str, Any]] = []
    vulnerable_success = 0
    hardened_success = 0
    for name, expected_reason, overrides in adversarial_cases():
        attack_corpus = overrides.get("corpus", corpus)
        attack_registry = overrides.get("registry", registry)
        attack_policy = overrides.get("policy", policy)
        attack_candidate = overrides.get("candidate", candidate)
        attack_request = overrides.get("request", request)
        attack_waivers = overrides.get("waivers", ())
        vulnerable_accepted = vulnerable.evaluate(
            candidate=attack_candidate,
            declared_waived_case_ids=tuple(waiver.case_id for waiver in attack_waivers),
            declared_critical_waivers=0,
        ).accepted
        if vulnerable_accepted:
            vulnerable_success += 1
        gate = SecurityInvariantWaiverGovernanceGate(
            corpus=attack_corpus,
            registry=attack_registry,
            policy=attack_policy,
        )
        actual_reason = None
        try:
            gate.evaluate(
                request=attack_request,
                candidate=attack_candidate,
                waivers=attack_waivers,
            )
            hardened_accepted = True
            hardened_success += 1
        except WaiverGovernanceRejected as exc:
            hardened_accepted = False
            actual_reason = exc.reason.value
        adversarial_results.append({
            "case": name,
            "expected_reject_reason": expected_reason.value,
            "actual_reject_reason": actual_reason,
            "vulnerable_accepted": vulnerable_accepted,
            "hardened_accepted": hardened_accepted,
        })

    benign_results: list[dict[str, Any]] = []
    benign_false_positive = 0
    benign_success = 0
    for name, benign_candidate, benign_request, benign_waivers in benign_cases():
        gate = SecurityInvariantWaiverGovernanceGate(
            corpus=corpus,
            registry=registry,
            policy=policy,
        )
        try:
            verified = gate.evaluate(
                request=benign_request,
                candidate=benign_candidate,
                waivers=benign_waivers,
            )
            accepted = True
            benign_success += 1
            governance_evidence_sha256 = verified.governance_evidence_sha256
        except WaiverGovernanceRejected:
            accepted = False
            benign_false_positive += 1
            governance_evidence_sha256 = None
        benign_results.append({
            "case": name,
            "hardened_accepted": accepted,
            "governance_evidence_sha256": governance_evidence_sha256,
        })

    adversarial_count = len(adversarial_results)
    benign_count = len(benign_results)
    return {
        "milestone": "P6-B security invariant drift and waiver governance",
        "adversarial_cases": adversarial_count,
        "benign_cases": benign_count,
        "vulnerable_asr": f"{vulnerable_success}/{adversarial_count}",
        "hardened_asr": f"{hardened_success}/{adversarial_count}",
        "hardened_fpr": f"{benign_false_positive}/{benign_count}",
        "safe_task_rate": f"{benign_success}/{benign_count}",
        "dataset_sha256": dataset_digest(),
        "fixture_sha256": fixture_digest(),
        "registry_sha256": invariant_registry_digest(registry),
        "adversarial_results": adversarial_results,
        "benign_results": benign_results,
        "claim_boundary": {
            "versioned_invariant_ownership": True,
            "severity_downgrade_detection": True,
            "expiry_bound_waivers": True,
            "critical_waivers_denied": True,
            "high_waiver_dual_role_approval": True,
            "formal_verification": False,
            "production_change_management": False,
            "external_ticket_verification": False,
            "cryptographic_approval_attestation": False,
            "human_identity_proof": False,
        },
    }


def main() -> int:
    result = run_evaluation()
    print(json.dumps(result, indent=2, sort_keys=True))
    expected = (
        result["vulnerable_asr"] == f"{result['adversarial_cases']}/{result['adversarial_cases']}"
        and result["hardened_asr"] == f"0/{result['adversarial_cases']}"
        and result["hardened_fpr"] == f"0/{result['benign_cases']}"
        and result["safe_task_rate"] == f"{result['benign_cases']}/{result['benign_cases']}"
        and all(item["expected_reject_reason"] == item["actual_reject_reason"] for item in result["adversarial_results"])
    )
    return 0 if expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
