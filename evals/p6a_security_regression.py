from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from typing import Any

from aegis.assurance.regression import (
    AssuranceCase,
    AssuranceCorpus,
    AssuranceExpectation,
    AssurancePolicy,
    AssuranceRejectReason,
    AssuranceRejected,
    AssuranceRequest,
    AssuranceSeverity,
    CaseObservation,
    ContinuousSecurityAssuranceGate,
    ReleaseAssuranceEvidence,
    case_definition_digest,
    corpus_digest,
)
from aegis.vulnerable.assurance_regression import VulnerableAggregateAssuranceGate


BASELINE_COMMIT = "a" * 64
CANDIDATE_COMMIT = "b" * 64
BASELINE_RELEASE = "aegisdesk-v0.54.0"
CANDIDATE_RELEASE = "aegisdesk-v0.55.0"
BASELINE_VERSION = "0.54.0"
CANDIDATE_VERSION = "0.55.0"
RUNNER_ID = "aegis-deterministic-assurance-runner-v1"


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
    return AssuranceCorpus(corpus_id="aegisdesk-cross-boundary-security-corpus", version="2026.08-p6a.1", cases=cases)


def evidence_for(
    corpus: AssuranceCorpus,
    *,
    release_id: str,
    commit_sha: str,
    package_version: str,
    runner_id: str = RUNNER_ID,
    overrides: dict[str, AssuranceExpectation] | None = None,
    definition_overrides: dict[str, str] | None = None,
    result_ids: list[str] | None = None,
) -> ReleaseAssuranceEvidence:
    overrides = overrides or {}
    definition_overrides = definition_overrides or {}
    by_id = {case.case_id: case for case in corpus.cases}
    ids = result_ids or [case.case_id for case in corpus.cases]
    results = tuple(
        CaseObservation(
            case_id=case_id,
            case_definition_sha256=definition_overrides.get(case_id, case_definition_digest(by_id[case_id])),
            observed_outcome=overrides.get(case_id, by_id[case_id].expectation),
        )
        for case_id in ids
    )
    return ReleaseAssuranceEvidence(
        release_id=release_id,
        commit_sha=commit_sha,
        package_version=package_version,
        corpus_sha256=corpus_digest(corpus),
        runner_id=runner_id,
        results=results,
    )


def default_fixture() -> dict[str, Any]:
    corpus = build_corpus()
    policy = AssurancePolicy(
        expected_corpus_sha256=corpus_digest(corpus),
        baseline_release_id=BASELINE_RELEASE,
        baseline_commit_sha=BASELINE_COMMIT,
        baseline_package_version=BASELINE_VERSION,
        trusted_runner_ids=frozenset({RUNNER_ID}),
        required_boundaries=frozenset({case.boundary for case in corpus.cases}),
    )
    baseline = evidence_for(corpus, release_id=BASELINE_RELEASE, commit_sha=BASELINE_COMMIT, package_version=BASELINE_VERSION)
    candidate = evidence_for(corpus, release_id=CANDIDATE_RELEASE, commit_sha=CANDIDATE_COMMIT, package_version=CANDIDATE_VERSION)
    request = AssuranceRequest(
        candidate_release_id=CANDIDATE_RELEASE,
        candidate_commit_sha=CANDIDATE_COMMIT,
        candidate_package_version=CANDIDATE_VERSION,
        corpus_sha256=corpus_digest(corpus),
    )
    return {"corpus": corpus, "policy": policy, "baseline": baseline, "candidate": candidate, "request": request}


def _serializable(value: Any) -> Any:
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, frozenset):
        return sorted(value)
    if isinstance(value, tuple):
        return [_serializable(item) for item in value]
    if isinstance(value, dict):
        return {key: _serializable(item) for key, item in value.items()}
    if hasattr(value, "__dataclass_fields__"):
        return {key: _serializable(item) for key, item in asdict(value).items()}
    return value


def fixture_digest() -> str:
    fixture = default_fixture()
    document = {
        "corpus": _serializable(fixture["corpus"]),
        "policy": _serializable(fixture["policy"]),
        "request": _serializable(fixture["request"]),
    }
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def adversarial_cases() -> list[tuple[str, AssuranceRejectReason, dict[str, Any]]]:
    base = default_fixture()
    corpus: AssuranceCorpus = base["corpus"]
    policy: AssurancePolicy = base["policy"]
    baseline: ReleaseAssuranceEvidence = base["baseline"]
    candidate: ReleaseAssuranceEvidence = base["candidate"]
    request: AssuranceRequest = base["request"]
    ids = [case.case_id for case in corpus.cases]

    missing = evidence_for(corpus, release_id=CANDIDATE_RELEASE, commit_sha=CANDIDATE_COMMIT, package_version=CANDIDATE_VERSION, result_ids=ids[:-1])
    duplicate = replace(candidate, results=candidate.results + (candidate.results[0],))
    unknown = replace(candidate, results=candidate.results[:-1] + (replace(candidate.results[-1], case_id="P6A-UNKNOWN"),))
    bad_definition = evidence_for(corpus, release_id=CANDIDATE_RELEASE, commit_sha=CANDIDATE_COMMIT, package_version=CANDIDATE_VERSION, definition_overrides={"P6A-C05": "0" * 64})
    attack_regression = evidence_for(corpus, release_id=CANDIDATE_RELEASE, commit_sha=CANDIDATE_COMMIT, package_version=CANDIDATE_VERSION, overrides={"P6A-C10": AssuranceExpectation.ALLOW})
    safe_regression = evidence_for(corpus, release_id=CANDIDATE_RELEASE, commit_sha=CANDIDATE_COMMIT, package_version=CANDIDATE_VERSION, overrides={"P6A-C17": AssuranceExpectation.BLOCK})
    baseline_bad = evidence_for(corpus, release_id=BASELINE_RELEASE, commit_sha=BASELINE_COMMIT, package_version=BASELINE_VERSION, overrides={"P6A-C04": AssuranceExpectation.ALLOW})
    mutated_case = replace(corpus.cases[0], invariant="mutated invariant")
    mutated_corpus = replace(corpus, cases=(mutated_case,) + corpus.cases[1:])
    reduced_boundaries = frozenset(set(policy.required_boundaries) | {"nonexistent-boundary"})

    return [
        ("P6A-A01 corpus digest substitution", AssuranceRejectReason.CORPUS_DIGEST_MISMATCH, {"policy": replace(policy, expected_corpus_sha256="0" * 64)}),
        ("P6A-A02 mutated case definition in corpus", AssuranceRejectReason.CORPUS_DIGEST_MISMATCH, {"corpus": mutated_corpus}),
        ("P6A-A03 missing required boundary", AssuranceRejectReason.BOUNDARY_COVERAGE_MISMATCH, {"policy": replace(policy, required_boundaries=reduced_boundaries)}),
        ("P6A-A04 untrusted assurance runner", AssuranceRejectReason.RUNNER_UNTRUSTED, {"candidate": replace(candidate, runner_id="untrusted-runner")}),
        ("P6A-A05 candidate case omission", AssuranceRejectReason.CASE_COVERAGE_MISMATCH, {"candidate": missing}),
        ("P6A-A06 candidate duplicate case", AssuranceRejectReason.CASE_DUPLICATE, {"candidate": duplicate}),
        ("P6A-A07 candidate unknown case substitution", AssuranceRejectReason.CASE_COVERAGE_MISMATCH, {"candidate": unknown}),
        ("P6A-A08 case-definition digest substitution", AssuranceRejectReason.CASE_DEFINITION_MISMATCH, {"candidate": bad_definition}),
        ("P6A-A09 baseline release substitution", AssuranceRejectReason.BASELINE_IDENTITY_MISMATCH, {"baseline": replace(baseline, release_id="wrong-baseline")}),
        ("P6A-A10 baseline insecure result", AssuranceRejectReason.BASELINE_NOT_SECURE, {"baseline": baseline_bad}),
        ("P6A-A11 candidate release substitution", AssuranceRejectReason.EVIDENCE_IDENTITY_MISMATCH, {"candidate": replace(candidate, release_id="wrong-candidate")}),
        ("P6A-A12 candidate commit substitution", AssuranceRejectReason.EVIDENCE_IDENTITY_MISMATCH, {"candidate": replace(candidate, commit_sha="c" * 64)}),
        ("P6A-A13 stale corpus evidence", AssuranceRejectReason.EVIDENCE_IDENTITY_MISMATCH, {"candidate": replace(candidate, corpus_sha256="d" * 64)}),
        ("P6A-A14 critical attack-block regression", AssuranceRejectReason.SECURITY_REGRESSION, {"candidate": attack_regression}),
        ("P6A-A15 benign safe-task regression", AssuranceRejectReason.SAFE_TASK_REGRESSION, {"candidate": safe_regression}),
        ("P6A-A16 request commit substitution", AssuranceRejectReason.EVIDENCE_IDENTITY_MISMATCH, {"request": replace(request, candidate_commit_sha="e" * 64)}),
        ("P6A-A17 aggregate-score masking of one critical regression", AssuranceRejectReason.SECURITY_REGRESSION, {"candidate": attack_regression}),
    ]


def benign_cases() -> list[tuple[str, ReleaseAssuranceEvidence]]:
    candidate: ReleaseAssuranceEvidence = default_fixture()["candidate"]
    return [
        ("P6A-B1 exact candidate evidence", candidate),
        ("P6A-B2 reordered exact case evidence", replace(candidate, results=tuple(reversed(candidate.results)))),
        ("P6A-B3 trusted alternate deterministic runner", replace(candidate, runner_id="aegis-secondary-assurance-runner-v1")),
    ]


def dataset_digest() -> str:
    document = {
        "adversarial": [{"name": name, "reason": reason.value} for name, reason, _ in adversarial_cases()],
        "benign": [name for name, _ in benign_cases()],
        "corpus_cases": [
            {
                "case_id": case.case_id,
                "boundary": case.boundary,
                "attack_class": case.attack_class,
                "severity": case.severity.value,
                "expectation": case.expectation.value,
                "invariant": case.invariant,
            }
            for case in build_corpus().cases
        ],
    }
    payload = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def run_evaluation() -> dict[str, Any]:
    fixture = default_fixture()
    corpus: AssuranceCorpus = fixture["corpus"]
    policy: AssurancePolicy = fixture["policy"]
    baseline: ReleaseAssuranceEvidence = fixture["baseline"]
    candidate: ReleaseAssuranceEvidence = fixture["candidate"]
    request: AssuranceRequest = fixture["request"]
    vulnerable = VulnerableAggregateAssuranceGate()
    adversarial_results: list[dict[str, Any]] = []
    vulnerable_success = 0
    hardened_success = 0

    for name, expected_reason, overrides in adversarial_cases():
        attack_corpus = overrides.get("corpus", corpus)
        attack_policy = overrides.get("policy", policy)
        attack_baseline = overrides.get("baseline", baseline)
        attack_candidate = overrides.get("candidate", candidate)
        attack_request = overrides.get("request", request)
        gate = ContinuousSecurityAssuranceGate(corpus=attack_corpus, policy=attack_policy)
        vulnerable_accepted = vulnerable.evaluate(candidate=attack_candidate, declared_pass_rate_ppm=1_000_000, declared_regressions=0).accepted
        if vulnerable_accepted:
            vulnerable_success += 1
        rejected_reason = None
        try:
            gate.evaluate(request=attack_request, baseline=attack_baseline, candidate=attack_candidate)
            hardened_accepted = True
            hardened_success += 1
        except AssuranceRejected as exc:
            hardened_accepted = False
            rejected_reason = exc.reason.value
        adversarial_results.append({
            "case": name,
            "vulnerable_accepted": vulnerable_accepted,
            "hardened_accepted": hardened_accepted,
            "expected_reject_reason": expected_reason.value,
            "actual_reject_reason": rejected_reason,
        })

    benign_results: list[dict[str, Any]] = []
    benign_false_positive = 0
    benign_success = 0
    benign_policy = replace(policy, trusted_runner_ids=frozenset({RUNNER_ID, "aegis-secondary-assurance-runner-v1"}))
    for name, benign_candidate in benign_cases():
        gate = ContinuousSecurityAssuranceGate(corpus=corpus, policy=benign_policy)
        try:
            verified = gate.evaluate(request=request, baseline=baseline, candidate=benign_candidate)
            accepted = True
            benign_success += 1
            evidence_sha256 = verified.evidence_sha256
        except AssuranceRejected:
            accepted = False
            benign_false_positive += 1
            evidence_sha256 = None
        benign_results.append({"case": name, "hardened_accepted": accepted, "evidence_sha256": evidence_sha256})

    return {
        "milestone": "P6-A",
        "adversarial_cases": len(adversarial_results),
        "vulnerable_asr": f"{vulnerable_success}/{len(adversarial_results)}",
        "hardened_asr": f"{hardened_success}/{len(adversarial_results)}",
        "hardened_fpr": f"{benign_false_positive}/{len(benign_results)}",
        "safe_task_rate": f"{benign_success}/{len(benign_results)}",
        "corpus_case_count": len(corpus.cases),
        "corpus_boundary_count": len({case.boundary for case in corpus.cases}),
        "corpus_sha256": corpus_digest(corpus),
        "dataset_sha256": dataset_digest(),
        "fixture_sha256": fixture_digest(),
        "adversarial_results": adversarial_results,
        "benign_results": benign_results,
        "claim_boundary": {
            "versioned_cross_boundary_corpus": True,
            "exact_case_definition_binding": True,
            "exact_case_coverage": True,
            "release_to_release_regression_detection": True,
            "formal_verification": False,
            "exhaustive_attack_coverage": False,
            "production_ci_attestation": False,
            "real_attack_execution": False,
            "network_operations": 0,
        },
    }


def main() -> int:
    print(json.dumps(run_evaluation(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
