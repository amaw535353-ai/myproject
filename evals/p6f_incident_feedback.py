from __future__ import annotations

import hashlib
import json
from dataclasses import replace

from aegis.assurance.corpus_evolution import (
    CorpusChangeManifest,
    CorpusChangeRecord,
    CorpusChangeType,
    VerifiedCorpusEvolution,
    change_manifest_digest,
)
from aegis.assurance.incident_feedback import (
    IncidentAssuranceFeedback,
    IncidentCaseLink,
    IncidentCoverageLedger,
    IncidentCoverageObligation,
    IncidentFeedbackPolicy,
    IncidentFeedbackRejected,
    IncidentFeedbackRequest,
    IncidentToAssuranceFeedbackGate,
    incident_coverage_ledger_digest,
    incident_feedback_digest,
    incident_trace_digest,
)
from aegis.assurance.regression import (
    AssuranceCase,
    AssuranceCorpus,
    AssuranceExpectation,
    AssuranceSeverity,
    case_definition_digest,
    corpus_digest,
)
from aegis.model_serving.abuse_response import (
    AbuseSignalType,
    IncidentAction,
    VerifiedIncidentDecision,
)
from aegis.vulnerable.incident_feedback import VulnerableIncidentFeedbackGate


ZERO = "0" * 64
HIST_TRACE = hashlib.sha256(b"historical-serving-incident").hexdigest()
EVOLUTION_EVIDENCE = hashlib.sha256(b"p6c-evolution-evidence").hexdigest()


def _historical_case() -> AssuranceCase:
    return AssuranceCase(
        case_id="P6F-HIST-001",
        boundary="p5i_model_serving_abuse",
        attack_class="incident_derived_serving_abuse",
        severity=AssuranceSeverity.CRITICAL,
        expectation=AssuranceExpectation.BLOCK,
        invariant=f"historical serving canary leakage stays blocked; incident_trace_sha256={HIST_TRACE}",
    )


def _safe_cases() -> tuple[AssuranceCase, ...]:
    return (
        AssuranceCase("P6F-SAFE-001", "p5i_model_serving_abuse", "safe_task", AssuranceSeverity.LOW, AssuranceExpectation.ALLOW, "normal single request remains allowed"),
        AssuranceCase("P6F-SAFE-002", "p5i_model_serving_abuse", "safe_task", AssuranceSeverity.LOW, AssuranceExpectation.ALLOW, "normal multi-principal traffic remains allowed"),
        AssuranceCase("P6F-SAFE-003", "p5i_model_serving_abuse", "safe_task", AssuranceSeverity.LOW, AssuranceExpectation.ALLOW, "low-risk isolated probe remains observable without quarantine"),
    )


def _incident() -> VerifiedIncidentDecision:
    return VerifiedIncidentDecision(
        incident_id="incident-2026-08-15-001",
        deployment_id="helpdesk-prod-blue",
        package_id="helpdesk-runtime-package",
        model_id="helpdesk-model",
        revision="r4",
        runtime_id="helpdesk-inference",
        collector_id="aegis-serving-collector",
        batch_id="batch-440",
        batch_sha256=hashlib.sha256(b"verified-p5i-batch-440").hexdigest(),
        first_sequence=801,
        last_sequence=806,
        action=IncidentAction.QUARANTINE,
        risk_points=23,
        distinct_principals=4,
        signal_counts=(
            (AbuseSignalType.SENSITIVE_CHANNEL_PROBE.value, 2),
            (AbuseSignalType.MEMBERSHIP_INFERENCE_SIGNAL.value, 4),
        ),
        attestation_statement_sha256=hashlib.sha256(b"p5h-attestation").hexdigest(),
        quarantine_required=True,
    )


def build_fixture():
    incident = _incident()
    baseline = AssuranceCorpus(
        corpus_id="aegis-cross-boundary-security-regressions",
        version="6.5",
        cases=(_historical_case(),) + _safe_cases(),
    )
    baseline_sha = corpus_digest(baseline)

    previous_ledger = IncidentCoverageLedger(
        ledger_id="aegis-operational-incident-coverage",
        version=1,
        previous_ledger_sha256=ZERO,
        obligations=(
            IncidentCoverageObligation(
                obligation_id="obligation-historical-canary",
                incident_id="incident-historical-canary",
                incident_batch_sha256=hashlib.sha256(b"historical-batch").hexdigest(),
                required_min_severity=AssuranceSeverity.CRITICAL,
                required_signal_types=(AbuseSignalType.CANARY_LEAKAGE.value,),
                created_in_corpus_version=baseline.version,
                trace_sha256=HIST_TRACE,
            ),
        ),
    )
    previous_ledger_sha = incident_coverage_ledger_digest(previous_ledger)
    min_severity = AssuranceSeverity.HIGH
    current_trace = incident_trace_digest(incident, required_min_severity=min_severity)

    current_case = AssuranceCase(
        case_id="P6F-INC-001",
        boundary="p5i_model_serving_abuse",
        attack_class="incident_derived_serving_abuse",
        severity=AssuranceSeverity.HIGH,
        expectation=AssuranceExpectation.BLOCK,
        invariant=(
            "quarantine-class sensitive-channel and membership-inference incident remains blocked; "
            f"incident_trace_sha256={current_trace}"
        ),
    )
    candidate = AssuranceCorpus(
        corpus_id=baseline.corpus_id,
        version="6.6",
        cases=baseline.cases + (current_case,),
    )
    candidate_sha = corpus_digest(candidate)
    feedback_id = "feedback-incident-2026-08-15-001"
    reason = f"incident-feedback:{feedback_id}:{incident.incident_id}:{incident.batch_sha256}"
    change = CorpusChangeRecord(
        change_id="change-p6f-inc-001",
        change_type=CorpusChangeType.ADD,
        case_id=current_case.case_id,
        owner_id="ai-security",
        reason=reason,
        new_case_definition_sha256=case_definition_digest(current_case),
    )
    manifest = CorpusChangeManifest(
        baseline_corpus_sha256=baseline_sha,
        candidate_corpus_sha256=candidate_sha,
        changes=(change,),
        tombstones=(),
    )
    manifest_sha = change_manifest_digest(manifest)

    candidate_ledger = IncidentCoverageLedger(
        ledger_id=previous_ledger.ledger_id,
        version=2,
        previous_ledger_sha256=previous_ledger_sha,
        obligations=previous_ledger.obligations + (
            IncidentCoverageObligation(
                obligation_id="obligation-incident-2026-08-15-001",
                incident_id=incident.incident_id,
                incident_batch_sha256=incident.batch_sha256,
                required_min_severity=min_severity,
                required_signal_types=tuple(sorted({
                    AbuseSignalType.SENSITIVE_CHANNEL_PROBE.value,
                    AbuseSignalType.MEMBERSHIP_INFERENCE_SIGNAL.value,
                })),
                created_in_corpus_version=candidate.version,
                trace_sha256=current_trace,
            ),
        ),
    )
    candidate_ledger_sha = incident_coverage_ledger_digest(candidate_ledger)

    evolution = VerifiedCorpusEvolution(
        corpus_id=candidate.corpus_id,
        baseline_version=baseline.version,
        candidate_version=candidate.version,
        baseline_corpus_sha256=baseline_sha,
        candidate_corpus_sha256=candidate_sha,
        change_manifest_sha256=manifest_sha,
        added_case_ids=(current_case.case_id,),
        modified_case_ids=(),
        deprecated_case_ids=(),
        tombstoned_case_ids=(),
        candidate_case_count=len(candidate.cases),
        candidate_block_case_count=sum(c.expectation == AssuranceExpectation.BLOCK for c in candidate.cases),
        candidate_allow_case_count=sum(c.expectation == AssuranceExpectation.ALLOW for c in candidate.cases),
        candidate_critical_block_count=sum(c.expectation == AssuranceExpectation.BLOCK and c.severity == AssuranceSeverity.CRITICAL for c in candidate.cases),
        candidate_high_or_critical_block_count=sum(c.expectation == AssuranceExpectation.BLOCK and c.severity in {AssuranceSeverity.HIGH, AssuranceSeverity.CRITICAL} for c in candidate.cases),
        evidence_sha256=EVOLUTION_EVIDENCE,
    )

    link = IncidentCaseLink(
        case_id=current_case.case_id,
        case_definition_sha256=case_definition_digest(current_case),
        change_id=change.change_id,
        signal_types=tuple(sorted({
            AbuseSignalType.SENSITIVE_CHANNEL_PROBE.value,
            AbuseSignalType.MEMBERSHIP_INFERENCE_SIGNAL.value,
        })),
    )
    feedback = IncidentAssuranceFeedback(
        feedback_id=feedback_id,
        incident_id=incident.incident_id,
        deployment_id=incident.deployment_id,
        incident_batch_sha256=incident.batch_sha256,
        incident_action=incident.action,
        incident_risk_points=incident.risk_points,
        incident_signal_counts=incident.signal_counts,
        baseline_corpus_sha256=baseline_sha,
        candidate_corpus_sha256=candidate_sha,
        change_manifest_sha256=manifest_sha,
        previous_ledger_sha256=previous_ledger_sha,
        candidate_ledger_sha256=candidate_ledger_sha,
        links=(link,),
        created_at_epoch=1_800_000_600,
    )
    feedback_sha = incident_feedback_digest(feedback)
    request = IncidentFeedbackRequest(
        feedback_id=feedback.feedback_id,
        feedback_sha256=feedback_sha,
        incident_id=incident.incident_id,
        incident_batch_sha256=incident.batch_sha256,
        candidate_corpus_sha256=candidate_sha,
        candidate_ledger_sha256=candidate_ledger_sha,
        evolution_evidence_sha256=evolution.evidence_sha256,
    )
    policy = IncidentFeedbackPolicy(
        expected_baseline_corpus_id=baseline.corpus_id,
        expected_baseline_corpus_sha256=baseline_sha,
        expected_previous_ledger_sha256=previous_ledger_sha,
        trusted_change_owner_ids=frozenset({"ai-security"}),
        allowed_target_boundaries=frozenset({"p5i_model_serving_abuse"}),
    )
    return {
        "incident": incident, "baseline": baseline, "candidate": candidate,
        "previous_ledger": previous_ledger, "candidate_ledger": candidate_ledger,
        "manifest": manifest, "evolution": evolution, "feedback": feedback,
        "request": request, "policy": policy,
    }


def _replace_case(corpus, case_id, **changes):
    return replace(corpus, cases=tuple(replace(c, **changes) if c.case_id == case_id else c for c in corpus.cases))


def adversarial_variants():
    base = build_fixture()
    cases = []

    def add(name, **mods):
        fixture = build_fixture()
        fixture.update(mods)
        cases.append((name, fixture))

    inc = base["incident"]
    add("P6F-A01 incident signature verification removed", incident=replace(inc, telemetry_signature_verified=False))
    add("P6F-A02 incident chain verification removed", incident=replace(inc, telemetry_chain_verified=False))
    add("P6F-A03 incomplete incident telemetry", incident=replace(inc, telemetry_complete=False))
    add("P6F-A04 incident network operations nonzero", incident=replace(inc, network_operations=1))
    add("P6F-A05 non-material throttle incident", incident=replace(inc, action=IncidentAction.THROTTLE))
    add("P6F-A06 invalid incident batch digest", incident=replace(inc, batch_sha256="bad"))
    add("P6F-A07 duplicate incident signal counts", incident=replace(inc, signal_counts=((AbuseSignalType.SENSITIVE_CHANNEL_PROBE.value, 1),(AbuseSignalType.SENSITIVE_CHANNEL_PROBE.value, 2))))
    add("P6F-A08 baseline corpus substitution", baseline=replace(base["baseline"], version="6.4"))
    add("P6F-A09 candidate lineage substitution", candidate=replace(base["candidate"], corpus_id="other-corpus"))
    add("P6F-A10 P6-C exact-change verification removed", evolution=replace(base["evolution"], exact_change_coverage_verified=False))
    add("P6F-A11 P6-C candidate digest substitution", evolution=replace(base["evolution"], candidate_corpus_sha256=hashlib.sha256(b"wrong-candidate").hexdigest()))
    add("P6F-A12 P6-C candidate count substitution", evolution=replace(base["evolution"], candidate_case_count=999))

    add("P6F-A13 previous ledger digest substitution", policy=replace(base["policy"], expected_previous_ledger_sha256=hashlib.sha256(b"wrong-ledger").hexdigest()))
    add("P6F-A14 candidate ledger rollback", candidate_ledger=replace(base["candidate_ledger"], version=1))
    add("P6F-A15 candidate ledger parent substitution", candidate_ledger=replace(base["candidate_ledger"], previous_ledger_sha256=hashlib.sha256(b"fork").hexdigest()))
    add("P6F-A16 historical obligation dropped", candidate_ledger=replace(base["candidate_ledger"], obligations=(base["candidate_ledger"].obligations[-1],)))
    hist = base["candidate_ledger"].obligations[0]
    mutated_hist = replace(hist, required_min_severity=AssuranceSeverity.HIGH)
    add("P6F-A17 historical obligation mutated", candidate_ledger=replace(base["candidate_ledger"], obligations=(mutated_hist, base["candidate_ledger"].obligations[-1])))
    add("P6F-A18 current obligation missing", candidate_ledger=replace(base["candidate_ledger"], obligations=base["previous_ledger"].obligations))
    current_ob = base["candidate_ledger"].obligations[-1]
    add("P6F-A19 current obligation severity downgrade", candidate_ledger=replace(base["candidate_ledger"], obligations=(hist, replace(current_ob, required_min_severity=AssuranceSeverity.MEDIUM))))
    add("P6F-A20 current obligation trace substitution", candidate_ledger=replace(base["candidate_ledger"], obligations=(hist, replace(current_ob, trace_sha256=hashlib.sha256(b"wrong-trace").hexdigest()))))

    fb = base["feedback"]
    add("P6F-A21 feedback incident identity substitution", feedback=replace(fb, incident_id="other-incident"))
    add("P6F-A22 feedback action substitution", feedback=replace(fb, incident_action=IncidentAction.REVOKE_DEPLOYMENT))
    add("P6F-A23 feedback risk substitution", feedback=replace(fb, incident_risk_points=99))
    add("P6F-A24 feedback signal counts substitution", feedback=replace(fb, incident_signal_counts=((AbuseSignalType.SENSITIVE_CHANNEL_PROBE.value, 2),)))
    add("P6F-A25 feedback candidate ledger digest substitution", feedback=replace(fb, candidate_ledger_sha256=hashlib.sha256(b"wrong-ledger").hexdigest()))
    add("P6F-A26 request feedback digest substitution", request=replace(base["request"], feedback_sha256=hashlib.sha256(b"wrong-feedback").hexdigest()))
    add("P6F-A27 request evolution digest substitution", request=replace(base["request"], evolution_evidence_sha256=hashlib.sha256(b"wrong-evolution").hexdigest()))

    link = fb.links[0]
    add("P6F-A28 case definition digest substitution", feedback=replace(fb, links=(replace(link, case_definition_sha256=hashlib.sha256(b"wrong-case").hexdigest()),)))
    add("P6F-A29 material signal omitted from case link", feedback=replace(fb, links=(replace(link, signal_types=(AbuseSignalType.SENSITIVE_CHANNEL_PROBE.value,)),)))
    add("P6F-A30 case link claims absent signal", feedback=replace(fb, links=(replace(link, signal_types=link.signal_types + (AbuseSignalType.EXTRACTION_SIGNAL.value,)),)))

    weak_candidate = _replace_case(base["candidate"], "P6F-INC-001", expectation=AssuranceExpectation.ALLOW)
    add("P6F-A31 incident-derived case changed to allow", candidate=weak_candidate)
    low_candidate = _replace_case(base["candidate"], "P6F-INC-001", severity=AssuranceSeverity.MEDIUM)
    add("P6F-A32 incident-derived severity downgraded", candidate=low_candidate)
    other_boundary = _replace_case(base["candidate"], "P6F-INC-001", boundary="p5a_model_artifact_provenance")
    add("P6F-A33 incident-derived boundary substituted", candidate=other_boundary)
    wrong_class = _replace_case(base["candidate"], "P6F-INC-001", attack_class="membership_inference")
    add("P6F-A34 incident-derived attack class substituted", candidate=wrong_class)
    no_trace = _replace_case(base["candidate"], "P6F-INC-001", invariant="quarantine-class incident remains blocked without incident trace")
    add("P6F-A35 incident trace removed from regression case", candidate=no_trace)

    change = base["manifest"].changes[0]
    add("P6F-A36 P6-C change record omitted", manifest=replace(base["manifest"], changes=()))
    add("P6F-A37 P6-C change type deprecate", manifest=replace(base["manifest"], changes=(replace(change, change_type=CorpusChangeType.DEPRECATE),)))
    add("P6F-A38 P6-C change owner untrusted", manifest=replace(base["manifest"], changes=(replace(change, owner_id="app-team"),)))
    add("P6F-A39 P6-C incident change reason unbound", manifest=replace(base["manifest"], changes=(replace(change, reason="routine regression update"),)))

    historical_removed = replace(base["candidate"], cases=tuple(c for c in base["candidate"].cases if c.case_id != "P6F-HIST-001"))
    add("P6F-A40 historical incident regression coverage removed", candidate=historical_removed)
    return cases


def run_hardened(fixture):
    gate = IncidentToAssuranceFeedbackGate(fixture["policy"])
    return gate.evaluate(
        fixture["request"], fixture["feedback"], fixture["incident"],
        fixture["baseline"], fixture["candidate"], fixture["manifest"],
        fixture["evolution"], fixture["previous_ledger"], fixture["candidate_ledger"],
    )


def run_evaluation():
    adversarial = adversarial_variants()
    vulnerable = VulnerableIncidentFeedbackGate()
    vulnerable_successes = 0
    hardened_successes = 0
    results = []
    for name, fixture in adversarial:
        v = vulnerable.evaluate(
            feedback_id=fixture["feedback"].feedback_id,
            caller_declared_status="complete",
            incident_closed_loop=True,
            regression_coverage_added=True,
        )
        if v.accepted:
            vulnerable_successes += 1
        try:
            run_hardened(fixture)
        except IncidentFeedbackRejected as exc:
            results.append({"case": name, "hardened": "blocked", "reason": exc.reason.value})
        else:
            hardened_successes += 1
            results.append({"case": name, "hardened": "accepted", "reason": "none"})

    benign = []
    for suffix in ("A", "B", "C"):
        fixture = build_fixture()
        fixture["feedback"] = replace(fixture["feedback"], feedback_id=f"{fixture['feedback'].feedback_id}-{suffix}")
        expected_reason = f"incident-feedback:{fixture['feedback'].feedback_id}:{fixture['incident'].incident_id}:{fixture['incident'].batch_sha256}"
        change = replace(fixture["manifest"].changes[0], reason=expected_reason)
        fixture["manifest"] = replace(fixture["manifest"], changes=(change,))
        manifest_sha = change_manifest_digest(fixture["manifest"])
        fixture["evolution"] = replace(fixture["evolution"], change_manifest_sha256=manifest_sha)
        fixture["feedback"] = replace(fixture["feedback"], change_manifest_sha256=manifest_sha)
        fixture["request"] = replace(
            fixture["request"],
            feedback_id=fixture["feedback"].feedback_id,
            feedback_sha256=incident_feedback_digest(fixture["feedback"]),
        )
        benign.append(fixture)

    benign_pass = 0
    for fixture in benign:
        try:
            run_hardened(fixture)
            benign_pass += 1
        except IncidentFeedbackRejected:
            pass

    base = build_fixture()
    dataset_document = [{"id": name.split()[0], "name": name} for name, _ in adversarial]
    dataset_sha = hashlib.sha256(json.dumps(dataset_document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    fixture_document = {
        "baseline": corpus_digest(base["baseline"]),
        "candidate": corpus_digest(base["candidate"]),
        "manifest": change_manifest_digest(base["manifest"]),
        "previous_ledger": incident_coverage_ledger_digest(base["previous_ledger"]),
        "candidate_ledger": incident_coverage_ledger_digest(base["candidate_ledger"]),
        "feedback": incident_feedback_digest(base["feedback"]),
        "evolution": base["evolution"].evidence_sha256,
        "incident_batch": base["incident"].batch_sha256,
    }
    fixture_sha = hashlib.sha256(json.dumps(fixture_document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    report = {
        "adversarial_cases": len(adversarial),
        "vulnerable_asr": f"{vulnerable_successes}/{len(adversarial)}",
        "hardened_asr": f"{hardened_successes}/{len(adversarial)}",
        "hardened_fpr": f"{len(benign)-benign_pass}/{len(benign)}",
        "safe_task_rate": f"{benign_pass}/{len(benign)}",
        "baseline_corpus_sha256": corpus_digest(base["baseline"]),
        "candidate_corpus_sha256": corpus_digest(base["candidate"]),
        "previous_ledger_sha256": incident_coverage_ledger_digest(base["previous_ledger"]),
        "candidate_ledger_sha256": incident_coverage_ledger_digest(base["candidate_ledger"]),
        "dataset_sha256": dataset_sha,
        "fixture_sha256": fixture_sha,
        "results": results,
    }
    return report


def main():
    report = run_evaluation()
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["vulnerable_asr"] != f"{report['adversarial_cases']}/{report['adversarial_cases']}":
        raise SystemExit(1)
    if report["hardened_asr"] != f"0/{report['adversarial_cases']}":
        raise SystemExit(1)
    if report["hardened_fpr"] != "0/3" or report["safe_task_rate"] != "3/3":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
