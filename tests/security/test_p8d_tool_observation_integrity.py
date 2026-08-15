from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.agentic.tool_observation_security import (
    AgentToolObservationIntegrityAnalyzer,
    ObservationDecision,
    ObservationRisk,
    ObservationTrust,
    ToolObservationSecurityRejected,
    tool_observation_manifest_digest,
)
from evals.p8d_fixture import (
    build_fixture,
    make_upstreams,
    rebind,
    replace_manifest_item,
    sha,
    truthful_request_for_context,
    truthful_unsafe_contexts,
)
from evals.p8d_tool_observation_integrity import (
    ADVERSARIAL_CASES,
    EXPECTED_ADVERSARIAL_CASES,
    _clone,
    _hardened_attack_succeeds,
    run,
)


def evaluate(ctx):
    return AgentToolObservationIntegrityAnalyzer(ctx["policy"]).evaluate(
        ctx["request"], ctx["manifest"], ctx["p8a"], ctx["p8c"], ctx["p7i"]
    )


def test_clean_fixture_allows_all_observations():
    result = evaluate(build_fixture())
    assert result.observation_count == 4
    assert result.allowed_observation_count == 4
    assert result.denied_observation_count == 0
    assert result.network_operations == 0


def test_graph_digest_is_deterministic():
    ctx = build_fixture()
    assert tool_observation_manifest_digest(ctx["manifest"]) == ctx["request"].graph_sha256
    assert ctx["request"].graph_sha256 == "1542df3c4f06744f5cb1ad26024e5e4bdac1b4a0d31379944c207ee3e3020ada"


def test_all_adversarial_cases_fail_closed():
    assert EXPECTED_ADVERSARIAL_CASES == len(ADVERSARIAL_CASES) == 208
    assert [name for name, mutation in ADVERSARIAL_CASES if _hardened_attack_succeeds(mutation(_clone()))] == []


def test_evaluator_metrics_and_hashes_are_exact():
    result = run()
    assert result["adversarial_cases"] == 208
    assert result["vulnerable_asr"] == "208/208"
    assert result["hardened_asr"] == "0/208"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
    assert result["graph_sha256"] == "1542df3c4f06744f5cb1ad26024e5e4bdac1b4a0d31379944c207ee3e3020ada"
    assert result["dataset_sha256"] == "24a0f4c3c864f95dbba2faaec65015fc5b6868165bcd43b930bcc58d4b32c1f6"
    assert result["fixture_sha256"] == "1f9b05b6f02d2ec640c2630debc28de45602714992ec58aad63a2d5c93600abb"


def test_replayed_result_is_denied_truthfully():
    result = evaluate(truthful_unsafe_contexts()["replay"])
    facts = {x.observation_id: x for x in result.observations}
    assert result.denied_observation_count == 2
    assert ObservationRisk.REPLAY_RESULT in facts["obs-search"].risks
    assert ObservationRisk.REPLAY_RESULT in facts["obs-ticket"].risks
    assert result.stale_or_replay_denial_count == 2


def test_stale_result_is_denied_truthfully():
    result = evaluate(truthful_unsafe_contexts()["stale"])
    fact = next(x for x in result.observations if x.observation_id == "obs-search")
    assert fact.decision == ObservationDecision.DENY
    assert ObservationRisk.STALE_RESULT in fact.risks


def test_missing_side_effect_ack_is_denied_truthfully():
    result = evaluate(truthful_unsafe_contexts()["side_effect"])
    fact = next(x for x in result.observations if x.observation_id == "obs-ticket")
    assert ObservationRisk.SIDE_EFFECT_UNACKNOWLEDGED in fact.risks
    assert fact.side_effect_acknowledged is False
    assert result.side_effect_integrity_denial_count == 1


def test_environment_state_spoof_is_denied_truthfully():
    result = evaluate(truthful_unsafe_contexts()["environment"])
    fact = next(x for x in result.observations if x.observation_id == "obs-ticket")
    assert ObservationRisk.ENVIRONMENT_STATE_SPOOF in fact.risks
    assert result.environment_integrity_denial_count == 1


def test_unattested_result_cannot_become_verified_authority():
    result = evaluate(truthful_unsafe_contexts()["laundering"])
    fact = next(x for x in result.observations if x.observation_id == "obs-search")
    assert fact.derived_trust == ObservationTrust.TOOL_ASSERTED
    assert ObservationRisk.OBSERVATION_LAUNDERING in fact.risks
    assert ObservationRisk.OBSERVATION_TRUST_MISMATCH in fact.risks


def test_upstream_denied_plan_step_denies_observation():
    result = evaluate(truthful_unsafe_contexts()["upstream"])
    fact = next(x for x in result.observations if x.observation_id == "obs-ticket")
    assert ObservationRisk.UPSTREAM_PLAN_UNSAFE in fact.risks
    assert result.upstream_safety_denial_count == 1


def test_upstream_denied_delegation_denies_observation():
    ctx = build_fixture()
    ctx.update(make_upstreams(denied_delegations=frozenset({"delegation-release-deploy"})))
    ctx["request"] = truthful_request_for_context(ctx)
    result = evaluate(ctx)
    fact = next(x for x in result.observations if x.observation_id == "obs-release")
    assert ObservationRisk.UPSTREAM_DELEGATION_UNSAFE in fact.risks


def test_required_invariant_unsafe_denies_observation():
    ctx = build_fixture()
    ctx.update(make_upstreams(unsafe_invariants=frozenset({"INV-ADMIN-NON-SELF-BYPASS"})))
    ctx["request"] = truthful_request_for_context(ctx)
    result = evaluate(ctx)
    fact = next(x for x in result.observations if x.observation_id == "obs-telemetry")
    assert ObservationRisk.REQUIRED_INVARIANT_UNSAFE in fact.risks


def test_argument_digest_binding_detects_result_swap():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "results", "result-search", args_sha256=sha("attacker-args"))
    rebind(ctx, truthful=True)
    result = evaluate(ctx)
    fact = next(x for x in result.observations if x.observation_id == "obs-search")
    assert ObservationRisk.ARGUMENT_DIGEST_MISMATCH in fact.risks


def test_environment_version_regression_is_denied():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "results", "result-ticket", observed_environment_version=9)
    rebind(ctx, truthful=True)
    result = evaluate(ctx)
    fact = next(x for x in result.observations if x.observation_id == "obs-ticket")
    assert ObservationRisk.ENVIRONMENT_VERSION_REGRESSION in fact.risks


def test_caller_cannot_hide_truthful_denial():
    ctx = truthful_unsafe_contexts()["environment"]
    ctx["request"] = replace(ctx["request"], declared_denied_observation_ids=(), declared_risks_by_observation={k: () for k in ctx["request"].observation_ids})
    with pytest.raises(ToolObservationSecurityRejected):
        evaluate(ctx)


def test_claim_boundary_flags_are_explicit():
    result = evaluate(build_fixture())
    assert result.caller_declared_tool_observation_safety_trusted is False
    assert result.production_tool_runtime_enforcement is False
    assert result.production_environment_attestation is False
    assert result.cryptographic_tool_result_attestation is False
    assert result.semantic_tool_output_safety_proof is False
    assert result.exhaustive_environment_state_coverage is False


def test_verified_results_require_allowlisted_attestation():
    facts = {x.observation_id: x for x in evaluate(build_fixture()).observations}
    assert facts["obs-search"].derived_trust == ObservationTrust.TOOL_ASSERTED
    assert facts["obs-ticket"].derived_trust == ObservationTrust.VERIFIED
    assert facts["obs-release"].derived_trust == ObservationTrust.VERIFIED
    assert facts["obs-telemetry"].derived_trust == ObservationTrust.VERIFIED


def test_assessment_digest_is_stable_for_same_evidence():
    assert evaluate(build_fixture()).assessment_evidence_sha256 == evaluate(build_fixture()).assessment_evidence_sha256
