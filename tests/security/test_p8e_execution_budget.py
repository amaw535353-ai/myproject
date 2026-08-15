from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.agentic.execution_budget_security import (
    AgentExecutionBudgetSecurityAnalyzer,
    BudgetDecision,
    BudgetRejectReason,
    BudgetRisk,
    ExecutionBudgetSecurityRejected,
    execution_budget_manifest_digest,
)
from evals.p8e_execution_budget import (
    ADVERSARIAL_CASES,
    EXPECTED_ADVERSARIAL_CASES,
    _clone,
    _coherent_budget,
    _cost_limit_case,
    _hardened_attack_succeeds,
    _item,
    _loop_case,
    _truthful_cost_context,
    _truthful_retry_context,
    benign_contexts,
    run,
)
from evals.p8e_fixture import build_fixture, make_upstreams, truthful_request_for_context


def evaluate(ctx):
    return AgentExecutionBudgetSecurityAnalyzer(ctx["policy"]).evaluate(
        ctx["request"], ctx["manifest"], ctx["p8a"], ctx["p8c"], ctx["p8d"]
    )


def test_clean_fixture_all_runs_allowed():
    result = evaluate(build_fixture())
    assert result.run_count == 4
    assert result.allowed_run_count == 4
    assert result.denied_run_count == 0
    assert result.maximum_risk_score == 0
    assert result.network_operations == 0


def test_graph_digest_and_clean_assessment_digest_are_exact():
    ctx = build_fixture()
    assert execution_budget_manifest_digest(ctx["manifest"]) == "6ded859ac55c7bd348313593fa73104fab41b6694482a8b9f764108ac51914e7"
    result = evaluate(ctx)
    assert result.assessment_evidence_sha256 == "7a4b8ca83bae7ef6477f0464b26c064db7db5ea0e2009b42155a46beb40130fb"


def test_all_adversarial_cases_fail_closed_or_derive_denial():
    assert EXPECTED_ADVERSARIAL_CASES == 129
    failures = [case_id for case_id, mutation in ADVERSARIAL_CASES if _hardened_attack_succeeds(mutation(_clone()))]
    assert failures == []


def test_evaluator_metrics_and_hashes_are_exact():
    result = run()
    assert result["adversarial_cases"] == 129
    assert result["vulnerable_asr"] == "129/129"
    assert result["hardened_asr"] == "0/129"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
    assert result["graph_sha256"] == "6ded859ac55c7bd348313593fa73104fab41b6694482a8b9f764108ac51914e7"
    assert result["dataset_sha256"] == "b5abbaa72815e06ce1ddec4577f996a47a13b341cdaacbae7f5f03896de61cd5"
    assert result["fixture_sha256"] == "19165ac7dbdaa6437213cc149ecf357351e0d17d76f4027905943599138940c7"


def test_truthful_retry_limit_is_processed_not_rejected():
    result = evaluate(_truthful_retry_context())
    fact = next(item for item in result.runs if item.run_id == "run-search")
    assert fact.decision == BudgetDecision.DENY
    assert BudgetRisk.RETRY_LIMIT in fact.risks
    assert fact.max_retry_count == 2
    assert fact.risk_score == 98


def test_truthful_cost_limit_is_processed_not_rejected():
    result = evaluate(_truthful_cost_context())
    fact = next(item for item in result.runs if item.run_id == "run-search")
    assert fact.decision == BudgetDecision.DENY
    assert BudgetRisk.COST_LIMIT in fact.risks
    assert fact.derived_cost_microusd == 300
    assert fact.risk_score == 102


def test_loop_detection_uses_repeated_operation_key():
    ctx = _loop_case(_clone())
    ctx["request"] = truthful_request_for_context(ctx)
    fact = next(item for item in evaluate(ctx).runs if item.run_id == "run-search")
    assert BudgetRisk.LOOP_DETECTED in fact.risks
    assert fact.max_repeated_operation_count == 3


def test_delegated_budget_cannot_amplify_parent_ceiling():
    ctx = _coherent_budget("budget-search-child", max_model_calls=3)(_clone())
    ctx["request"] = truthful_request_for_context(ctx)
    fact = next(item for item in evaluate(ctx).runs if item.run_id == "run-search")
    assert BudgetRisk.DELEGATED_BUDGET_AMPLIFICATION in fact.risks
    assert fact.risk_score == 120


def test_claimed_cost_cannot_override_policy_derived_cost():
    ctx = _item("events", "evt-search-model", claimed_cost_microusd=0)(_clone())
    ctx["request"] = truthful_request_for_context(ctx)
    fact = next(item for item in evaluate(ctx).runs if item.run_id == "run-search")
    assert BudgetRisk.COST_CLAIM_MISMATCH in fact.risks
    assert fact.derived_cost_microusd == 30


def test_denied_delegation_blocks_budgeted_execution():
    ctx = build_fixture()
    ctx.update(make_upstreams(denied_delegations=frozenset({"delegation-retrieval"})))
    ctx["request"] = truthful_request_for_context(ctx)
    fact = next(item for item in evaluate(ctx).runs if item.run_id == "run-search")
    assert BudgetRisk.UPSTREAM_DELEGATION_UNSAFE in fact.risks


def test_denied_plan_step_blocks_budgeted_execution():
    ctx = build_fixture()
    ctx.update(make_upstreams(denied_steps=frozenset({"step-release"})))
    ctx["request"] = truthful_request_for_context(ctx)
    fact = next(item for item in evaluate(ctx).runs if item.run_id == "run-release")
    assert BudgetRisk.UPSTREAM_PLAN_UNSAFE in fact.risks


def test_denied_tool_observation_blocks_budgeted_execution():
    ctx = build_fixture()
    ctx.update(make_upstreams(denied_observations=frozenset({"obs-telemetry"})))
    ctx["request"] = truthful_request_for_context(ctx)
    fact = next(item for item in evaluate(ctx).runs if item.run_id == "run-telemetry")
    assert BudgetRisk.UPSTREAM_TOOL_OBSERVATION_UNSAFE in fact.risks


def test_event_tenant_mismatch_is_derived_from_evidence():
    ctx = _item("events", "evt-search-tool", tenant_id="tenant-B")(_clone())
    ctx["request"] = truthful_request_for_context(ctx)
    fact = next(item for item in evaluate(ctx).runs if item.run_id == "run-search")
    assert BudgetRisk.TENANT_MISMATCH in fact.risks


def test_caller_cannot_hide_truthful_denial():
    ctx = _truthful_retry_context()
    ctx["request"] = replace(ctx["request"], declared_denied_run_ids=(), declared_risks_by_run={run_id: () for run_id in ctx["request"].run_ids}, declared_max_risk_score=0)
    with pytest.raises(ExecutionBudgetSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason in {BudgetRejectReason.DECLARED_DECISION_MISMATCH, BudgetRejectReason.DECLARED_RISK_MISMATCH}


def test_tool_call_requires_p8d_observation_binding():
    ctx = _item("events", "evt-ticket-tool", p8d_observation_id=None)(_clone())
    with pytest.raises(ExecutionBudgetSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == BudgetRejectReason.REFERENCE_INVALID


def test_event_graph_cycle_is_rejected():
    ctx = _item("events", "evt-search-step", parent_event_id="evt-search-tool")(_clone())
    with pytest.raises(ExecutionBudgetSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == BudgetRejectReason.GRAPH_CYCLE


def test_benign_truthful_contexts_are_all_accepted():
    for _, ctx in benign_contexts():
        evaluate(ctx)


def test_claim_boundary_flags_are_explicit():
    result = evaluate(build_fixture())
    assert result.delegated_budget_non_amplification_verified is True
    assert result.recursion_and_fanout_limits_evaluated is True
    assert result.retry_and_loop_limits_evaluated is True
    assert result.model_cost_derived_from_policy_rates is True
    assert result.irreversible_action_rate_limits_evaluated is True
    assert result.caller_declared_resource_safety_trusted is False
    assert result.production_provider_billing_enforcement is False
    assert result.production_runtime_kill_switch is False
    assert result.real_time_cost_accuracy is False
    assert result.distributed_resource_accounting is False
    assert result.exhaustive_loop_detection is False
