from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.agentic.goal_plan_security import (
    AgentGoalPlanIntegrityAnalyzer,
    GoalPlanRejectReason,
    GoalPlanRisk,
    GoalPlanSecurityRejected,
    GoalIntegrityState,
    IntegrityDecision,
    goal_plan_manifest_digest,
)
from evals.p8c_fixture import (
    ACTION_TOOL_READ,
    GOAL_RELEASE_DEPLOY,
    GOAL_RETRIEVAL,
    GOAL_TOOL,
    INSTR_MEMORY_HINT,
    INSTR_RETRIEVAL,
    INV_TOOL,
    MUTATION_RELEASE_REINSPECT,
    NOW,
    RETRIEVAL_PREFS,
    STEP_RELEASE_DEPLOY,
    STEP_RELEASE_ROLLBACK,
    STEP_RETRIEVAL,
    STEP_TOOL,
    build_fixture,
    make_upstreams,
    replace_manifest_item,
)
from evals.p8c_goal_plan_integrity import ADVERSARIAL_CASES, _clone, _hardened_attack_succeeds, benign_contexts, run


def evaluate(ctx):
    return AgentGoalPlanIntegrityAnalyzer(ctx["policy"]).evaluate(
        ctx["request"], ctx["manifest"], ctx["p8a"], ctx["p8b"], ctx["p7i"]
    )


def test_clean_goal_plan_is_allowed():
    result = evaluate(build_fixture())
    assert result.goal_count == 5
    assert result.safe_goal_count == 5
    assert result.unsafe_goal_count == 0
    assert result.step_count == 7
    assert result.allowed_step_count == 7
    assert result.denied_step_count == 0
    assert result.mutation_count == 2
    assert result.allowed_mutation_count == 2
    assert result.denied_mutation_count == 0
    assert result.max_integrity_risk_score == 0
    assert result.network_operations == 0


def test_graph_digest_is_deterministic():
    ctx = build_fixture()
    assert goal_plan_manifest_digest(ctx["manifest"]) == ctx["request"].graph_sha256
    assert ctx["request"].graph_sha256 == "4ffef28407a47d9a7d2ba3a6cdba49b96f6222e8fcfb0f4e7fa995dc979907de"


def test_evaluator_metrics_and_hashes_are_exact():
    result = run()
    assert result["adversarial_cases"] == 133
    assert result["vulnerable_asr"] == "133/133"
    assert result["hardened_asr"] == "0/133"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
    assert result["graph_sha256"] == "4ffef28407a47d9a7d2ba3a6cdba49b96f6222e8fcfb0f4e7fa995dc979907de"
    assert result["dataset_sha256"] == "cc53112d1512ede5ee2c347b789f41931d91a6f923fc1a1befc1d3d0e15f97c5"
    assert result["fixture_sha256"] == "ba57043fa13a50eb38222e8a52625ecb6622df68a8d171a7e7fafd89348f7079"


def test_all_adversarial_cases_fail_closed():
    failures = [case_id for case_id, mutation in ADVERSARIAL_CASES if _hardened_attack_succeeds(mutation(_clone()))]
    assert failures == []


def test_truthful_termination_bypass_is_denied():
    ctx = dict(benign_contexts()[1][1])
    result = evaluate(ctx)
    assert result.denied_step_count == 1
    assert result.unsafe_goal_count == 1
    assert result.max_integrity_risk_score == 96
    step = next(item for item in result.steps if item.step_id == STEP_RELEASE_DEPLOY)
    assert step.decision == IntegrityDecision.DENY
    assert step.risks == (GoalPlanRisk.TERMINATION_BYPASS,)
    goal = next(item for item in result.goals if item.goal_id == GOAL_RELEASE_DEPLOY)
    assert goal.state == GoalIntegrityState.VIOLATED


def test_truthful_unsafe_invariant_is_denied():
    ctx = dict(benign_contexts()[2][1])
    result = evaluate(ctx)
    step = next(item for item in result.steps if item.step_id == STEP_TOOL)
    assert step.decision == IntegrityDecision.DENY
    assert GoalPlanRisk.ARCHITECTURE_INVARIANT_UNSAFE in step.risks
    assert result.max_integrity_risk_score == 76


def test_memory_instruction_cannot_expand_goal_scope():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(
        ctx["manifest"],
        "steps",
        STEP_RETRIEVAL,
        action_class=ACTION_TOOL_READ,
        capability_ids=("tool.read",),
        source_instruction_ids=(INSTR_RETRIEVAL, INSTR_MEMORY_HINT),
    )
    digest = goal_plan_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    with pytest.raises(GoalPlanSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == GoalPlanRejectReason.DECLARED_STEP_DECISION_MISMATCH


def test_denied_p8a_delegation_blocks_goal_execution():
    ctx = build_fixture()
    ctx.update(make_upstreams(denied_delegations=frozenset({"delegation-tool-child"})))
    with pytest.raises(GoalPlanSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == GoalPlanRejectReason.DECLARED_STEP_DECISION_MISMATCH


def test_denied_p8b_memory_retrieval_blocks_dependent_step():
    ctx = build_fixture()
    ctx.update(make_upstreams(denied_retrievals=frozenset({RETRIEVAL_PREFS})))
    with pytest.raises(GoalPlanSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == GoalPlanRejectReason.DECLARED_STEP_DECISION_MISMATCH


def test_unsafe_p7i_invariant_blocks_tool_step():
    ctx = build_fixture()
    ctx.update(make_upstreams(unsafe_invariants=frozenset({INV_TOOL})))
    with pytest.raises(GoalPlanSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == GoalPlanRejectReason.DECLARED_STEP_DECISION_MISMATCH


def test_sequence_gap_is_detected():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "steps", STEP_RELEASE_ROLLBACK, sequence=3)
    digest = goal_plan_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    with pytest.raises(GoalPlanSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == GoalPlanRejectReason.DECLARED_STEP_DECISION_MISMATCH


def test_irreversible_flag_cannot_erase_rollback_obligation():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "steps", STEP_RELEASE_DEPLOY, irreversible=False)
    digest = goal_plan_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    with pytest.raises(GoalPlanSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == GoalPlanRejectReason.STEP_TIME_INVALID


def test_low_authority_memory_cannot_authorize_plan_mutation():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(
        ctx["manifest"],
        "mutations",
        MUTATION_RELEASE_REINSPECT,
        goal_id=GOAL_RETRIEVAL,
        target_step_id=STEP_RETRIEVAL,
        source_instruction_id=INSTR_MEMORY_HINT,
        proposed_action_class="retrieval.query",
        proposed_instruction_ids=(INSTR_RETRIEVAL, INSTR_MEMORY_HINT),
    )
    digest = goal_plan_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    with pytest.raises(GoalPlanSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == GoalPlanRejectReason.DECLARED_MUTATION_DECISION_MISMATCH


def test_caller_cannot_hide_termination_bypass():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "steps", STEP_RELEASE_DEPLOY, created_at_epoch=NOW - 1)
    digest = goal_plan_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    with pytest.raises(GoalPlanSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == GoalPlanRejectReason.DECLARED_STEP_DECISION_MISMATCH


def test_expired_goal_is_not_silently_executed():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "goals", GOAL_RETRIEVAL, expires_at_epoch=NOW - 1)
    digest = goal_plan_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    with pytest.raises(GoalPlanSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == GoalPlanRejectReason.DECLARED_STEP_DECISION_MISMATCH


def test_instruction_provenance_cycle_rejected():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "instructions", INSTR_RETRIEVAL, parent_instruction_id=INSTR_MEMORY_HINT)
    digest = goal_plan_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    with pytest.raises(GoalPlanSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason in {GoalPlanRejectReason.INSTRUCTION_CYCLE, GoalPlanRejectReason.INSTRUCTION_PROVENANCE_INVALID}


def test_caller_declarations_must_be_exact():
    ctx = build_fixture()
    ctx["request"] = replace(ctx["request"], declared_unsafe_goal_ids=(GOAL_TOOL,))
    with pytest.raises(GoalPlanSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == GoalPlanRejectReason.DECLARED_GOAL_STATE_MISMATCH


def test_claim_boundary_flags_are_explicit():
    result = evaluate(build_fixture())
    assert result.caller_declared_goal_safety_trusted is False
    assert result.production_agent_runtime_enforcement is False
    assert result.production_instruction_interception is False
    assert result.semantic_intent_proof is False
    assert result.exhaustive_goal_hijack_coverage is False
    assert result.formal_plan_correctness_proof is False
