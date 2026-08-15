from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace

from aegis.agentic.execution_budget_security import (
    AgentExecutionBudgetSecurityAnalyzer,
    BudgetAllocation,
    BudgetEnvelope,
    BudgetDecision,
    ExecutionBudgetManifest,
    ExecutionBudgetPolicy,
    ExecutionBudgetRequest,
    ExecutionEvent,
    ExecutionEventType,
    ExecutionRun,
    ModelCostRate,
    execution_budget_manifest_digest,
)

NOW = 1_786_792_400
NOW_MS = NOW * 1000
GRAPH_ID = "aegis-agent-execution-budget-graph"
GRAPH_VERSION = "1"
OWNER = "platform-security"
P8A_DIGEST = hashlib.sha256(b"p8a-delegation-evidence-p8e").hexdigest()
P8C_DIGEST = hashlib.sha256(b"p8c-goal-plan-evidence-p8e").hexdigest()
P8D_DIGEST = hashlib.sha256(b"p8d-tool-observation-evidence-p8e").hexdigest()

MODEL_SMALL = "model-small"
MODEL_RELEASE = "model-release"
MODEL_IDS = (MODEL_SMALL, MODEL_RELEASE)

BUDGET_IDS = (
    "budget-search-root", "budget-search-child",
    "budget-ticket-root", "budget-ticket-child",
    "budget-release-root", "budget-release-child",
    "budget-telemetry-root", "budget-telemetry-child",
)
ALLOCATION_IDS = ("alloc-search", "alloc-ticket", "alloc-release", "alloc-telemetry")
RUN_IDS = ("run-search", "run-ticket", "run-release", "run-telemetry")
EVENT_IDS = (
    "evt-search-step", "evt-search-model", "evt-search-tool",
    "evt-ticket-step", "evt-ticket-tool",
    "evt-release-step", "evt-release-model", "evt-release-tool",
    "evt-telemetry-step", "evt-telemetry-tool",
)


def _cost(input_tokens: int, output_tokens: int, input_rate: int, output_rate: int) -> int:
    return (input_tokens * input_rate + 999) // 1000 + (output_tokens * output_rate + 999) // 1000


def make_upstreams(
    *,
    denied_delegations: frozenset[str] = frozenset(),
    denied_steps: frozenset[str] = frozenset(),
    denied_observations: frozenset[str] = frozenset(),
    p8a_digest: str = P8A_DIGEST,
    p8c_digest: str = P8C_DIGEST,
    p8d_digest: str = P8D_DIGEST,
):
    delegation_specs = (
        ("delegation-retrieval", "agent-retrieval-a"),
        ("delegation-tool-child", "agent-tool-executor"),
        ("delegation-release-deploy", "agent-release-executor"),
        ("delegation-telemetry", "agent-security-orchestrator"),
    )
    delegations = tuple(
        SimpleNamespace(delegation_id=delegation_id, delegatee_agent_id=delegatee, decision="deny" if delegation_id in denied_delegations else "allow")
        for delegation_id, delegatee in delegation_specs
    )
    steps = tuple(
        SimpleNamespace(step_id=step_id, decision="deny" if step_id in denied_steps else "allow")
        for step_id in ("step-search", "step-ticket", "step-release", "step-telemetry")
    )
    observation_specs = (
        ("obs-search", "tenant-A", "goal-search"),
        ("obs-ticket", "tenant-A", "goal-ticket"),
        ("obs-release", "platform", "goal-release"),
        ("obs-telemetry", "platform", "goal-telemetry"),
    )
    observations = tuple(
        SimpleNamespace(observation_id=observation_id, tenant_id=tenant, goal_id=goal, decision="deny" if observation_id in denied_observations else "allow")
        for observation_id, tenant, goal in observation_specs
    )
    return {
        "p8a": SimpleNamespace(
            assessment_evidence_sha256=p8a_digest,
            exact_delegation_graph_binding_verified=True,
            caller_declared_delegation_authorization_trusted=False,
            delegations=delegations,
        ),
        "p8c": SimpleNamespace(
            assessment_evidence_sha256=p8c_digest,
            exact_goal_plan_graph_binding_verified=True,
            caller_declared_goal_safety_trusted=False,
            steps=steps,
        ),
        "p8d": SimpleNamespace(
            assessment_evidence_sha256=p8d_digest,
            exact_tool_observation_graph_binding_verified=True,
            caller_declared_tool_observation_safety_trusted=False,
            observations=observations,
        ),
    }


def _rates() -> tuple[ModelCostRate, ...]:
    return (
        ModelCostRate(MODEL_SMALL, 20, 40, OWNER, "Synthetic low-cost local model rate."),
        ModelCostRate(MODEL_RELEASE, 50, 100, OWNER, "Synthetic release-model rate."),
    )


def _budgets() -> tuple[BudgetEnvelope, ...]:
    return (
        BudgetEnvelope("budget-search-root", "user-a", "tenant-A", "goal-search", None, 2, 2, 3000, 200, 20_000, 3, 4, 2, 1, 2, 0, 0, OWNER, "Search run root budget."),
        BudgetEnvelope("budget-search-child", "user-a", "tenant-A", "goal-search", "delegation-retrieval", 2, 1, 2500, 150, 15_000, 1, 3, 2, 1, 2, 0, 0, OWNER, "Retrieval-agent delegated budget."),
        BudgetEnvelope("budget-ticket-root", "user-a", "tenant-A", "goal-ticket", None, 1, 2, 1000, 100, 20_000, 3, 4, 2, 1, 2, 2, 1, OWNER, "Ticket mutation root budget."),
        BudgetEnvelope("budget-ticket-child", "user-a", "tenant-A", "goal-ticket", "delegation-tool-child", 0, 1, 0, 0, 15_000, 1, 3, 2, 1, 2, 1, 1, OWNER, "Tool-executor delegated budget."),
        BudgetEnvelope("budget-release-root", "release-admin", "platform", "goal-release", None, 2, 2, 4000, 500, 30_000, 4, 4, 2, 1, 2, 2, 1, OWNER, "Release run root budget."),
        BudgetEnvelope("budget-release-child", "release-admin", "platform", "goal-release", "delegation-release-deploy", 1, 1, 3000, 400, 20_000, 1, 3, 2, 1, 2, 1, 1, OWNER, "Release-agent delegated budget."),
        BudgetEnvelope("budget-telemetry-root", "security-admin", "platform", "goal-telemetry", None, 1, 2, 1000, 100, 20_000, 3, 4, 2, 1, 2, 2, 1, OWNER, "Telemetry administration root budget."),
        BudgetEnvelope("budget-telemetry-child", "security-admin", "platform", "goal-telemetry", "delegation-telemetry", 0, 1, 0, 0, 15_000, 1, 3, 2, 1, 2, 1, 1, OWNER, "Telemetry-agent delegated budget."),
    )


def _allocations() -> tuple[BudgetAllocation, ...]:
    return (
        BudgetAllocation("alloc-search", "budget-search-root", "budget-search-child", "agent-orchestrator-a", "agent-retrieval-a", "delegation-retrieval", OWNER, "Search budget delegation."),
        BudgetAllocation("alloc-ticket", "budget-ticket-root", "budget-ticket-child", "agent-tool-broker-a", "agent-tool-executor", "delegation-tool-child", OWNER, "Tool mutation budget delegation."),
        BudgetAllocation("alloc-release", "budget-release-root", "budget-release-child", "agent-release-orchestrator", "agent-release-executor", "delegation-release-deploy", OWNER, "Release budget delegation."),
        BudgetAllocation("alloc-telemetry", "budget-telemetry-root", "budget-telemetry-child", "agent-security-orchestrator", "agent-security-orchestrator", "delegation-telemetry", OWNER, "Telemetry budget delegation."),
    )


def _runs() -> tuple[ExecutionRun, ...]:
    return (
        ExecutionRun("run-search", "budget-search-root", "user-a", "tenant-A", "goal-search", NOW_MS - 10_000, NOW_MS - 1_000, OWNER, "Tenant search run."),
        ExecutionRun("run-ticket", "budget-ticket-root", "user-a", "tenant-A", "goal-ticket", NOW_MS - 20_000, NOW_MS - 11_000, OWNER, "Tenant ticket mutation run."),
        ExecutionRun("run-release", "budget-release-root", "release-admin", "platform", "goal-release", NOW_MS - 30_000, NOW_MS - 21_000, OWNER, "Release deployment run."),
        ExecutionRun("run-telemetry", "budget-telemetry-root", "security-admin", "platform", "goal-telemetry", NOW_MS - 40_000, NOW_MS - 31_000, OWNER, "Telemetry configuration run."),
    )


def _events() -> tuple[ExecutionEvent, ...]:
    small_cost = _cost(1000, 250, 20, 40)
    release_cost = _cost(1500, 300, 50, 100)
    return (
        ExecutionEvent("evt-search-step", "run-search", None, "budget-search-root", ExecutionEventType.AGENT_STEP, "step:search-root", "agent-orchestrator-a", "user-a", "tenant-A", "goal-search", "step-search", None, None, 0, 0, 0, 1, NOW_MS - 9_800, NOW_MS - 9_500, False, None, OWNER, "Root search planning step."),
        ExecutionEvent("evt-search-model", "run-search", "evt-search-step", "budget-search-child", ExecutionEventType.MODEL_CALL, "model:search-plan", "agent-retrieval-a", "user-a", "tenant-A", "goal-search", "step-search", "delegation-retrieval", MODEL_SMALL, 1000, 250, small_cost, 1, NOW_MS - 9_300, NOW_MS - 8_300, False, None, OWNER, "Retrieval planning model call."),
        ExecutionEvent("evt-search-tool", "run-search", "evt-search-model", "budget-search-child", ExecutionEventType.TOOL_CALL, "tool:search", "agent-retrieval-a", "user-a", "tenant-A", "goal-search", "step-search", "delegation-retrieval", None, 0, 0, 0, 1, NOW_MS - 8_000, NOW_MS - 7_000, False, "obs-search", OWNER, "Tenant search tool call."),
        ExecutionEvent("evt-ticket-step", "run-ticket", None, "budget-ticket-root", ExecutionEventType.AGENT_STEP, "step:ticket-root", "agent-tool-broker-a", "user-a", "tenant-A", "goal-ticket", "step-ticket", None, None, 0, 0, 0, 1, NOW_MS - 19_800, NOW_MS - 19_400, False, None, OWNER, "Ticket mutation planning step."),
        ExecutionEvent("evt-ticket-tool", "run-ticket", "evt-ticket-step", "budget-ticket-child", ExecutionEventType.TOOL_CALL, "tool:ticket", "agent-tool-executor", "user-a", "tenant-A", "goal-ticket", "step-ticket", "delegation-tool-child", None, 0, 0, 0, 1, NOW_MS - 19_000, NOW_MS - 18_000, True, "obs-ticket", OWNER, "Tenant ticket mutation."),
        ExecutionEvent("evt-release-step", "run-release", None, "budget-release-root", ExecutionEventType.AGENT_STEP, "step:release-root", "agent-release-orchestrator", "release-admin", "platform", "goal-release", "step-release", None, None, 0, 0, 0, 1, NOW_MS - 29_800, NOW_MS - 29_400, False, None, OWNER, "Release planning step."),
        ExecutionEvent("evt-release-model", "run-release", "evt-release-step", "budget-release-child", ExecutionEventType.MODEL_CALL, "model:release-check", "agent-release-executor", "release-admin", "platform", "goal-release", "step-release", "delegation-release-deploy", MODEL_RELEASE, 1500, 300, release_cost, 1, NOW_MS - 29_000, NOW_MS - 27_800, False, None, OWNER, "Release verification model call."),
        ExecutionEvent("evt-release-tool", "run-release", "evt-release-model", "budget-release-child", ExecutionEventType.TOOL_CALL, "tool:release", "agent-release-executor", "release-admin", "platform", "goal-release", "step-release", "delegation-release-deploy", None, 0, 0, 0, 1, NOW_MS - 27_500, NOW_MS - 26_000, True, "obs-release", OWNER, "Release deployment tool call."),
        ExecutionEvent("evt-telemetry-step", "run-telemetry", None, "budget-telemetry-root", ExecutionEventType.AGENT_STEP, "step:telemetry-root", "agent-security-orchestrator", "security-admin", "platform", "goal-telemetry", "step-telemetry", None, None, 0, 0, 0, 1, NOW_MS - 39_800, NOW_MS - 39_400, False, None, OWNER, "Telemetry planning step."),
        ExecutionEvent("evt-telemetry-tool", "run-telemetry", "evt-telemetry-step", "budget-telemetry-child", ExecutionEventType.TOOL_CALL, "tool:telemetry", "agent-security-orchestrator", "security-admin", "platform", "goal-telemetry", "step-telemetry", "delegation-telemetry", None, 0, 0, 0, 1, NOW_MS - 39_000, NOW_MS - 38_000, True, "obs-telemetry", OWNER, "Telemetry configuration tool call."),
    )


def _profile(budget: BudgetEnvelope):
    return (
        budget.original_principal_id, budget.tenant_id, budget.goal_id, budget.delegation_id,
        budget.max_model_calls, budget.max_tool_calls, budget.max_total_tokens, budget.max_cost_microusd,
        budget.max_elapsed_ms, budget.max_steps, budget.max_recursion_depth, budget.max_fanout_per_event,
        budget.max_retries_per_operation, budget.max_repeated_operation_count,
        budget.max_irreversible_actions, budget.max_irreversible_actions_per_minute,
    )


def build_fixture():
    manifest = ExecutionBudgetManifest(
        graph_id=GRAPH_ID,
        version=GRAPH_VERSION,
        p8a_assessment_evidence_sha256=P8A_DIGEST,
        p8c_assessment_evidence_sha256=P8C_DIGEST,
        p8d_assessment_evidence_sha256=P8D_DIGEST,
        created_at_epoch=NOW - 60,
        model_rates=_rates(),
        budgets=_budgets(),
        allocations=_allocations(),
        runs=_runs(),
        events=_events(),
    )
    digest = execution_budget_manifest_digest(manifest)
    policy = ExecutionBudgetPolicy(
        expected_graph_id=GRAPH_ID,
        expected_graph_version=GRAPH_VERSION,
        expected_graph_sha256=digest,
        expected_p8a_assessment_evidence_sha256=P8A_DIGEST,
        expected_p8c_assessment_evidence_sha256=P8C_DIGEST,
        expected_p8d_assessment_evidence_sha256=P8D_DIGEST,
        required_model_ids=frozenset(MODEL_IDS),
        required_budget_ids=frozenset(BUDGET_IDS),
        required_allocation_ids=frozenset(ALLOCATION_IDS),
        required_run_ids=frozenset(RUN_IDS),
        required_event_ids=frozenset(EVENT_IDS),
        trusted_owner_ids=frozenset({OWNER}),
        expected_model_rates={rate.model_id: (rate.input_microusd_per_1k_tokens, rate.output_microusd_per_1k_tokens) for rate in manifest.model_rates},
        expected_budget_profiles={budget.budget_id: _profile(budget) for budget in manifest.budgets},
        expected_run_bindings={run.run_id: (run.root_budget_id, run.original_principal_id, run.tenant_id, run.goal_id) for run in manifest.runs},
    )
    ctx = {"manifest": manifest, "policy": policy, **make_upstreams()}
    ctx["request"] = truthful_request_for_context(ctx)
    return ctx


def truthful_request_for_context(ctx):
    p = ctx["policy"]
    facts = AgentExecutionBudgetSecurityAnalyzer(p).derive(ctx["manifest"], ctx["p8a"], ctx["p8c"], ctx["p8d"], NOW)
    return ExecutionBudgetRequest(
        graph_id=p.expected_graph_id,
        graph_version=p.expected_graph_version,
        graph_sha256=p.expected_graph_sha256,
        p8a_assessment_evidence_sha256=p.expected_p8a_assessment_evidence_sha256,
        p8c_assessment_evidence_sha256=p.expected_p8c_assessment_evidence_sha256,
        p8d_assessment_evidence_sha256=p.expected_p8d_assessment_evidence_sha256,
        evaluated_at_epoch=NOW,
        run_ids=tuple(sorted(p.required_run_ids)),
        declared_denied_run_ids=tuple(sorted(fact.run_id for fact in facts if fact.decision == BudgetDecision.DENY)),
        declared_risks_by_run={fact.run_id: fact.risks for fact in facts},
        declared_max_risk_score=max((fact.risk_score for fact in facts), default=0),
    )


def replace_manifest_item(manifest: ExecutionBudgetManifest, collection: str, item_id: str, **changes):
    attr = {"model_rates": "model_id", "budgets": "budget_id", "allocations": "allocation_id", "runs": "run_id", "events": "event_id"}[collection]
    items = tuple(replace(item, **changes) if getattr(item, attr) == item_id else item for item in getattr(manifest, collection))
    return replace(manifest, **{collection: items})


def rebind(ctx, *, truthful: bool = False):
    digest = execution_budget_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    if truthful:
        ctx["request"] = truthful_request_for_context(ctx)
    return ctx


def clone_context(ctx=None):
    return dict(ctx or build_fixture())
