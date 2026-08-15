from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Callable

from aegis.agentic.execution_budget_security import (
    AgentExecutionBudgetSecurityAnalyzer,
    BudgetDecision,
    BudgetRisk,
    ExecutionBudgetSecurityRejected,
    ExecutionEvent,
    ExecutionEventType,
    execution_budget_manifest_digest,
)
from aegis.vulnerable.execution_budget_security import VulnerableDeclaredExecutionBudgetSafety
from evals.p8e_fixture import (
    ALLOCATION_IDS,
    BUDGET_IDS,
    EVENT_IDS,
    GRAPH_ID,
    GRAPH_VERSION,
    MODEL_IDS,
    MODEL_RELEASE,
    MODEL_SMALL,
    NOW,
    NOW_MS,
    OWNER,
    P8A_DIGEST,
    P8C_DIGEST,
    P8D_DIGEST,
    RUN_IDS,
    build_fixture,
    clone_context,
    make_upstreams,
    rebind,
    replace_manifest_item,
    truthful_request_for_context,
)

Mutation = Callable[[dict[str, object]], dict[str, object]]


def _clone() -> dict[str, object]:
    return clone_context(build_fixture())


def _repin(ctx: dict[str, object]) -> dict[str, object]:
    digest = execution_budget_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    return ctx


def _request(field: str, value: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["request"] = replace(ctx["request"], **{field: value})
        return ctx
    return mutate


def _manifest(field: str, value: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["manifest"] = replace(ctx["manifest"], **{field: value})
        return ctx
    return mutate


def _item(collection: str, item_id: str, **changes: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["manifest"] = replace_manifest_item(ctx["manifest"], collection, item_id, **changes)
        return _repin(ctx)
    return mutate


def _drop(collection: str, attr: str, item_id: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        values = tuple(item for item in getattr(ctx["manifest"], collection) if getattr(item, attr) != item_id)
        ctx["manifest"] = replace(ctx["manifest"], **{collection: values})
        return _repin(ctx)
    return mutate


def _duplicate(collection: str, attr: str, item_id: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        values = list(getattr(ctx["manifest"], collection))
        item = next(item for item in values if getattr(item, attr) == item_id)
        values.append(item)
        ctx["manifest"] = replace(ctx["manifest"], **{collection: tuple(values)})
        return _repin(ctx)
    return mutate


def _upstream(source: str, **changes: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx[source] = SimpleNamespace(**{**vars(ctx[source]), **changes})
        return ctx
    return mutate


def _policy_map_omit(field: str, key: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        mapping = dict(getattr(ctx["policy"], field))
        mapping.pop(key)
        ctx["policy"] = replace(ctx["policy"], **{field: mapping})
        return ctx
    return mutate


def _coherent_budget(budget_id: str, **changes: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["manifest"] = replace_manifest_item(ctx["manifest"], "budgets", budget_id, **changes)
        budget = next(item for item in ctx["manifest"].budgets if item.budget_id == budget_id)
        profile = (
            budget.original_principal_id, budget.tenant_id, budget.goal_id, budget.delegation_id,
            budget.max_model_calls, budget.max_tool_calls, budget.max_total_tokens, budget.max_cost_microusd,
            budget.max_elapsed_ms, budget.max_steps, budget.max_recursion_depth, budget.max_fanout_per_event,
            budget.max_retries_per_operation, budget.max_repeated_operation_count,
            budget.max_irreversible_actions, budget.max_irreversible_actions_per_minute,
        )
        profiles = dict(ctx["policy"].expected_budget_profiles)
        profiles[budget_id] = profile
        ctx["policy"] = replace(ctx["policy"], expected_budget_profiles=profiles)
        return _repin(ctx)
    return mutate


def _coherent_rate(model_id: str, input_rate: int, output_rate: int) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["manifest"] = replace_manifest_item(ctx["manifest"], "model_rates", model_id, input_microusd_per_1k_tokens=input_rate, output_microusd_per_1k_tokens=output_rate)
        rates = dict(ctx["policy"].expected_model_rates)
        rates[model_id] = (input_rate, output_rate)
        ctx["policy"] = replace(ctx["policy"], expected_model_rates=rates)
        return _repin(ctx)
    return mutate


def _coherent_run(run_id: str, **changes: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["manifest"] = replace_manifest_item(ctx["manifest"], "runs", run_id, **changes)
        run = next(item for item in ctx["manifest"].runs if item.run_id == run_id)
        bindings = dict(ctx["policy"].expected_run_bindings)
        bindings[run_id] = (run.root_budget_id, run.original_principal_id, run.tenant_id, run.goal_id)
        ctx["policy"] = replace(ctx["policy"], expected_run_bindings=bindings)
        return _repin(ctx)
    return mutate


def _add_event(event: ExecutionEvent) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["manifest"] = replace(ctx["manifest"], events=ctx["manifest"].events + (event,))
        ctx["policy"] = replace(ctx["policy"], required_event_ids=ctx["policy"].required_event_ids | {event.event_id})
        return _repin(ctx)
    return mutate


def _combine(*mutations: Mutation) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        for operation in mutations:
            ctx = operation(ctx)
        return ctx
    return mutate


REQUEST_CASES = (
    ("request-graph-id", _request("graph_id", "evil")),
    ("request-version", _request("graph_version", "evil")),
    ("request-graph-sha", _request("graph_sha256", "1" * 64)),
    ("request-p8a-sha", _request("p8a_assessment_evidence_sha256", "2" * 64)),
    ("request-p8c-sha", _request("p8c_assessment_evidence_sha256", "3" * 64)),
    ("request-p8d-sha", _request("p8d_assessment_evidence_sha256", "4" * 64)),
    ("request-run-omission", _request("run_ids", tuple(sorted(set(RUN_IDS) - {"run-search"})))),
    ("request-run-duplicate", _request("run_ids", RUN_IDS + ("run-search",))),
    ("request-bad-sha-shape", _request("graph_sha256", "not-a-sha")),
)

MANIFEST_CASES = (
    ("manifest-schema", _manifest("schema_version", "evil")),
    ("manifest-id", _manifest("graph_id", "evil")),
    ("manifest-version", _manifest("version", "evil")),
    ("manifest-stale", _manifest("created_at_epoch", NOW - 90_000)),
    ("manifest-future", _manifest("created_at_epoch", NOW + 100)),
    ("manifest-p8a-pin", _manifest("p8a_assessment_evidence_sha256", "5" * 64)),
    ("manifest-p8c-pin", _manifest("p8c_assessment_evidence_sha256", "6" * 64)),
    ("manifest-p8d-pin", _manifest("p8d_assessment_evidence_sha256", "7" * 64)),
)

UPSTREAM_CASES = (
    ("p8a-digest", _upstream("p8a", assessment_evidence_sha256="8" * 64)),
    ("p8a-unverified", _upstream("p8a", exact_delegation_graph_binding_verified=False)),
    ("p8a-caller-trusted", _upstream("p8a", caller_declared_delegation_authorization_trusted=True)),
    ("p8c-digest", _upstream("p8c", assessment_evidence_sha256="9" * 64)),
    ("p8c-unverified", _upstream("p8c", exact_goal_plan_graph_binding_verified=False)),
    ("p8c-caller-trusted", _upstream("p8c", caller_declared_goal_safety_trusted=True)),
    ("p8d-digest", _upstream("p8d", assessment_evidence_sha256="a" * 64)),
    ("p8d-unverified", _upstream("p8d", exact_tool_observation_graph_binding_verified=False)),
    ("p8d-caller-trusted", _upstream("p8d", caller_declared_tool_observation_safety_trusted=True)),
)

COVERAGE_CASES = []
for collection, attr, item_id in (
    ("model_rates", "model_id", MODEL_SMALL),
    ("budgets", "budget_id", "budget-search-child"),
    ("allocations", "allocation_id", "alloc-search"),
    ("runs", "run_id", "run-search"),
    ("events", "event_id", "evt-search-tool"),
):
    COVERAGE_CASES.append((f"{collection}-omission", _drop(collection, attr, item_id)))
    COVERAGE_CASES.append((f"{collection}-duplicate", _duplicate(collection, attr, item_id)))
COVERAGE_CASES = tuple(COVERAGE_CASES)

OWNER_CASES = []
for collection, item_id in (
    ("model_rates", MODEL_SMALL),
    ("model_rates", MODEL_RELEASE),
    ("budgets", "budget-search-root"),
    ("budgets", "budget-ticket-child"),
    ("budgets", "budget-release-child"),
    ("budgets", "budget-telemetry-root"),
    ("allocations", "alloc-search"),
    ("allocations", "alloc-release"),
    ("runs", "run-search"),
    ("runs", "run-release"),
    ("events", "evt-search-model"),
    ("events", "evt-ticket-tool"),
    ("events", "evt-release-tool"),
    ("events", "evt-telemetry-tool"),
):
    OWNER_CASES.append((f"untrusted-owner-{collection}-{item_id}", _item(collection, item_id, owner_id="attacker")))
OWNER_CASES = tuple(OWNER_CASES)

POLICY_CASES = (
    ("policy-model-rate-map-omission", _policy_map_omit("expected_model_rates", MODEL_SMALL)),
    ("policy-budget-profile-map-omission", _policy_map_omit("expected_budget_profiles", "budget-search-root")),
    ("policy-run-binding-map-omission", _policy_map_omit("expected_run_bindings", "run-search")),
    ("policy-empty-trusted-owners", lambda ctx: {**ctx, "policy": replace(ctx["policy"], trusted_owner_ids=frozenset())}),
    ("policy-manifest-age-zero", lambda ctx: {**ctx, "policy": replace(ctx["policy"], max_manifest_age_seconds=0)}),
    ("policy-future-skew-negative", lambda ctx: {**ctx, "policy": replace(ctx["policy"], max_future_skew_seconds=-1)}),
    ("policy-negative-rate", lambda ctx: {**ctx, "policy": replace(ctx["policy"], expected_model_rates={**ctx["policy"].expected_model_rates, MODEL_SMALL: (-1, 40)})}),
)

DRIFT_CASES = (
    ("model-rate-input-drift", _item("model_rates", MODEL_SMALL, input_microusd_per_1k_tokens=21)),
    ("model-rate-output-drift", _item("model_rates", MODEL_SMALL, output_microusd_per_1k_tokens=41)),
    ("budget-principal-drift", _item("budgets", "budget-search-root", original_principal_id="attacker")),
    ("budget-tenant-drift", _item("budgets", "budget-search-root", tenant_id="tenant-B")),
    ("budget-goal-drift", _item("budgets", "budget-search-root", goal_id="goal-ticket")),
    ("budget-delegation-drift", _item("budgets", "budget-search-child", delegation_id="delegation-tool-child")),
    ("budget-model-ceiling-drift", _item("budgets", "budget-search-root", max_model_calls=99)),
    ("budget-tool-ceiling-drift", _item("budgets", "budget-search-root", max_tool_calls=99)),
    ("budget-token-ceiling-drift", _item("budgets", "budget-search-root", max_total_tokens=99999)),
    ("budget-cost-ceiling-drift", _item("budgets", "budget-search-root", max_cost_microusd=99999)),
    ("budget-elapsed-ceiling-drift", _item("budgets", "budget-search-root", max_elapsed_ms=99999)),
    ("budget-step-ceiling-drift", _item("budgets", "budget-search-root", max_steps=99)),
    ("budget-recursion-ceiling-drift", _item("budgets", "budget-search-root", max_recursion_depth=99)),
    ("budget-fanout-ceiling-drift", _item("budgets", "budget-search-root", max_fanout_per_event=99)),
    ("budget-retry-ceiling-drift", _item("budgets", "budget-search-root", max_retries_per_operation=99)),
    ("budget-loop-ceiling-drift", _item("budgets", "budget-search-root", max_repeated_operation_count=99)),
    ("budget-irreversible-ceiling-drift", _item("budgets", "budget-release-root", max_irreversible_actions=99)),
    ("budget-rate-ceiling-drift", _item("budgets", "budget-release-root", max_irreversible_actions_per_minute=99)),
    ("run-root-drift", _item("runs", "run-search", root_budget_id="budget-ticket-root")),
    ("run-principal-drift", _item("runs", "run-search", original_principal_id="attacker")),
    ("run-tenant-drift", _item("runs", "run-search", tenant_id="tenant-B")),
    ("run-goal-drift", _item("runs", "run-search", goal_id="goal-ticket")),
)

REFERENCE_CASES = (
    ("allocation-parent-unknown", _item("allocations", "alloc-search", parent_budget_id="missing")),
    ("allocation-child-unknown", _item("allocations", "alloc-search", child_budget_id="missing")),
    ("allocation-self-cycle", _item("allocations", "alloc-search", parent_budget_id="budget-search-child")),
    ("allocation-child-multiple-parents", _item("allocations", "alloc-ticket", child_budget_id="budget-search-child")),
    ("run-root-unknown", _item("runs", "run-search", root_budget_id="missing")),
    ("run-time-invalid", _item("runs", "run-search", completed_at_ms=NOW_MS - 20_000)),
    ("event-run-unknown", _item("events", "evt-search-model", run_id="missing")),
    ("event-budget-unknown", _item("events", "evt-search-model", budget_id="missing")),
    ("event-parent-unknown", _item("events", "evt-search-model", parent_event_id="missing")),
    ("event-cross-run-parent", _item("events", "evt-search-model", parent_event_id="evt-ticket-step")),
    ("event-time-before-run", _item("events", "evt-search-model", started_at_ms=NOW_MS - 20_000)),
    ("event-time-backwards", _item("events", "evt-search-model", ended_at_ms=NOW_MS - 9_400)),
    ("event-attempt-zero", _item("events", "evt-search-model", attempt=0)),
    ("model-id-unknown", _item("events", "evt-search-model", model_id="unknown-model")),
    ("model-input-negative", _item("events", "evt-search-model", input_tokens=-1)),
    ("non-model-has-model-id", _item("events", "evt-search-step", model_id=MODEL_SMALL)),
    ("non-model-has-tokens", _item("events", "evt-search-step", input_tokens=1)),
    ("claimed-cost-negative", _item("events", "evt-search-model", claimed_cost_microusd=-1)),
    ("tool-missing-observation", _item("events", "evt-search-tool", p8d_observation_id=None)),
    ("non-tool-has-observation", _item("events", "evt-search-model", p8d_observation_id="obs-search")),
    ("event-cycle", _item("events", "evt-search-step", parent_event_id="evt-search-tool")),
)

step_extra = ExecutionEvent("evt-search-extra-step", "run-search", "evt-search-tool", "budget-search-child", ExecutionEventType.AGENT_STEP, "step:extra", "agent-retrieval-a", "user-a", "tenant-A", "goal-search", "step-search", "delegation-retrieval", None, 0, 0, 0, 1, NOW_MS - 6_900, NOW_MS - 6_700, False, None, OWNER, "Extra search step.")
step_extra2 = replace(step_extra, event_id="evt-search-extra-step-2", parent_event_id="evt-search-extra-step", started_at_ms=NOW_MS - 6_600, ended_at_ms=NOW_MS - 6_400)
step_extra3 = replace(step_extra, event_id="evt-search-extra-step-3", parent_event_id="evt-search-extra-step-2", started_at_ms=NOW_MS - 6_300, ended_at_ms=NOW_MS - 6_100)
fanout1 = replace(step_extra, event_id="evt-search-fanout-1", parent_event_id="evt-search-step", operation_key="fanout:1")
fanout2 = replace(step_extra, event_id="evt-search-fanout-2", parent_event_id="evt-search-step", operation_key="fanout:2")
fanout3 = replace(step_extra, event_id="evt-search-fanout-3", parent_event_id="evt-search-step", operation_key="fanout:3")
release_extra = ExecutionEvent("evt-release-extra-tool", "run-release", "evt-release-step", "budget-release-child", ExecutionEventType.TOOL_CALL, "tool:release-extra", "agent-release-executor", "release-admin", "platform", "goal-release", "step-release", "delegation-release-deploy", None, 0, 0, 0, 1, NOW_MS - 25_900, NOW_MS - 25_200, True, "obs-release", OWNER, "Second irreversible release action.")


def _cost_limit_case(ctx):
    ctx = _coherent_rate(MODEL_SMALL, 200, 400)(ctx)
    ctx = _item("events", "evt-search-model", claimed_cost_microusd=300)(ctx)
    return ctx


def _model_call_limit_case(ctx):
    ctx = _item("events", "evt-search-step", event_type=ExecutionEventType.MODEL_CALL, model_id=MODEL_SMALL, input_tokens=100, output_tokens=10, claimed_cost_microusd=3)(ctx)
    ctx = _item("events", "evt-search-tool", event_type=ExecutionEventType.MODEL_CALL, model_id=MODEL_SMALL, input_tokens=100, output_tokens=10, claimed_cost_microusd=3, p8d_observation_id=None)(ctx)
    return ctx


def _tool_call_limit_case(ctx):
    ctx = _item("events", "evt-search-step", event_type=ExecutionEventType.TOOL_CALL, p8d_observation_id="obs-search")(ctx)
    ctx = _item("events", "evt-search-model", event_type=ExecutionEventType.TOOL_CALL, model_id=None, input_tokens=0, output_tokens=0, claimed_cost_microusd=0, p8d_observation_id="obs-search")(ctx)
    return ctx


def _loop_case(ctx):
    for event_id in ("evt-search-step", "evt-search-model", "evt-search-tool"):
        ctx = _item("events", event_id, operation_key="repeat:search")(ctx)
    return ctx


def _irreversible_rate_case(ctx):
    return _add_event(release_extra)(ctx)

SEMANTIC_CASES = (
    ("model-call-limit", _model_call_limit_case),
    ("tool-call-limit", _tool_call_limit_case),
    ("token-limit", _item("events", "evt-search-model", input_tokens=2600, output_tokens=0, claimed_cost_microusd=52)),
    ("cost-limit", _cost_limit_case),
    ("elapsed-limit", _coherent_run("run-search", completed_at_ms=NOW_MS + 15_000)),
    ("step-limit", _combine(_add_event(step_extra), _add_event(step_extra2), _add_event(step_extra3))),
    ("recursion-limit", _combine(_add_event(step_extra), _add_event(step_extra2))),
    ("fanout-limit", _combine(_add_event(fanout1), _add_event(fanout2), _add_event(fanout3))),
    ("retry-limit", _item("events", "evt-search-model", attempt=3)),
    ("loop-detected", _loop_case),
    ("irreversible-count-limit", _combine(_add_event(release_extra), _coherent_budget("budget-release-child", max_irreversible_actions=2), _coherent_budget("budget-release-root", max_irreversible_actions=1))),
    ("irreversible-rate-limit", _irreversible_rate_case),
    ("delegated-budget-amplification-model", _coherent_budget("budget-search-child", max_model_calls=3)),
    ("delegated-budget-amplification-cost", _coherent_budget("budget-search-child", max_cost_microusd=300)),
    ("delegated-budget-oversubscription", _item("allocations", "alloc-ticket", parent_budget_id="budget-search-root")),
    ("cost-claim-suppression", _item("events", "evt-search-model", claimed_cost_microusd=0)),
    ("event-principal-mismatch", _item("events", "evt-search-tool", original_principal_id="attacker")),
    ("event-tenant-mismatch", _item("events", "evt-search-tool", tenant_id="tenant-B")),
    ("event-goal-mismatch", _item("events", "evt-search-tool", goal_id="goal-ticket")),
    ("event-delegation-mismatch", _item("events", "evt-search-tool", delegation_id="delegation-tool-child")),
    ("allocation-delegation-mismatch", _item("allocations", "alloc-search", delegation_id="delegation-tool-child")),
    ("allocation-delegatee-mismatch", _item("allocations", "alloc-search", delegatee_agent_id="agent-tool-executor")),
    ("upstream-delegation-denied", lambda ctx: {**ctx, **make_upstreams(denied_delegations=frozenset({"delegation-retrieval"}))}),
    ("upstream-plan-step-denied", lambda ctx: {**ctx, **make_upstreams(denied_steps=frozenset({"step-search"}))}),
    ("upstream-tool-observation-denied", lambda ctx: {**ctx, **make_upstreams(denied_observations=frozenset({"obs-search"}))}),
)

CALLER_CASES = (
    ("caller-fake-denied-run", _request("declared_denied_run_ids", ("run-search",))),
    ("caller-fake-risk", _request("declared_risks_by_run", {run_id: ((BudgetRisk.COST_LIMIT,) if run_id == "run-search" else ()) for run_id in RUN_IDS})),
    ("caller-risk-map-omission", _request("declared_risks_by_run", {run_id: () for run_id in RUN_IDS if run_id != "run-search"})),
    ("caller-max-risk-forgery", _request("declared_max_risk_score", 999)),
)

ADVERSARIAL_CASES = REQUEST_CASES + MANIFEST_CASES + UPSTREAM_CASES + COVERAGE_CASES + OWNER_CASES + POLICY_CASES + DRIFT_CASES + REFERENCE_CASES + SEMANTIC_CASES + CALLER_CASES
EXPECTED_ADVERSARIAL_CASES = len(ADVERSARIAL_CASES)


def _hardened_attack_succeeds(ctx: dict[str, object]) -> bool:
    try:
        result = AgentExecutionBudgetSecurityAnalyzer(ctx["policy"]).evaluate(ctx["request"], ctx["manifest"], ctx["p8a"], ctx["p8c"], ctx["p8d"])
    except ExecutionBudgetSecurityRejected:
        return False
    return result.denied_run_count == 0


def _truthful_retry_context():
    ctx = _item("events", "evt-search-model", attempt=3)(_clone())
    ctx["request"] = truthful_request_for_context(ctx)
    return ctx


def _truthful_cost_context():
    ctx = _cost_limit_case(_clone())
    ctx["request"] = truthful_request_for_context(ctx)
    return ctx


def benign_contexts():
    return (
        ("safe-resource-budget", _clone()),
        ("truthful-retry-denial", _truthful_retry_context()),
        ("truthful-cost-denial", _truthful_cost_context()),
    )


def run():
    weak = VulnerableDeclaredExecutionBudgetSafety()
    vulnerable_successes = 0
    hardened_successes = 0
    cases = []
    for case_id, mutation in ADVERSARIAL_CASES:
        ctx = mutation(_clone())
        vulnerable = weak.evaluate(
            declared_within_budget=True,
            declared_no_runaway_loop=True,
            declared_no_resource_exhaustion=True,
            declared_cost_microusd=0,
            declared_steps=0,
        ).accepted
        hardened = _hardened_attack_succeeds(ctx)
        vulnerable_successes += int(vulnerable)
        hardened_successes += int(hardened)
        cases.append({"case_id": case_id, "vulnerable_success": vulnerable, "hardened_success": hardened})

    false_positives = 0
    safe_successes = 0
    benign = []
    for case_id, ctx in benign_contexts():
        accepted = True
        try:
            AgentExecutionBudgetSecurityAnalyzer(ctx["policy"]).evaluate(ctx["request"], ctx["manifest"], ctx["p8a"], ctx["p8c"], ctx["p8d"])
        except ExecutionBudgetSecurityRejected:
            accepted = False
        false_positives += int(not accepted)
        safe_successes += int(accepted)
        benign.append({"case_id": case_id, "accepted": accepted})

    fixture = build_fixture()
    dataset_sha = hashlib.sha256(json.dumps([case_id for case_id, _ in ADVERSARIAL_CASES], separators=(",", ":")).encode()).hexdigest()
    fixture_doc = {
        "graph_sha256": fixture["request"].graph_sha256,
        "run_ids": list(fixture["request"].run_ids),
        "p8a": P8A_DIGEST,
        "p8c": P8C_DIGEST,
        "p8d": P8D_DIGEST,
    }
    fixture_sha = hashlib.sha256(json.dumps(fixture_doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "adversarial_cases": len(ADVERSARIAL_CASES),
        "vulnerable_asr": f"{vulnerable_successes}/{len(ADVERSARIAL_CASES)}",
        "hardened_asr": f"{hardened_successes}/{len(ADVERSARIAL_CASES)}",
        "hardened_fpr": f"{false_positives}/{len(benign)}",
        "safe_task_rate": f"{safe_successes}/{len(benign)}",
        "graph_sha256": fixture["request"].graph_sha256,
        "dataset_sha256": dataset_sha,
        "fixture_sha256": fixture_sha,
        "cases": cases,
        "benign": benign,
    }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2, sort_keys=True))
    assert result["vulnerable_asr"] == f"{EXPECTED_ADVERSARIAL_CASES}/{EXPECTED_ADVERSARIAL_CASES}"
    assert result["hardened_asr"] == f"0/{EXPECTED_ADVERSARIAL_CASES}"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
