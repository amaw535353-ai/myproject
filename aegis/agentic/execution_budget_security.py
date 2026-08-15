from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, is_dataclass
from enum import StrEnum
from typing import Mapping

P8E_BUDGET_POLICY_VERSION = "agent-execution-budget-runaway-resource-security-v1"
P8E_BUDGET_SCHEMA_VERSION = "aegis-agent-execution-budget-manifest-v1"
P8E_ASSESSMENT_SCHEMA_VERSION = "aegis-agent-execution-budget-assessment-v1"
P8E_ASSESSMENT_MODE = "deterministic-evidence-bound-agent-resource-budget-v1"


class ExecutionEventType(StrEnum):
    AGENT_STEP = "agent_step"
    MODEL_CALL = "model_call"
    TOOL_CALL = "tool_call"


class BudgetDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class BudgetRisk(StrEnum):
    MODEL_CALL_LIMIT = "model_call_limit"
    TOOL_CALL_LIMIT = "tool_call_limit"
    TOKEN_LIMIT = "token_limit"
    COST_LIMIT = "cost_limit"
    ELAPSED_LIMIT = "elapsed_limit"
    STEP_LIMIT = "step_limit"
    RECURSION_LIMIT = "recursion_limit"
    FANOUT_LIMIT = "fanout_limit"
    RETRY_LIMIT = "retry_limit"
    LOOP_DETECTED = "loop_detected"
    IRREVERSIBLE_COUNT_LIMIT = "irreversible_count_limit"
    IRREVERSIBLE_RATE_LIMIT = "irreversible_rate_limit"
    DELEGATED_BUDGET_AMPLIFICATION = "delegated_budget_amplification"
    DELEGATED_BUDGET_OVERSUBSCRIBED = "delegated_budget_oversubscribed"
    COST_CLAIM_MISMATCH = "cost_claim_mismatch"
    IDENTITY_MISMATCH = "identity_mismatch"
    TENANT_MISMATCH = "tenant_mismatch"
    GOAL_MISMATCH = "goal_mismatch"
    UPSTREAM_DELEGATION_UNSAFE = "upstream_delegation_unsafe"
    UPSTREAM_PLAN_UNSAFE = "upstream_plan_unsafe"
    UPSTREAM_TOOL_OBSERVATION_UNSAFE = "upstream_tool_observation_unsafe"


class BudgetRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    UPSTREAM_INVALID = "upstream_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    COVERAGE_MISMATCH = "coverage_mismatch"
    OWNER_UNTRUSTED = "owner_untrusted"
    POLICY_DRIFT = "policy_drift"
    REFERENCE_INVALID = "reference_invalid"
    GRAPH_CYCLE = "graph_cycle"
    DECLARED_DECISION_MISMATCH = "declared_decision_mismatch"
    DECLARED_RISK_MISMATCH = "declared_risk_mismatch"


class ExecutionBudgetSecurityRejected(ValueError):
    def __init__(self, reason: BudgetRejectReason, message: str, *, item_id: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.item_id = item_id


@dataclass(frozen=True)
class ModelCostRate:
    model_id: str
    input_microusd_per_1k_tokens: int
    output_microusd_per_1k_tokens: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class BudgetEnvelope:
    budget_id: str
    original_principal_id: str
    tenant_id: str
    goal_id: str
    delegation_id: str | None
    max_model_calls: int
    max_tool_calls: int
    max_total_tokens: int
    max_cost_microusd: int
    max_elapsed_ms: int
    max_steps: int
    max_recursion_depth: int
    max_fanout_per_event: int
    max_retries_per_operation: int
    max_repeated_operation_count: int
    max_irreversible_actions: int
    max_irreversible_actions_per_minute: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class BudgetAllocation:
    allocation_id: str
    parent_budget_id: str
    child_budget_id: str
    delegator_agent_id: str
    delegatee_agent_id: str
    delegation_id: str
    owner_id: str
    description: str


@dataclass(frozen=True)
class ExecutionRun:
    run_id: str
    root_budget_id: str
    original_principal_id: str
    tenant_id: str
    goal_id: str
    started_at_ms: int
    completed_at_ms: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class ExecutionEvent:
    event_id: str
    run_id: str
    parent_event_id: str | None
    budget_id: str
    event_type: ExecutionEventType
    operation_key: str
    agent_id: str
    original_principal_id: str
    tenant_id: str
    goal_id: str
    step_id: str
    delegation_id: str | None
    model_id: str | None
    input_tokens: int
    output_tokens: int
    claimed_cost_microusd: int
    attempt: int
    started_at_ms: int
    ended_at_ms: int
    irreversible: bool
    p8d_observation_id: str | None
    owner_id: str
    description: str


@dataclass(frozen=True)
class ExecutionBudgetManifest:
    graph_id: str
    version: str
    p8a_assessment_evidence_sha256: str
    p8c_assessment_evidence_sha256: str
    p8d_assessment_evidence_sha256: str
    created_at_epoch: int
    model_rates: tuple[ModelCostRate, ...]
    budgets: tuple[BudgetEnvelope, ...]
    allocations: tuple[BudgetAllocation, ...]
    runs: tuple[ExecutionRun, ...]
    events: tuple[ExecutionEvent, ...]
    schema_version: str = P8E_BUDGET_SCHEMA_VERSION


@dataclass(frozen=True)
class ExecutionBudgetPolicy:
    expected_graph_id: str
    expected_graph_version: str
    expected_graph_sha256: str
    expected_p8a_assessment_evidence_sha256: str
    expected_p8c_assessment_evidence_sha256: str
    expected_p8d_assessment_evidence_sha256: str
    required_model_ids: frozenset[str]
    required_budget_ids: frozenset[str]
    required_allocation_ids: frozenset[str]
    required_run_ids: frozenset[str]
    required_event_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    expected_model_rates: Mapping[str, tuple[int, int]]
    expected_budget_profiles: Mapping[str, tuple[object, ...]]
    expected_run_bindings: Mapping[str, tuple[str, str, str, str]]
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class ExecutionBudgetRequest:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8a_assessment_evidence_sha256: str
    p8c_assessment_evidence_sha256: str
    p8d_assessment_evidence_sha256: str
    evaluated_at_epoch: int
    run_ids: tuple[str, ...]
    declared_denied_run_ids: tuple[str, ...]
    declared_risks_by_run: Mapping[str, tuple[BudgetRisk, ...]]
    declared_max_risk_score: int


@dataclass(frozen=True)
class ExecutionBudgetFact:
    run_id: str
    decision: BudgetDecision
    risks: tuple[BudgetRisk, ...]
    model_calls: int
    tool_calls: int
    total_tokens: int
    derived_cost_microusd: int
    elapsed_ms: int
    steps: int
    max_recursion_depth: int
    max_fanout: int
    max_retry_count: int
    max_repeated_operation_count: int
    irreversible_actions: int
    max_irreversible_actions_per_minute: int
    risk_score: int


@dataclass(frozen=True)
class VerifiedExecutionBudgetAssessment:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8a_assessment_evidence_sha256: str
    p8c_assessment_evidence_sha256: str
    p8d_assessment_evidence_sha256: str
    run_count: int
    allowed_run_count: int
    denied_run_count: int
    budget_exhaustion_denial_count: int
    loop_or_retry_denial_count: int
    delegated_budget_denial_count: int
    irreversible_action_denial_count: int
    upstream_safety_denial_count: int
    maximum_risk_score: int
    prioritized_denied_run_ids: tuple[str, ...]
    runs: tuple[ExecutionBudgetFact, ...]
    assessment_evidence_sha256: str
    exact_execution_budget_graph_binding_verified: bool = True
    exact_p8a_delegation_binding_verified: bool = True
    exact_p8c_goal_plan_binding_verified: bool = True
    exact_p8d_tool_observation_binding_verified: bool = True
    delegated_budget_non_amplification_verified: bool = True
    recursion_and_fanout_limits_evaluated: bool = True
    retry_and_loop_limits_evaluated: bool = True
    model_cost_derived_from_policy_rates: bool = True
    irreversible_action_rate_limits_evaluated: bool = True
    caller_declared_resource_safety_trusted: bool = False
    production_provider_billing_enforcement: bool = False
    production_runtime_kill_switch: bool = False
    real_time_cost_accuracy: bool = False
    distributed_resource_accounting: bool = False
    exhaustive_loop_detection: bool = False
    network_operations: int = 0
    schema_version: str = P8E_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P8E_BUDGET_POLICY_VERSION
    assessment_mode: str = P8E_ASSESSMENT_MODE


def _reject(reason: BudgetRejectReason, message: str, item_id: str | None = None) -> None:
    raise ExecutionBudgetSecurityRejected(reason, message, item_id=item_id)


def _sha(value: str) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value.casefold())


def _digest(value: object) -> str:
    return str(getattr(value, "assessment_evidence_sha256", "")).casefold()


def _decision_allowed(value: object) -> bool:
    raw = getattr(value, "decision", "")
    return str(getattr(raw, "value", raw)).casefold() in {"allow", "allowed", "safe"}


def _norm(value: object):
    if is_dataclass(value):
        return _norm(asdict(value))
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _norm(value[key]) for key in sorted(value)}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_norm(item) for item in sorted(value, key=lambda item: str(getattr(item, "value", item)))]
    if isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value):
        return value.casefold()
    return value


def canonical_execution_budget_manifest_bytes(manifest: ExecutionBudgetManifest) -> bytes:
    return json.dumps(_norm(manifest), sort_keys=True, separators=(",", ":")).encode("utf-8")


def execution_budget_manifest_digest(manifest: ExecutionBudgetManifest) -> str:
    return hashlib.sha256(canonical_execution_budget_manifest_bytes(manifest)).hexdigest()


def _profile(budget: BudgetEnvelope) -> tuple[object, ...]:
    return (
        budget.original_principal_id,
        budget.tenant_id,
        budget.goal_id,
        budget.delegation_id,
        budget.max_model_calls,
        budget.max_tool_calls,
        budget.max_total_tokens,
        budget.max_cost_microusd,
        budget.max_elapsed_ms,
        budget.max_steps,
        budget.max_recursion_depth,
        budget.max_fanout_per_event,
        budget.max_retries_per_operation,
        budget.max_repeated_operation_count,
        budget.max_irreversible_actions,
        budget.max_irreversible_actions_per_minute,
    )


def _risk_score(risk: BudgetRisk) -> int:
    return {
        BudgetRisk.DELEGATED_BUDGET_AMPLIFICATION: 120,
        BudgetRisk.DELEGATED_BUDGET_OVERSUBSCRIBED: 116,
        BudgetRisk.IRREVERSIBLE_RATE_LIMIT: 112,
        BudgetRisk.IRREVERSIBLE_COUNT_LIMIT: 108,
        BudgetRisk.COST_CLAIM_MISMATCH: 104,
        BudgetRisk.COST_LIMIT: 102,
        BudgetRisk.LOOP_DETECTED: 100,
        BudgetRisk.RETRY_LIMIT: 98,
        BudgetRisk.RECURSION_LIMIT: 96,
        BudgetRisk.FANOUT_LIMIT: 94,
        BudgetRisk.MODEL_CALL_LIMIT: 90,
        BudgetRisk.TOOL_CALL_LIMIT: 88,
        BudgetRisk.TOKEN_LIMIT: 86,
        BudgetRisk.STEP_LIMIT: 84,
        BudgetRisk.ELAPSED_LIMIT: 82,
        BudgetRisk.UPSTREAM_TOOL_OBSERVATION_UNSAFE: 80,
        BudgetRisk.UPSTREAM_PLAN_UNSAFE: 78,
        BudgetRisk.UPSTREAM_DELEGATION_UNSAFE: 76,
        BudgetRisk.IDENTITY_MISMATCH: 74,
        BudgetRisk.TENANT_MISMATCH: 72,
        BudgetRisk.GOAL_MISMATCH: 70,
    }[risk]


def _ceil_cost(tokens: int, rate: int) -> int:
    return (tokens * rate + 999) // 1000


class AgentExecutionBudgetSecurityAnalyzer:
    def __init__(self, policy: ExecutionBudgetPolicy) -> None:
        self.policy = policy

    def _validate_policy(self) -> None:
        p = self.policy
        if (
            not p.expected_graph_id
            or not p.expected_graph_version
            or not all(_sha(value) for value in (p.expected_graph_sha256, p.expected_p8a_assessment_evidence_sha256, p.expected_p8c_assessment_evidence_sha256, p.expected_p8d_assessment_evidence_sha256))
            or not p.required_model_ids
            or not p.required_budget_ids
            or not p.required_run_ids
            or not p.required_event_ids
            or not p.trusted_owner_ids
            or p.max_manifest_age_seconds <= 0
            or p.max_future_skew_seconds < 0
            or set(p.expected_model_rates) != set(p.required_model_ids)
            or set(p.expected_budget_profiles) != set(p.required_budget_ids)
            or set(p.expected_run_bindings) != set(p.required_run_ids)
        ):
            _reject(BudgetRejectReason.POLICY_INVALID, "invalid execution-budget policy")
        if any(inp < 0 or out < 0 for inp, out in p.expected_model_rates.values()):
            _reject(BudgetRejectReason.POLICY_INVALID, "model cost rates must be non-negative")

    def _validate_upstreams(self, manifest: ExecutionBudgetManifest, p8a: object, p8c: object, p8d: object) -> None:
        checks = (
            (p8a, self.policy.expected_p8a_assessment_evidence_sha256, manifest.p8a_assessment_evidence_sha256, "exact_delegation_graph_binding_verified", "caller_declared_delegation_authorization_trusted"),
            (p8c, self.policy.expected_p8c_assessment_evidence_sha256, manifest.p8c_assessment_evidence_sha256, "exact_goal_plan_graph_binding_verified", "caller_declared_goal_safety_trusted"),
            (p8d, self.policy.expected_p8d_assessment_evidence_sha256, manifest.p8d_assessment_evidence_sha256, "exact_tool_observation_graph_binding_verified", "caller_declared_tool_observation_safety_trusted"),
        )
        for evidence, pin, manifest_pin, verified_flag, caller_flag in checks:
            if (
                _digest(evidence) != pin.casefold()
                or manifest_pin.casefold() != pin.casefold()
                or not bool(getattr(evidence, verified_flag, False))
                or bool(getattr(evidence, caller_flag, True))
            ):
                _reject(BudgetRejectReason.UPSTREAM_INVALID, "unverified upstream evidence")

    def _map(self, items: tuple[object, ...], attribute: str) -> dict[str, object]:
        result: dict[str, object] = {}
        for item in items:
            key = str(getattr(item, attribute, ""))
            if not key or key in result:
                _reject(BudgetRejectReason.COVERAGE_MISMATCH, "duplicate or empty identifier", key or None)
            result[key] = item
        return result

    def _validate_manifest(self, manifest: ExecutionBudgetManifest, evaluated_at_epoch: int):
        p = self.policy
        digest = execution_budget_manifest_digest(manifest)
        if (
            manifest.schema_version != P8E_BUDGET_SCHEMA_VERSION
            or manifest.graph_id != p.expected_graph_id
            or manifest.version != p.expected_graph_version
            or not hmac.compare_digest(digest, p.expected_graph_sha256.casefold())
            or evaluated_at_epoch - manifest.created_at_epoch > p.max_manifest_age_seconds
            or manifest.created_at_epoch - evaluated_at_epoch > p.max_future_skew_seconds
        ):
            _reject(BudgetRejectReason.MANIFEST_INVALID, "manifest binding/freshness invalid")

        rates = self._map(manifest.model_rates, "model_id")
        budgets = self._map(manifest.budgets, "budget_id")
        allocations = self._map(manifest.allocations, "allocation_id")
        runs = self._map(manifest.runs, "run_id")
        events = self._map(manifest.events, "event_id")
        for got, required in (
            (rates, p.required_model_ids),
            (budgets, p.required_budget_ids),
            (allocations, p.required_allocation_ids),
            (runs, p.required_run_ids),
            (events, p.required_event_ids),
        ):
            if set(got) != set(required):
                _reject(BudgetRejectReason.COVERAGE_MISMATCH, "manifest coverage mismatch")

        for model_id, rate in rates.items():
            if rate.owner_id not in p.trusted_owner_ids:
                _reject(BudgetRejectReason.OWNER_UNTRUSTED, "untrusted model-rate owner", model_id)
            if (rate.input_microusd_per_1k_tokens, rate.output_microusd_per_1k_tokens) != p.expected_model_rates[model_id]:
                _reject(BudgetRejectReason.POLICY_DRIFT, "model-rate drift", model_id)

        for budget_id, budget in budgets.items():
            if budget.owner_id not in p.trusted_owner_ids:
                _reject(BudgetRejectReason.OWNER_UNTRUSTED, "untrusted budget owner", budget_id)
            if _profile(budget) != p.expected_budget_profiles[budget_id]:
                _reject(BudgetRejectReason.POLICY_DRIFT, "budget profile drift", budget_id)
            numeric = (
                budget.max_model_calls,
                budget.max_tool_calls,
                budget.max_total_tokens,
                budget.max_cost_microusd,
                budget.max_elapsed_ms,
                budget.max_steps,
                budget.max_recursion_depth,
                budget.max_fanout_per_event,
                budget.max_retries_per_operation,
                budget.max_repeated_operation_count,
                budget.max_irreversible_actions,
                budget.max_irreversible_actions_per_minute,
            )
            if any(value < 0 for value in numeric) or budget.max_elapsed_ms <= 0 or budget.max_recursion_depth <= 0 or budget.max_fanout_per_event <= 0 or budget.max_repeated_operation_count <= 0:
                _reject(BudgetRejectReason.POLICY_DRIFT, "invalid budget ceiling", budget_id)

        parent_of: dict[str, str] = {}
        allocation_by_child: dict[str, BudgetAllocation] = {}
        for allocation_id, allocation in allocations.items():
            if allocation.owner_id not in p.trusted_owner_ids:
                _reject(BudgetRejectReason.OWNER_UNTRUSTED, "untrusted allocation owner", allocation_id)
            if allocation.parent_budget_id not in budgets or allocation.child_budget_id not in budgets or allocation.parent_budget_id == allocation.child_budget_id:
                _reject(BudgetRejectReason.REFERENCE_INVALID, "invalid budget allocation reference", allocation_id)
            if allocation.child_budget_id in parent_of:
                _reject(BudgetRejectReason.REFERENCE_INVALID, "child budget has multiple parents", allocation.child_budget_id)
            parent_of[allocation.child_budget_id] = allocation.parent_budget_id
            allocation_by_child[allocation.child_budget_id] = allocation

        for budget_id in budgets:
            seen: set[str] = set()
            current = budget_id
            while current in parent_of:
                if current in seen:
                    _reject(BudgetRejectReason.GRAPH_CYCLE, "budget allocation cycle", budget_id)
                seen.add(current)
                current = parent_of[current]

        for run_id, run in runs.items():
            if run.owner_id not in p.trusted_owner_ids:
                _reject(BudgetRejectReason.OWNER_UNTRUSTED, "untrusted run owner", run_id)
            if run.root_budget_id not in budgets or run.completed_at_ms < run.started_at_ms:
                _reject(BudgetRejectReason.REFERENCE_INVALID, "invalid run reference/time", run_id)
            if (run.root_budget_id, run.original_principal_id, run.tenant_id, run.goal_id) != p.expected_run_bindings[run_id]:
                _reject(BudgetRejectReason.POLICY_DRIFT, "run binding drift", run_id)
            if run.root_budget_id in parent_of:
                _reject(BudgetRejectReason.REFERENCE_INVALID, "run root budget is not a root", run_id)

        for event_id, event in events.items():
            if event.owner_id not in p.trusted_owner_ids:
                _reject(BudgetRejectReason.OWNER_UNTRUSTED, "untrusted event owner", event_id)
            if event.run_id not in runs or event.budget_id not in budgets or event.started_at_ms < runs[event.run_id].started_at_ms or event.ended_at_ms < event.started_at_ms or event.ended_at_ms > runs[event.run_id].completed_at_ms or event.attempt <= 0:
                _reject(BudgetRejectReason.REFERENCE_INVALID, "invalid event run/budget/time", event_id)
            if event.parent_event_id is not None and event.parent_event_id not in events:
                _reject(BudgetRejectReason.REFERENCE_INVALID, "unknown parent event", event_id)
            if event.parent_event_id is not None and events[event.parent_event_id].run_id != event.run_id:
                _reject(BudgetRejectReason.REFERENCE_INVALID, "cross-run parent event", event_id)
            if event.event_type == ExecutionEventType.MODEL_CALL:
                if event.model_id not in rates or event.input_tokens < 0 or event.output_tokens < 0:
                    _reject(BudgetRejectReason.REFERENCE_INVALID, "invalid model-call accounting", event_id)
            elif event.model_id is not None or event.input_tokens != 0 or event.output_tokens != 0:
                _reject(BudgetRejectReason.REFERENCE_INVALID, "non-model event carries model accounting", event_id)
            if event.claimed_cost_microusd < 0:
                _reject(BudgetRejectReason.REFERENCE_INVALID, "negative claimed cost", event_id)
            if event.event_type == ExecutionEventType.TOOL_CALL and not event.p8d_observation_id:
                _reject(BudgetRejectReason.REFERENCE_INVALID, "tool call lacks P8-D observation binding", event_id)
            if event.event_type != ExecutionEventType.TOOL_CALL and event.p8d_observation_id is not None:
                _reject(BudgetRejectReason.REFERENCE_INVALID, "non-tool event has P8-D observation binding", event_id)

        for event_id in events:
            seen: set[str] = set()
            current: str | None = event_id
            while current is not None:
                if current in seen:
                    _reject(BudgetRejectReason.GRAPH_CYCLE, "execution-event graph contains cycle", event_id)
                seen.add(current)
                current = events[current].parent_event_id

        return rates, budgets, allocations, runs, events, parent_of, allocation_by_child, digest

    def derive(self, manifest: ExecutionBudgetManifest, p8a: object, p8c: object, p8d: object, evaluated_at_epoch: int) -> tuple[ExecutionBudgetFact, ...]:
        self._validate_policy()
        self._validate_upstreams(manifest, p8a, p8c, p8d)
        rates, budgets, allocations, runs, events, parent_of, allocation_by_child, _ = self._validate_manifest(manifest, evaluated_at_epoch)
        delegations = {str(getattr(item, "delegation_id", "")): item for item in getattr(p8a, "delegations", ())}
        steps = {str(getattr(item, "step_id", "")): item for item in getattr(p8c, "steps", ())}
        observations = {str(getattr(item, "observation_id", "")): item for item in getattr(p8d, "observations", ())}

        children: dict[str, list[str]] = {event_id: [] for event_id in events}
        for event in events.values():
            if event.parent_event_id is not None:
                children[event.parent_event_id].append(event.event_id)

        budget_children: dict[str, list[str]] = {budget_id: [] for budget_id in budgets}
        for child, parent in parent_of.items():
            budget_children[parent].append(child)

        def descendants(root_budget_id: str) -> set[str]:
            result = {root_budget_id}
            stack = [root_budget_id]
            while stack:
                current = stack.pop()
                for child in budget_children[current]:
                    if child not in result:
                        result.add(child)
                        stack.append(child)
            return result

        allocation_risks_by_root: dict[str, set[BudgetRisk]] = {run.root_budget_id: set() for run in runs.values()}
        additive_indexes = (4, 5, 6, 7, 9, 14)
        for child_budget_id, parent_budget_id in parent_of.items():
            child_profile = _profile(budgets[child_budget_id])
            parent_profile = _profile(budgets[parent_budget_id])
            if any(int(child_profile[index]) > int(parent_profile[index]) for index in range(4, 16)):
                root = parent_budget_id
                while root in parent_of:
                    root = parent_of[root]
                allocation_risks_by_root.setdefault(root, set()).add(BudgetRisk.DELEGATED_BUDGET_AMPLIFICATION)
        for parent_budget_id, child_ids in budget_children.items():
            if not child_ids:
                continue
            parent_profile = _profile(budgets[parent_budget_id])
            for index in additive_indexes:
                if sum(int(_profile(budgets[child_id])[index]) for child_id in child_ids) > int(parent_profile[index]):
                    root = parent_budget_id
                    while root in parent_of:
                        root = parent_of[root]
                    allocation_risks_by_root.setdefault(root, set()).add(BudgetRisk.DELEGATED_BUDGET_OVERSUBSCRIBED)

        for allocation in allocations.values():
            child = budgets[allocation.child_budget_id]
            if child.delegation_id != allocation.delegation_id:
                root = allocation.parent_budget_id
                while root in parent_of:
                    root = parent_of[root]
                allocation_risks_by_root.setdefault(root, set()).add(BudgetRisk.IDENTITY_MISMATCH)
            fact = delegations.get(allocation.delegation_id)
            if fact is None or not _decision_allowed(fact):
                root = allocation.parent_budget_id
                while root in parent_of:
                    root = parent_of[root]
                allocation_risks_by_root.setdefault(root, set()).add(BudgetRisk.UPSTREAM_DELEGATION_UNSAFE)
            elif str(getattr(fact, "delegatee_agent_id", allocation.delegatee_agent_id)) != allocation.delegatee_agent_id:
                root = allocation.parent_budget_id
                while root in parent_of:
                    root = parent_of[root]
                allocation_risks_by_root.setdefault(root, set()).add(BudgetRisk.IDENTITY_MISMATCH)

        facts: list[ExecutionBudgetFact] = []
        for run_id in sorted(runs):
            run = runs[run_id]
            root_budget = budgets[run.root_budget_id]
            run_budget_ids = descendants(run.root_budget_id)
            run_events = [event for event in events.values() if event.run_id == run_id]
            risks = set(allocation_risks_by_root.get(run.root_budget_id, set()))

            if root_budget.original_principal_id != run.original_principal_id:
                risks.add(BudgetRisk.IDENTITY_MISMATCH)
            if root_budget.tenant_id != run.tenant_id:
                risks.add(BudgetRisk.TENANT_MISMATCH)
            if root_budget.goal_id != run.goal_id:
                risks.add(BudgetRisk.GOAL_MISMATCH)

            derived_costs: dict[str, int] = {}
            for event in run_events:
                budget = budgets[event.budget_id]
                if event.budget_id not in run_budget_ids:
                    risks.add(BudgetRisk.IDENTITY_MISMATCH)
                if event.original_principal_id != run.original_principal_id or budget.original_principal_id != run.original_principal_id:
                    risks.add(BudgetRisk.IDENTITY_MISMATCH)
                if event.tenant_id != run.tenant_id or budget.tenant_id != run.tenant_id:
                    risks.add(BudgetRisk.TENANT_MISMATCH)
                if event.goal_id != run.goal_id or budget.goal_id != run.goal_id:
                    risks.add(BudgetRisk.GOAL_MISMATCH)
                if event.delegation_id != budget.delegation_id:
                    if not (event.budget_id == run.root_budget_id and event.delegation_id is None and budget.delegation_id is None):
                        risks.add(BudgetRisk.IDENTITY_MISMATCH)
                if event.delegation_id is not None:
                    delegation = delegations.get(event.delegation_id)
                    if delegation is None or not _decision_allowed(delegation):
                        risks.add(BudgetRisk.UPSTREAM_DELEGATION_UNSAFE)
                step = steps.get(event.step_id)
                if step is None or not _decision_allowed(step):
                    risks.add(BudgetRisk.UPSTREAM_PLAN_UNSAFE)
                if event.event_type == ExecutionEventType.TOOL_CALL:
                    observation = observations.get(event.p8d_observation_id or "")
                    if observation is None or not _decision_allowed(observation):
                        risks.add(BudgetRisk.UPSTREAM_TOOL_OBSERVATION_UNSAFE)
                    else:
                        if str(getattr(observation, "tenant_id", event.tenant_id)) != event.tenant_id:
                            risks.add(BudgetRisk.TENANT_MISMATCH)
                        if str(getattr(observation, "goal_id", event.goal_id)) != event.goal_id:
                            risks.add(BudgetRisk.GOAL_MISMATCH)
                if event.event_type == ExecutionEventType.MODEL_CALL:
                    rate = rates[event.model_id or ""]
                    cost = _ceil_cost(event.input_tokens, rate.input_microusd_per_1k_tokens) + _ceil_cost(event.output_tokens, rate.output_microusd_per_1k_tokens)
                else:
                    cost = 0
                derived_costs[event.event_id] = cost
                if event.claimed_cost_microusd != cost:
                    risks.add(BudgetRisk.COST_CLAIM_MISMATCH)

            depth_cache: dict[str, int] = {}
            def depth(event_id: str) -> int:
                if event_id in depth_cache:
                    return depth_cache[event_id]
                event = events[event_id]
                value = 1 if event.parent_event_id is None else depth(event.parent_event_id) + 1
                depth_cache[event_id] = value
                return value

            model_calls = sum(event.event_type == ExecutionEventType.MODEL_CALL for event in run_events)
            tool_calls = sum(event.event_type == ExecutionEventType.TOOL_CALL for event in run_events)
            total_tokens = sum(event.input_tokens + event.output_tokens for event in run_events)
            derived_cost = sum(derived_costs[event.event_id] for event in run_events)
            elapsed_ms = run.completed_at_ms - run.started_at_ms
            steps_count = sum(event.event_type == ExecutionEventType.AGENT_STEP for event in run_events)
            max_depth = max((depth(event.event_id) for event in run_events), default=0)
            max_fanout = max((len(children[event.event_id]) for event in run_events), default=0)
            max_retry = max((event.attempt - 1 for event in run_events), default=0)
            counts_by_operation: dict[str, int] = {}
            for event in run_events:
                counts_by_operation[event.operation_key] = counts_by_operation.get(event.operation_key, 0) + 1
            max_repeat = max(counts_by_operation.values(), default=0)
            irreversible_times = sorted(event.started_at_ms for event in run_events if event.irreversible)
            irreversible_actions = len(irreversible_times)
            max_irreversible_rate = 0
            for index, started in enumerate(irreversible_times):
                count = 1
                for later in irreversible_times[index + 1 :]:
                    if later - started < 60_000:
                        count += 1
                    else:
                        break
                max_irreversible_rate = max(max_irreversible_rate, count)

            if model_calls > root_budget.max_model_calls:
                risks.add(BudgetRisk.MODEL_CALL_LIMIT)
            if tool_calls > root_budget.max_tool_calls:
                risks.add(BudgetRisk.TOOL_CALL_LIMIT)
            if total_tokens > root_budget.max_total_tokens:
                risks.add(BudgetRisk.TOKEN_LIMIT)
            if derived_cost > root_budget.max_cost_microusd:
                risks.add(BudgetRisk.COST_LIMIT)
            if elapsed_ms > root_budget.max_elapsed_ms:
                risks.add(BudgetRisk.ELAPSED_LIMIT)
            if steps_count > root_budget.max_steps:
                risks.add(BudgetRisk.STEP_LIMIT)
            if max_depth > root_budget.max_recursion_depth:
                risks.add(BudgetRisk.RECURSION_LIMIT)
            if max_fanout > root_budget.max_fanout_per_event:
                risks.add(BudgetRisk.FANOUT_LIMIT)
            if max_retry > root_budget.max_retries_per_operation:
                risks.add(BudgetRisk.RETRY_LIMIT)
            if max_repeat > root_budget.max_repeated_operation_count:
                risks.add(BudgetRisk.LOOP_DETECTED)
            if irreversible_actions > root_budget.max_irreversible_actions:
                risks.add(BudgetRisk.IRREVERSIBLE_COUNT_LIMIT)
            if max_irreversible_rate > root_budget.max_irreversible_actions_per_minute:
                risks.add(BudgetRisk.IRREVERSIBLE_RATE_LIMIT)

            for budget_id in run_budget_ids:
                budget = budgets[budget_id]
                scope = descendants(budget_id)
                scoped_events = [event for event in run_events if event.budget_id in scope]
                scoped_model = sum(event.event_type == ExecutionEventType.MODEL_CALL for event in scoped_events)
                scoped_tool = sum(event.event_type == ExecutionEventType.TOOL_CALL for event in scoped_events)
                scoped_tokens = sum(event.input_tokens + event.output_tokens for event in scoped_events)
                scoped_cost = sum(derived_costs[event.event_id] for event in scoped_events)
                scoped_steps = sum(event.event_type == ExecutionEventType.AGENT_STEP for event in scoped_events)
                scoped_irr = sum(event.irreversible for event in scoped_events)
                if scoped_model > budget.max_model_calls:
                    risks.add(BudgetRisk.MODEL_CALL_LIMIT)
                if scoped_tool > budget.max_tool_calls:
                    risks.add(BudgetRisk.TOOL_CALL_LIMIT)
                if scoped_tokens > budget.max_total_tokens:
                    risks.add(BudgetRisk.TOKEN_LIMIT)
                if scoped_cost > budget.max_cost_microusd:
                    risks.add(BudgetRisk.COST_LIMIT)
                if scoped_steps > budget.max_steps:
                    risks.add(BudgetRisk.STEP_LIMIT)
                if scoped_irr > budget.max_irreversible_actions:
                    risks.add(BudgetRisk.IRREVERSIBLE_COUNT_LIMIT)

            ordered_risks = tuple(sorted(risks, key=lambda risk: (-_risk_score(risk), risk.value)))
            score = max((_risk_score(risk) for risk in ordered_risks), default=0)
            facts.append(
                ExecutionBudgetFact(
                    run_id=run_id,
                    decision=BudgetDecision.DENY if ordered_risks else BudgetDecision.ALLOW,
                    risks=ordered_risks,
                    model_calls=model_calls,
                    tool_calls=tool_calls,
                    total_tokens=total_tokens,
                    derived_cost_microusd=derived_cost,
                    elapsed_ms=elapsed_ms,
                    steps=steps_count,
                    max_recursion_depth=max_depth,
                    max_fanout=max_fanout,
                    max_retry_count=max_retry,
                    max_repeated_operation_count=max_repeat,
                    irreversible_actions=irreversible_actions,
                    max_irreversible_actions_per_minute=max_irreversible_rate,
                    risk_score=score,
                )
            )
        return tuple(facts)

    def evaluate(self, request: ExecutionBudgetRequest, manifest: ExecutionBudgetManifest, p8a: object, p8c: object, p8d: object) -> VerifiedExecutionBudgetAssessment:
        p = self.policy
        pins = (request.graph_sha256, request.p8a_assessment_evidence_sha256, request.p8c_assessment_evidence_sha256, request.p8d_assessment_evidence_sha256)
        expected = (p.expected_graph_sha256, p.expected_p8a_assessment_evidence_sha256, p.expected_p8c_assessment_evidence_sha256, p.expected_p8d_assessment_evidence_sha256)
        if (
            request.graph_id != p.expected_graph_id
            or request.graph_version != p.expected_graph_version
            or not all(_sha(value) for value in pins)
            or any(left.casefold() != right.casefold() for left, right in zip(pins, expected))
            or set(request.run_ids) != set(p.required_run_ids)
            or len(set(request.run_ids)) != len(request.run_ids)
        ):
            _reject(BudgetRejectReason.REQUEST_INVALID, "invalid execution-budget request")
        facts = self.derive(manifest, p8a, p8c, p8d, request.evaluated_at_epoch)
        denied = tuple(fact.run_id for fact in facts if fact.decision == BudgetDecision.DENY)
        if set(request.declared_denied_run_ids) != set(denied):
            _reject(BudgetRejectReason.DECLARED_DECISION_MISMATCH, "caller-declared denied runs differ from derived evidence")
        if set(request.declared_risks_by_run) != set(request.run_ids):
            _reject(BudgetRejectReason.DECLARED_RISK_MISMATCH, "caller risk map must exactly cover run IDs")
        for fact in facts:
            declared = tuple(request.declared_risks_by_run[fact.run_id])
            if set(declared) != set(fact.risks) or len(set(declared)) != len(declared):
                _reject(BudgetRejectReason.DECLARED_RISK_MISMATCH, "caller-declared risks differ from derived evidence", fact.run_id)
        maximum = max((fact.risk_score for fact in facts), default=0)
        if request.declared_max_risk_score != maximum:
            _reject(BudgetRejectReason.DECLARED_RISK_MISMATCH, "caller-declared max risk differs from derived evidence")
        prioritized = tuple(fact.run_id for fact in sorted((fact for fact in facts if fact.decision == BudgetDecision.DENY), key=lambda fact: (-fact.risk_score, fact.run_id)))
        evidence = {
            "graph_sha256": execution_budget_manifest_digest(manifest),
            "p8a": _digest(p8a),
            "p8c": _digest(p8c),
            "p8d": _digest(p8d),
            "runs": [asdict(fact) for fact in facts],
        }
        assessment_sha = hashlib.sha256(json.dumps(_norm(evidence), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        budget_exhaustion = {BudgetRisk.MODEL_CALL_LIMIT, BudgetRisk.TOOL_CALL_LIMIT, BudgetRisk.TOKEN_LIMIT, BudgetRisk.COST_LIMIT, BudgetRisk.ELAPSED_LIMIT, BudgetRisk.STEP_LIMIT, BudgetRisk.RECURSION_LIMIT, BudgetRisk.FANOUT_LIMIT}
        loop_retry = {BudgetRisk.RETRY_LIMIT, BudgetRisk.LOOP_DETECTED}
        delegated = {BudgetRisk.DELEGATED_BUDGET_AMPLIFICATION, BudgetRisk.DELEGATED_BUDGET_OVERSUBSCRIBED}
        irreversible = {BudgetRisk.IRREVERSIBLE_COUNT_LIMIT, BudgetRisk.IRREVERSIBLE_RATE_LIMIT}
        upstream = {BudgetRisk.UPSTREAM_DELEGATION_UNSAFE, BudgetRisk.UPSTREAM_PLAN_UNSAFE, BudgetRisk.UPSTREAM_TOOL_OBSERVATION_UNSAFE}
        return VerifiedExecutionBudgetAssessment(
            graph_id=manifest.graph_id,
            graph_version=manifest.version,
            graph_sha256=execution_budget_manifest_digest(manifest),
            p8a_assessment_evidence_sha256=_digest(p8a),
            p8c_assessment_evidence_sha256=_digest(p8c),
            p8d_assessment_evidence_sha256=_digest(p8d),
            run_count=len(facts),
            allowed_run_count=len(facts) - len(denied),
            denied_run_count=len(denied),
            budget_exhaustion_denial_count=sum(any(risk in budget_exhaustion for risk in fact.risks) for fact in facts),
            loop_or_retry_denial_count=sum(any(risk in loop_retry for risk in fact.risks) for fact in facts),
            delegated_budget_denial_count=sum(any(risk in delegated for risk in fact.risks) for fact in facts),
            irreversible_action_denial_count=sum(any(risk in irreversible for risk in fact.risks) for fact in facts),
            upstream_safety_denial_count=sum(any(risk in upstream for risk in fact.risks) for fact in facts),
            maximum_risk_score=maximum,
            prioritized_denied_run_ids=prioritized,
            runs=facts,
            assessment_evidence_sha256=assessment_sha,
        )
