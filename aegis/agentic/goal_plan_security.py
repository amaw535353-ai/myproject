from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping

P8C_GOAL_PLAN_POLICY_VERSION = "agent-goal-plan-instruction-integrity-v1"
P8C_GOAL_PLAN_SCHEMA_VERSION = "aegis-agent-goal-plan-manifest-v1"
P8C_ASSESSMENT_SCHEMA_VERSION = "aegis-agent-goal-plan-integrity-assessment-v1"
P8C_ASSESSMENT_MODE = "deterministic-evidence-bound-goal-plan-integrity-v1"


class InstructionSource(StrEnum):
    SYSTEM_POLICY = "system_policy"
    USER_GOAL = "user_goal"
    DELEGATED_GOAL = "delegated_goal"
    AGENT_DERIVED = "agent_derived"
    MEMORY = "memory"
    TOOL_OUTPUT = "tool_output"
    EXTERNAL_CONTENT = "external_content"


class InstructionDirective(StrEnum):
    OBJECTIVE = "objective"
    CONSTRAINT = "constraint"
    SUGGESTION = "suggestion"
    TERMINATE = "terminate"
    ROLLBACK = "rollback"


class InstructionTrust(StrEnum):
    UNTRUSTED = "untrusted"
    CONTEXTUAL = "contextual"
    USER_AUTHORIZED = "user_authorized"
    DELEGATED_AUTHORIZED = "delegated_authorized"
    SYSTEM = "system"


class PlanMutationType(StrEnum):
    APPEND = "append"
    REPLACE = "replace"
    DELETE = "delete"
    TERMINATE = "terminate"
    ROLLBACK = "rollback"


class IntegrityDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class GoalIntegrityState(StrEnum):
    HOLDS = "holds"
    VIOLATED = "violated"


class GoalPlanRisk(StrEnum):
    GOAL_PROVENANCE_BROKEN = "goal_provenance_broken"
    GOAL_SCOPE_EXPANSION = "goal_scope_expansion"
    INSTRUCTION_PRECEDENCE_VIOLATION = "instruction_precedence_violation"
    INSTRUCTION_LAUNDERING = "instruction_laundering"
    MEMORY_INSTRUCTION_ESCALATION = "memory_instruction_escalation"
    TOOL_OUTPUT_INSTRUCTION_ESCALATION = "tool_output_instruction_escalation"
    DELEGATED_GOAL_CONTINUITY = "delegated_goal_continuity"
    UPSTREAM_DELEGATION_DENIED = "upstream_delegation_denied"
    UPSTREAM_MEMORY_DENIED = "upstream_memory_denied"
    MEMORY_CONTEXT_MISMATCH = "memory_context_mismatch"
    CAPABILITY_SCOPE_MISMATCH = "capability_scope_mismatch"
    PLAN_STEP_UNAUTHORIZED = "plan_step_unauthorized"
    PLAN_MUTATION_UNAUTHORIZED = "plan_mutation_unauthorized"
    TERMINATION_BYPASS = "termination_bypass"
    ROLLBACK_BYPASS = "rollback_bypass"
    PLAN_SEQUENCE_INVALID = "plan_sequence_invalid"
    STEP_LIMIT_EXCEEDED = "step_limit_exceeded"
    ARCHITECTURE_INVARIANT_UNSAFE = "architecture_invariant_unsafe"
    EXPIRED_GOAL = "expired_goal"
    CROSS_TENANT = "cross_tenant"
    CROSS_SESSION = "cross_session"


class GoalPlanRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    P8A_UNVERIFIED = "p8a_unverified"
    P8A_DIGEST_MISMATCH = "p8a_digest_mismatch"
    P8B_UNVERIFIED = "p8b_unverified"
    P8B_DIGEST_MISMATCH = "p8b_digest_mismatch"
    P7I_UNVERIFIED = "p7i_unverified"
    P7I_DIGEST_MISMATCH = "p7i_digest_mismatch"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    MANIFEST_STALE = "manifest_stale"
    MANIFEST_FUTURE = "manifest_future"
    INSTRUCTION_DUPLICATE = "instruction_duplicate"
    INSTRUCTION_COVERAGE_MISMATCH = "instruction_coverage_mismatch"
    INSTRUCTION_OWNER_UNTRUSTED = "instruction_owner_untrusted"
    INSTRUCTION_SOURCE_DRIFT = "instruction_source_drift"
    INSTRUCTION_DIRECTIVE_DRIFT = "instruction_directive_drift"
    INSTRUCTION_TRUST_DRIFT = "instruction_trust_drift"
    INSTRUCTION_PRECEDENCE_DRIFT = "instruction_precedence_drift"
    INSTRUCTION_ACTION_DRIFT = "instruction_action_drift"
    INSTRUCTION_REFERENCE_UNKNOWN = "instruction_reference_unknown"
    INSTRUCTION_PROVENANCE_INVALID = "instruction_provenance_invalid"
    INSTRUCTION_CYCLE = "instruction_cycle"
    INSTRUCTION_SANITIZATION_INVALID = "instruction_sanitization_invalid"
    GOAL_DUPLICATE = "goal_duplicate"
    GOAL_COVERAGE_MISMATCH = "goal_coverage_mismatch"
    GOAL_OWNER_UNTRUSTED = "goal_owner_untrusted"
    GOAL_ROOT_DRIFT = "goal_root_drift"
    GOAL_PRINCIPAL_DRIFT = "goal_principal_drift"
    GOAL_TENANT_DRIFT = "goal_tenant_drift"
    GOAL_SESSION_DRIFT = "goal_session_drift"
    GOAL_DELEGATION_DRIFT = "goal_delegation_drift"
    GOAL_ACTION_DRIFT = "goal_action_drift"
    GOAL_STEP_LIMIT_DRIFT = "goal_step_limit_drift"
    GOAL_TIME_INVALID = "goal_time_invalid"
    STEP_DUPLICATE = "step_duplicate"
    STEP_COVERAGE_MISMATCH = "step_coverage_mismatch"
    STEP_OWNER_UNTRUSTED = "step_owner_untrusted"
    STEP_REFERENCE_UNKNOWN = "step_reference_unknown"
    STEP_AGENT_UNTRUSTED = "step_agent_untrusted"
    STEP_CAPABILITY_UNKNOWN = "step_capability_unknown"
    STEP_TIME_INVALID = "step_time_invalid"
    MUTATION_DUPLICATE = "mutation_duplicate"
    MUTATION_COVERAGE_MISMATCH = "mutation_coverage_mismatch"
    MUTATION_OWNER_UNTRUSTED = "mutation_owner_untrusted"
    MUTATION_REFERENCE_UNKNOWN = "mutation_reference_unknown"
    MUTATION_ACTOR_UNTRUSTED = "mutation_actor_untrusted"
    ACTION_POLICY_MISSING = "action_policy_missing"
    DECLARED_STEP_DECISION_MISMATCH = "declared_step_decision_mismatch"
    DECLARED_MUTATION_DECISION_MISMATCH = "declared_mutation_decision_mismatch"
    DECLARED_GOAL_STATE_MISMATCH = "declared_goal_state_mismatch"
    DECLARED_MAX_RISK_MISMATCH = "declared_max_risk_mismatch"


class GoalPlanSecurityRejected(ValueError):
    def __init__(
        self,
        reason: GoalPlanRejectReason,
        message: str,
        *,
        instruction_id: str | None = None,
        goal_id: str | None = None,
        step_id: str | None = None,
        mutation_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.instruction_id = instruction_id
        self.goal_id = goal_id
        self.step_id = step_id
        self.mutation_id = mutation_id


@dataclass(frozen=True)
class InstructionRecord:
    instruction_id: str
    goal_id: str | None
    source: InstructionSource
    directive: InstructionDirective
    trust: InstructionTrust
    precedence: int
    tenant_id: str
    session_id: str | None
    original_principal_id: str
    content_sha256: str
    provenance_sha256: str
    parent_instruction_id: str | None
    memory_retrieval_id: str | None
    tool_output_sha256: str | None
    allowed_action_classes: tuple[str, ...]
    sanitized: bool
    sanitization_evidence_sha256: str | None
    issued_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class AgentGoal:
    goal_id: str
    root_instruction_id: str
    original_principal_id: str
    tenant_id: str
    session_id: str | None
    delegation_id: str | None
    allowed_action_classes: tuple[str, ...]
    max_step_count: int
    created_at_epoch: int
    expires_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class PlanStep:
    step_id: str
    goal_id: str
    sequence: int
    agent_id: str
    action_class: str
    source_instruction_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    memory_retrieval_ids: tuple[str, ...]
    irreversible: bool
    rollback_for_step_id: str | None
    created_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class PlanMutation:
    mutation_id: str
    goal_id: str
    actor_agent_id: str
    target_step_id: str | None
    mutation_type: PlanMutationType
    source_instruction_id: str
    proposed_action_class: str | None
    proposed_instruction_ids: tuple[str, ...]
    created_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class GoalPlanManifest:
    graph_id: str
    version: str
    p8a_assessment_evidence_sha256: str
    p8b_assessment_evidence_sha256: str
    p7i_assessment_evidence_sha256: str
    created_at_epoch: int
    instructions: tuple[InstructionRecord, ...]
    goals: tuple[AgentGoal, ...]
    steps: tuple[PlanStep, ...]
    mutations: tuple[PlanMutation, ...]
    schema_version: str = P8C_GOAL_PLAN_SCHEMA_VERSION


@dataclass(frozen=True)
class GoalPlanRequest:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8a_assessment_evidence_sha256: str
    p8b_assessment_evidence_sha256: str
    p7i_assessment_evidence_sha256: str
    evaluated_at_epoch: int
    goal_ids: tuple[str, ...]
    step_ids: tuple[str, ...]
    mutation_ids: tuple[str, ...]
    declared_denied_step_ids: tuple[str, ...]
    declared_denied_mutation_ids: tuple[str, ...]
    declared_unsafe_goal_ids: tuple[str, ...]
    declared_max_integrity_risk_score: int


@dataclass(frozen=True)
class GoalPlanPolicy:
    expected_graph_id: str
    expected_graph_version: str
    expected_graph_sha256: str
    expected_p8a_assessment_evidence_sha256: str
    expected_p8b_assessment_evidence_sha256: str
    expected_p7i_assessment_evidence_sha256: str
    required_instruction_ids: frozenset[str]
    required_goal_ids: frozenset[str]
    required_step_ids: frozenset[str]
    required_mutation_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    trusted_agent_ids: frozenset[str]
    trusted_mutation_agent_ids: frozenset[str]
    allowed_sanitization_evidence_sha256: frozenset[str]
    expected_instruction_source: Mapping[str, InstructionSource]
    expected_instruction_directive: Mapping[str, InstructionDirective]
    expected_instruction_trust: Mapping[str, InstructionTrust]
    expected_instruction_precedence: Mapping[str, int]
    expected_instruction_allowed_actions: Mapping[str, frozenset[str]]
    expected_goal_root_instruction: Mapping[str, str]
    expected_goal_principal: Mapping[str, str]
    expected_goal_tenant: Mapping[str, str]
    expected_goal_session: Mapping[str, str | None]
    expected_goal_delegation: Mapping[str, str | None]
    expected_goal_allowed_actions: Mapping[str, frozenset[str]]
    expected_goal_max_steps: Mapping[str, int]
    action_required_capabilities: Mapping[str, frozenset[str]]
    action_required_p7i_invariants: Mapping[str, frozenset[str]]
    rollback_action_by_action: Mapping[str, str]
    irreversible_action_classes: frozenset[str]
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class PlanStepIntegrityFact:
    step_id: str
    goal_id: str
    sequence: int
    agent_id: str
    action_class: str
    decision: IntegrityDecision
    risks: tuple[GoalPlanRisk, ...]
    source_instruction_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    memory_retrieval_ids: tuple[str, ...]
    required_p7i_invariant_ids: tuple[str, ...]
    rollback_for_step_id: str | None
    risk_score: int


@dataclass(frozen=True)
class PlanMutationIntegrityFact:
    mutation_id: str
    goal_id: str
    mutation_type: PlanMutationType
    actor_agent_id: str
    source_instruction_id: str
    decision: IntegrityDecision
    risks: tuple[GoalPlanRisk, ...]
    proposed_action_class: str | None
    risk_score: int


@dataclass(frozen=True)
class GoalIntegrityFact:
    goal_id: str
    original_principal_id: str
    tenant_id: str
    session_id: str | None
    delegation_id: str | None
    state: GoalIntegrityState
    risks: tuple[GoalPlanRisk, ...]
    denied_step_ids: tuple[str, ...]
    denied_mutation_ids: tuple[str, ...]
    max_risk_score: int


@dataclass(frozen=True)
class VerifiedGoalPlanIntegrityAssessment:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8a_assessment_evidence_sha256: str
    p8b_assessment_evidence_sha256: str
    p7i_assessment_evidence_sha256: str
    goal_count: int
    safe_goal_count: int
    unsafe_goal_count: int
    step_count: int
    allowed_step_count: int
    denied_step_count: int
    mutation_count: int
    allowed_mutation_count: int
    denied_mutation_count: int
    instruction_laundering_denial_count: int
    goal_scope_expansion_denial_count: int
    termination_bypass_denial_count: int
    rollback_bypass_denial_count: int
    max_integrity_risk_score: int
    prioritized_unsafe_goal_ids: tuple[str, ...]
    steps: tuple[PlanStepIntegrityFact, ...]
    mutations: tuple[PlanMutationIntegrityFact, ...]
    goals: tuple[GoalIntegrityFact, ...]
    assessment_evidence_sha256: str
    exact_goal_plan_graph_binding_verified: bool = True
    exact_p8a_delegation_binding_verified: bool = True
    exact_p8b_memory_binding_verified: bool = True
    exact_p7i_invariant_binding_verified: bool = True
    instruction_precedence_enforced: bool = True
    delegated_goal_continuity_verified: bool = True
    plan_step_authorization_derived_from_evidence: bool = True
    plan_mutation_authorization_derived_from_evidence: bool = True
    goal_scope_non_amplification_verified: bool = True
    termination_and_rollback_boundaries_enforced: bool = True
    caller_declared_goal_safety_trusted: bool = False
    production_agent_runtime_enforcement: bool = False
    production_instruction_interception: bool = False
    semantic_intent_proof: bool = False
    exhaustive_goal_hijack_coverage: bool = False
    formal_plan_correctness_proof: bool = False
    network_operations: int = 0
    schema_version: str = P8C_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P8C_GOAL_PLAN_POLICY_VERSION
    assessment_mode: str = P8C_ASSESSMENT_MODE


def _reject(reason: GoalPlanRejectReason, message: str, **context: str | None) -> None:
    raise GoalPlanSecurityRejected(reason, message, **context)


def _is_sha256(value: str | None) -> bool:
    if value is None:
        return False
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def _digest(value: object) -> str:
    return str(getattr(value, "assessment_evidence_sha256", "")).casefold()


def _value(value: object) -> str:
    return str(getattr(value, "value", value)).casefold()


def _verified(value: object, *flags: str) -> bool:
    return all(bool(getattr(value, flag, False)) for flag in flags)


def _trust_rank(value: InstructionTrust) -> int:
    return {
        InstructionTrust.UNTRUSTED: 1,
        InstructionTrust.CONTEXTUAL: 2,
        InstructionTrust.USER_AUTHORIZED: 3,
        InstructionTrust.DELEGATED_AUTHORIZED: 4,
        InstructionTrust.SYSTEM: 5,
    }[value]


def _risk_priority(value: GoalPlanRisk) -> int:
    return {
        GoalPlanRisk.INSTRUCTION_LAUNDERING: 100,
        GoalPlanRisk.GOAL_SCOPE_EXPANSION: 98,
        GoalPlanRisk.TERMINATION_BYPASS: 96,
        GoalPlanRisk.ROLLBACK_BYPASS: 94,
        GoalPlanRisk.DELEGATED_GOAL_CONTINUITY: 92,
        GoalPlanRisk.UPSTREAM_DELEGATION_DENIED: 90,
        GoalPlanRisk.PLAN_MUTATION_UNAUTHORIZED: 88,
        GoalPlanRisk.PLAN_STEP_UNAUTHORIZED: 86,
        GoalPlanRisk.INSTRUCTION_PRECEDENCE_VIOLATION: 84,
        GoalPlanRisk.MEMORY_INSTRUCTION_ESCALATION: 82,
        GoalPlanRisk.TOOL_OUTPUT_INSTRUCTION_ESCALATION: 80,
        GoalPlanRisk.CAPABILITY_SCOPE_MISMATCH: 78,
        GoalPlanRisk.ARCHITECTURE_INVARIANT_UNSAFE: 76,
        GoalPlanRisk.UPSTREAM_MEMORY_DENIED: 74,
        GoalPlanRisk.MEMORY_CONTEXT_MISMATCH: 72,
        GoalPlanRisk.GOAL_PROVENANCE_BROKEN: 70,
        GoalPlanRisk.CROSS_TENANT: 68,
        GoalPlanRisk.CROSS_SESSION: 66,
        GoalPlanRisk.PLAN_SEQUENCE_INVALID: 64,
        GoalPlanRisk.STEP_LIMIT_EXCEEDED: 62,
        GoalPlanRisk.EXPIRED_GOAL: 60,
    }[value]


def _risk_score(risks: tuple[GoalPlanRisk, ...]) -> int:
    if not risks:
        return 0
    priorities = sorted((_risk_priority(value) for value in risks), reverse=True)
    return priorities[0] + min(30, max(0, len(priorities) - 1) * 5)


def instruction_provenance_digest(parent_provenance_sha256: str, content_sha256: str) -> str:
    return hashlib.sha256(f"{parent_provenance_sha256.casefold()}:{content_sha256.casefold()}".encode("utf-8")).hexdigest()


def canonical_goal_plan_manifest_bytes(manifest: GoalPlanManifest) -> bytes:
    document = {
        "created_at_epoch": manifest.created_at_epoch,
        "goals": [
            {
                "allowed_action_classes": sorted(item.allowed_action_classes),
                "created_at_epoch": item.created_at_epoch,
                "delegation_id": item.delegation_id,
                "description": item.description,
                "expires_at_epoch": item.expires_at_epoch,
                "goal_id": item.goal_id,
                "max_step_count": item.max_step_count,
                "original_principal_id": item.original_principal_id,
                "owner_id": item.owner_id,
                "root_instruction_id": item.root_instruction_id,
                "session_id": item.session_id,
                "tenant_id": item.tenant_id,
            }
            for item in sorted(manifest.goals, key=lambda value: value.goal_id)
        ],
        "graph_id": manifest.graph_id,
        "instructions": [
            {
                "allowed_action_classes": sorted(item.allowed_action_classes),
                "content_sha256": item.content_sha256.casefold(),
                "description": item.description,
                "directive": item.directive.value,
                "goal_id": item.goal_id,
                "instruction_id": item.instruction_id,
                "issued_at_epoch": item.issued_at_epoch,
                "memory_retrieval_id": item.memory_retrieval_id,
                "original_principal_id": item.original_principal_id,
                "owner_id": item.owner_id,
                "parent_instruction_id": item.parent_instruction_id,
                "precedence": item.precedence,
                "provenance_sha256": item.provenance_sha256.casefold(),
                "sanitization_evidence_sha256": item.sanitization_evidence_sha256.casefold() if item.sanitization_evidence_sha256 else None,
                "sanitized": item.sanitized,
                "session_id": item.session_id,
                "source": item.source.value,
                "tenant_id": item.tenant_id,
                "tool_output_sha256": item.tool_output_sha256.casefold() if item.tool_output_sha256 else None,
                "trust": item.trust.value,
            }
            for item in sorted(manifest.instructions, key=lambda value: value.instruction_id)
        ],
        "mutations": [
            {
                "actor_agent_id": item.actor_agent_id,
                "created_at_epoch": item.created_at_epoch,
                "description": item.description,
                "goal_id": item.goal_id,
                "mutation_id": item.mutation_id,
                "mutation_type": item.mutation_type.value,
                "owner_id": item.owner_id,
                "proposed_action_class": item.proposed_action_class,
                "proposed_instruction_ids": sorted(item.proposed_instruction_ids),
                "source_instruction_id": item.source_instruction_id,
                "target_step_id": item.target_step_id,
            }
            for item in sorted(manifest.mutations, key=lambda value: value.mutation_id)
        ],
        "p7i_assessment_evidence_sha256": manifest.p7i_assessment_evidence_sha256.casefold(),
        "p8a_assessment_evidence_sha256": manifest.p8a_assessment_evidence_sha256.casefold(),
        "p8b_assessment_evidence_sha256": manifest.p8b_assessment_evidence_sha256.casefold(),
        "schema_version": manifest.schema_version,
        "steps": [
            {
                "action_class": item.action_class,
                "agent_id": item.agent_id,
                "capability_ids": sorted(item.capability_ids),
                "created_at_epoch": item.created_at_epoch,
                "description": item.description,
                "goal_id": item.goal_id,
                "irreversible": item.irreversible,
                "memory_retrieval_ids": sorted(item.memory_retrieval_ids),
                "owner_id": item.owner_id,
                "rollback_for_step_id": item.rollback_for_step_id,
                "sequence": item.sequence,
                "source_instruction_ids": sorted(item.source_instruction_ids),
                "step_id": item.step_id,
            }
            for item in sorted(manifest.steps, key=lambda value: value.step_id)
        ],
        "version": manifest.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def goal_plan_manifest_digest(manifest: GoalPlanManifest) -> str:
    return hashlib.sha256(canonical_goal_plan_manifest_bytes(manifest)).hexdigest()


def _validate_policy(policy: GoalPlanPolicy) -> None:
    hashes = (
        policy.expected_graph_sha256,
        policy.expected_p8a_assessment_evidence_sha256,
        policy.expected_p8b_assessment_evidence_sha256,
        policy.expected_p7i_assessment_evidence_sha256,
    )
    if (
        not policy.expected_graph_id
        or not policy.expected_graph_version
        or not all(_is_sha256(value) for value in hashes)
        or not policy.required_instruction_ids
        or not policy.required_goal_ids
        or not policy.required_step_ids
        or not policy.trusted_owner_ids
        or not policy.trusted_agent_ids
        or not policy.trusted_mutation_agent_ids
        or policy.max_manifest_age_seconds <= 0
        or policy.max_future_skew_seconds < 0
    ):
        _reject(GoalPlanRejectReason.POLICY_INVALID, "goal/plan policy metadata is invalid")

    instruction_maps = (
        policy.expected_instruction_source,
        policy.expected_instruction_directive,
        policy.expected_instruction_trust,
        policy.expected_instruction_precedence,
        policy.expected_instruction_allowed_actions,
    )
    if any(set(mapping) != set(policy.required_instruction_ids) for mapping in instruction_maps):
        _reject(GoalPlanRejectReason.POLICY_INVALID, "instruction policy maps must exactly cover required instructions")

    goal_maps = (
        policy.expected_goal_root_instruction,
        policy.expected_goal_principal,
        policy.expected_goal_tenant,
        policy.expected_goal_session,
        policy.expected_goal_delegation,
        policy.expected_goal_allowed_actions,
        policy.expected_goal_max_steps,
    )
    if any(set(mapping) != set(policy.required_goal_ids) for mapping in goal_maps):
        _reject(GoalPlanRejectReason.POLICY_INVALID, "goal policy maps must exactly cover required goals")
    if any(value <= 0 for value in policy.expected_goal_max_steps.values()):
        _reject(GoalPlanRejectReason.POLICY_INVALID, "goal step limits must be positive")

    actions = set(policy.action_required_capabilities)
    if not actions or set(policy.action_required_p7i_invariants) != actions:
        _reject(GoalPlanRejectReason.POLICY_INVALID, "action capability/invariant policy maps must have identical non-empty coverage")
    if any(action not in actions for action in policy.rollback_action_by_action.values()):
        _reject(GoalPlanRejectReason.POLICY_INVALID, "rollback action policy references unknown action class")
    if not policy.irreversible_action_classes.issubset(actions) or any(action not in policy.rollback_action_by_action for action in policy.irreversible_action_classes):
        _reject(GoalPlanRejectReason.POLICY_INVALID, "irreversible actions must be known and have rollback mappings")
    if any(action not in actions for actions_set in policy.expected_goal_allowed_actions.values() for action in actions_set):
        _reject(GoalPlanRejectReason.POLICY_INVALID, "goal policy references unknown action class")


def _unique(items: tuple[object, ...], attribute: str, reason: GoalPlanRejectReason) -> dict[str, object]:
    result: dict[str, object] = {}
    for item in items:
        object_id = str(getattr(item, attribute, ""))
        if not object_id or object_id in result:
            _reject(reason, "upstream evidence has empty or duplicate identifiers")
        result[object_id] = item
    if not result:
        _reject(reason, "upstream evidence inventory is empty")
    return result


def _validate_upstreams(policy: GoalPlanPolicy, p8a: object, p8b: object, p7i: object) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    if not _verified(p8a, "exact_delegation_graph_binding_verified", "agent_identity_continuity_verified", "authority_non_amplification_verified"):
        _reject(GoalPlanRejectReason.P8A_UNVERIFIED, "P8-A delegation evidence is not fully verified")
    if _digest(p8a) != policy.expected_p8a_assessment_evidence_sha256.casefold():
        _reject(GoalPlanRejectReason.P8A_DIGEST_MISMATCH, "P8-A evidence digest does not match goal/plan policy")

    if not _verified(p8b, "exact_memory_graph_binding_verified", "memory_provenance_verified", "retrieval_trust_labels_derived_from_evidence", "revocation_and_supersession_enforced"):
        _reject(GoalPlanRejectReason.P8B_UNVERIFIED, "P8-B memory evidence is not fully verified")
    if _digest(p8b) != policy.expected_p8b_assessment_evidence_sha256.casefold():
        _reject(GoalPlanRejectReason.P8B_DIGEST_MISMATCH, "P8-B evidence digest does not match goal/plan policy")

    if not _verified(p7i, "exact_catalog_binding_verified", "blast_radius_derived_from_evidence", "counterevidence_preserved"):
        _reject(GoalPlanRejectReason.P7I_UNVERIFIED, "P7-I invariant evidence is not fully verified")
    if _digest(p7i) != policy.expected_p7i_assessment_evidence_sha256.casefold():
        _reject(GoalPlanRejectReason.P7I_DIGEST_MISMATCH, "P7-I evidence digest does not match goal/plan policy")

    delegations = _unique(tuple(getattr(p8a, "delegations", ())), "delegation_id", GoalPlanRejectReason.P8A_UNVERIFIED)
    retrievals = _unique(tuple(getattr(p8b, "retrievals", ())), "retrieval_id", GoalPlanRejectReason.P8B_UNVERIFIED)
    invariants = _unique(tuple(getattr(p7i, "invariants", ())), "invariant_id", GoalPlanRejectReason.P7I_UNVERIFIED)
    return delegations, retrievals, invariants


def _validate_manifest(
    policy: GoalPlanPolicy,
    request: GoalPlanRequest,
    manifest: GoalPlanManifest,
    delegations: Mapping[str, object],
    retrievals: Mapping[str, object],
    invariants: Mapping[str, object],
) -> tuple[dict[str, InstructionRecord], dict[str, AgentGoal], dict[str, PlanStep], dict[str, PlanMutation], str]:
    if (
        manifest.schema_version != P8C_GOAL_PLAN_SCHEMA_VERSION
        or manifest.graph_id != policy.expected_graph_id
        or manifest.version != policy.expected_graph_version
        or not manifest.instructions
        or not manifest.goals
        or not manifest.steps
    ):
        _reject(GoalPlanRejectReason.MANIFEST_INVALID, "goal/plan manifest metadata is invalid")
    pins = (
        (manifest.p8a_assessment_evidence_sha256, policy.expected_p8a_assessment_evidence_sha256),
        (manifest.p8b_assessment_evidence_sha256, policy.expected_p8b_assessment_evidence_sha256),
        (manifest.p7i_assessment_evidence_sha256, policy.expected_p7i_assessment_evidence_sha256),
    )
    if any(left.casefold() != right.casefold() for left, right in pins):
        _reject(GoalPlanRejectReason.MANIFEST_INVALID, "manifest upstream evidence pins are invalid")
    if manifest.created_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
        _reject(GoalPlanRejectReason.MANIFEST_FUTURE, "goal/plan manifest is future-dated")
    if request.evaluated_at_epoch - manifest.created_at_epoch > policy.max_manifest_age_seconds:
        _reject(GoalPlanRejectReason.MANIFEST_STALE, "goal/plan manifest is stale")
    actual_sha = goal_plan_manifest_digest(manifest)
    if not hmac.compare_digest(actual_sha, policy.expected_graph_sha256.casefold()) or not hmac.compare_digest(actual_sha, request.graph_sha256.casefold()):
        _reject(GoalPlanRejectReason.MANIFEST_DIGEST_MISMATCH, "goal/plan manifest digest does not match request/policy")

    instructions: dict[str, InstructionRecord] = {}
    for item in manifest.instructions:
        if not item.instruction_id or item.instruction_id in instructions:
            _reject(GoalPlanRejectReason.INSTRUCTION_DUPLICATE, "instruction is duplicate or empty", instruction_id=item.instruction_id or None)
        instructions[item.instruction_id] = item
    if set(instructions) != set(policy.required_instruction_ids):
        _reject(GoalPlanRejectReason.INSTRUCTION_COVERAGE_MISMATCH, "instruction coverage differs from policy")
    for instruction_id, item in instructions.items():
        if item.owner_id not in policy.trusted_owner_ids:
            _reject(GoalPlanRejectReason.INSTRUCTION_OWNER_UNTRUSTED, "instruction owner is untrusted", instruction_id=instruction_id)
        if item.source != policy.expected_instruction_source[instruction_id]:
            _reject(GoalPlanRejectReason.INSTRUCTION_SOURCE_DRIFT, "instruction source differs from policy", instruction_id=instruction_id)
        if item.directive != policy.expected_instruction_directive[instruction_id]:
            _reject(GoalPlanRejectReason.INSTRUCTION_DIRECTIVE_DRIFT, "instruction directive differs from policy", instruction_id=instruction_id)
        if item.trust != policy.expected_instruction_trust[instruction_id]:
            _reject(GoalPlanRejectReason.INSTRUCTION_TRUST_DRIFT, "instruction trust differs from policy", instruction_id=instruction_id)
        if item.precedence != policy.expected_instruction_precedence[instruction_id] or item.precedence <= 0:
            _reject(GoalPlanRejectReason.INSTRUCTION_PRECEDENCE_DRIFT, "instruction precedence differs from policy", instruction_id=instruction_id)
        if set(item.allowed_action_classes) != set(policy.expected_instruction_allowed_actions[instruction_id]) or len(set(item.allowed_action_classes)) != len(item.allowed_action_classes):
            _reject(GoalPlanRejectReason.INSTRUCTION_ACTION_DRIFT, "instruction allowed actions differ from policy", instruction_id=instruction_id)
        if not _is_sha256(item.content_sha256) or not _is_sha256(item.provenance_sha256):
            _reject(GoalPlanRejectReason.INSTRUCTION_PROVENANCE_INVALID, "instruction content/provenance digest is invalid", instruction_id=instruction_id)
        if item.parent_instruction_id is not None and item.parent_instruction_id not in instructions:
            _reject(GoalPlanRejectReason.INSTRUCTION_REFERENCE_UNKNOWN, "instruction parent is unknown", instruction_id=instruction_id)
        if item.memory_retrieval_id is not None and item.memory_retrieval_id not in retrievals:
            _reject(GoalPlanRejectReason.INSTRUCTION_REFERENCE_UNKNOWN, "instruction references unknown P8-B retrieval", instruction_id=instruction_id)
        if item.tool_output_sha256 is not None and not _is_sha256(item.tool_output_sha256):
            _reject(GoalPlanRejectReason.INSTRUCTION_PROVENANCE_INVALID, "instruction tool-output digest is invalid", instruction_id=instruction_id)
        if item.sanitized:
            if not item.sanitization_evidence_sha256 or item.sanitization_evidence_sha256.casefold() not in {value.casefold() for value in policy.allowed_sanitization_evidence_sha256}:
                _reject(GoalPlanRejectReason.INSTRUCTION_SANITIZATION_INVALID, "instruction sanitization evidence is not policy-approved", instruction_id=instruction_id)
        elif item.sanitization_evidence_sha256 is not None:
            _reject(GoalPlanRejectReason.INSTRUCTION_SANITIZATION_INVALID, "unsanitized instruction cannot carry sanitization evidence", instruction_id=instruction_id)
        if item.source == InstructionSource.MEMORY and item.memory_retrieval_id is None:
            _reject(GoalPlanRejectReason.INSTRUCTION_REFERENCE_UNKNOWN, "memory instruction must bind P8-B retrieval evidence", instruction_id=instruction_id)
        if item.source == InstructionSource.TOOL_OUTPUT and item.tool_output_sha256 is None:
            _reject(GoalPlanRejectReason.INSTRUCTION_PROVENANCE_INVALID, "tool-output instruction must bind output digest", instruction_id=instruction_id)

    for instruction_id in instructions:
        seen: set[str] = set()
        current: str | None = instruction_id
        while current is not None:
            if current in seen:
                _reject(GoalPlanRejectReason.INSTRUCTION_CYCLE, "instruction provenance graph contains a cycle", instruction_id=instruction_id)
            seen.add(current)
            current = instructions[current].parent_instruction_id
    for instruction_id, item in instructions.items():
        if item.parent_instruction_id is not None:
            parent = instructions[item.parent_instruction_id]
            expected_provenance = instruction_provenance_digest(parent.provenance_sha256, item.content_sha256)
            if not hmac.compare_digest(expected_provenance, item.provenance_sha256.casefold()):
                _reject(GoalPlanRejectReason.INSTRUCTION_PROVENANCE_INVALID, "derived instruction provenance chain is invalid", instruction_id=instruction_id)
            if (item.precedence > parent.precedence or _trust_rank(item.trust) > _trust_rank(parent.trust)) and not item.sanitized:
                _reject(GoalPlanRejectReason.INSTRUCTION_SANITIZATION_INVALID, "instruction cannot gain precedence/trust without approved sanitization", instruction_id=instruction_id)

    goals: dict[str, AgentGoal] = {}
    for item in manifest.goals:
        if not item.goal_id or item.goal_id in goals:
            _reject(GoalPlanRejectReason.GOAL_DUPLICATE, "goal is duplicate or empty", goal_id=item.goal_id or None)
        goals[item.goal_id] = item
    if set(goals) != set(policy.required_goal_ids):
        _reject(GoalPlanRejectReason.GOAL_COVERAGE_MISMATCH, "goal coverage differs from policy")
    for goal_id, item in goals.items():
        if item.owner_id not in policy.trusted_owner_ids:
            _reject(GoalPlanRejectReason.GOAL_OWNER_UNTRUSTED, "goal owner is untrusted", goal_id=goal_id)
        if item.root_instruction_id != policy.expected_goal_root_instruction[goal_id] or item.root_instruction_id not in instructions:
            _reject(GoalPlanRejectReason.GOAL_ROOT_DRIFT, "goal root instruction differs from policy", goal_id=goal_id)
        if item.original_principal_id != policy.expected_goal_principal[goal_id]:
            _reject(GoalPlanRejectReason.GOAL_PRINCIPAL_DRIFT, "goal original principal differs from policy", goal_id=goal_id)
        if item.tenant_id != policy.expected_goal_tenant[goal_id]:
            _reject(GoalPlanRejectReason.GOAL_TENANT_DRIFT, "goal tenant differs from policy", goal_id=goal_id)
        if item.session_id != policy.expected_goal_session[goal_id]:
            _reject(GoalPlanRejectReason.GOAL_SESSION_DRIFT, "goal session differs from policy", goal_id=goal_id)
        if item.delegation_id != policy.expected_goal_delegation[goal_id]:
            _reject(GoalPlanRejectReason.GOAL_DELEGATION_DRIFT, "goal delegation differs from policy", goal_id=goal_id)
        if item.delegation_id is not None and item.delegation_id not in delegations:
            _reject(GoalPlanRejectReason.GOAL_DELEGATION_DRIFT, "goal delegation is unknown", goal_id=goal_id)
        if set(item.allowed_action_classes) != set(policy.expected_goal_allowed_actions[goal_id]) or len(set(item.allowed_action_classes)) != len(item.allowed_action_classes):
            _reject(GoalPlanRejectReason.GOAL_ACTION_DRIFT, "goal allowed actions differ from policy", goal_id=goal_id)
        if item.max_step_count != policy.expected_goal_max_steps[goal_id] or item.max_step_count <= 0:
            _reject(GoalPlanRejectReason.GOAL_STEP_LIMIT_DRIFT, "goal step bound differs from policy", goal_id=goal_id)
        if item.expires_at_epoch <= item.created_at_epoch or item.created_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
            _reject(GoalPlanRejectReason.GOAL_TIME_INVALID, "goal timestamps are invalid", goal_id=goal_id)
        root = instructions[item.root_instruction_id]
        if root.goal_id != goal_id or root.original_principal_id != item.original_principal_id or root.tenant_id != item.tenant_id or root.session_id != item.session_id:
            _reject(GoalPlanRejectReason.GOAL_ROOT_DRIFT, "goal/root-instruction identity context is inconsistent", goal_id=goal_id)

    steps: dict[str, PlanStep] = {}
    for item in manifest.steps:
        if not item.step_id or item.step_id in steps:
            _reject(GoalPlanRejectReason.STEP_DUPLICATE, "plan step is duplicate or empty", step_id=item.step_id or None)
        steps[item.step_id] = item
    if set(steps) != set(policy.required_step_ids):
        _reject(GoalPlanRejectReason.STEP_COVERAGE_MISMATCH, "plan-step coverage differs from policy")
    for step_id, item in steps.items():
        if item.owner_id not in policy.trusted_owner_ids:
            _reject(GoalPlanRejectReason.STEP_OWNER_UNTRUSTED, "plan-step owner is untrusted", step_id=step_id)
        if item.goal_id not in goals or any(value not in instructions for value in item.source_instruction_ids) or any(value not in retrievals for value in item.memory_retrieval_ids):
            _reject(GoalPlanRejectReason.STEP_REFERENCE_UNKNOWN, "plan step references unknown goal/instruction/memory retrieval", step_id=step_id)
        if item.rollback_for_step_id is not None and item.rollback_for_step_id not in steps:
            _reject(GoalPlanRejectReason.STEP_REFERENCE_UNKNOWN, "rollback step references unknown target step", step_id=step_id)
        if item.agent_id not in policy.trusted_agent_ids:
            _reject(GoalPlanRejectReason.STEP_AGENT_UNTRUSTED, "plan-step agent is untrusted", step_id=step_id)
        if item.action_class not in policy.action_required_capabilities:
            _reject(GoalPlanRejectReason.ACTION_POLICY_MISSING, "plan step uses action without policy", step_id=step_id)
        if len(set(item.capability_ids)) != len(item.capability_ids) or any(not value for value in item.capability_ids):
            _reject(GoalPlanRejectReason.STEP_CAPABILITY_UNKNOWN, "plan-step capabilities are duplicate/empty", step_id=step_id)
        if item.irreversible != (item.action_class in policy.irreversible_action_classes):
            _reject(GoalPlanRejectReason.STEP_TIME_INVALID, "plan-step irreversible classification differs from policy", step_id=step_id)
        if item.sequence <= 0 or item.created_at_epoch < goals[item.goal_id].created_at_epoch:
            _reject(GoalPlanRejectReason.STEP_TIME_INVALID, "plan-step sequence/time is invalid", step_id=step_id)

    mutations: dict[str, PlanMutation] = {}
    for item in manifest.mutations:
        if not item.mutation_id or item.mutation_id in mutations:
            _reject(GoalPlanRejectReason.MUTATION_DUPLICATE, "plan mutation is duplicate or empty", mutation_id=item.mutation_id or None)
        mutations[item.mutation_id] = item
    if set(mutations) != set(policy.required_mutation_ids):
        _reject(GoalPlanRejectReason.MUTATION_COVERAGE_MISMATCH, "plan-mutation coverage differs from policy")
    for mutation_id, item in mutations.items():
        if item.owner_id not in policy.trusted_owner_ids:
            _reject(GoalPlanRejectReason.MUTATION_OWNER_UNTRUSTED, "plan-mutation owner is untrusted", mutation_id=mutation_id)
        if item.goal_id not in goals or item.source_instruction_id not in instructions or (item.target_step_id is not None and item.target_step_id not in steps) or any(value not in instructions for value in item.proposed_instruction_ids):
            _reject(GoalPlanRejectReason.MUTATION_REFERENCE_UNKNOWN, "plan mutation references unknown goal/step/instruction", mutation_id=mutation_id)
        if item.actor_agent_id not in policy.trusted_mutation_agent_ids:
            _reject(GoalPlanRejectReason.MUTATION_ACTOR_UNTRUSTED, "plan-mutation actor is untrusted", mutation_id=mutation_id)
        if item.proposed_action_class is not None and item.proposed_action_class not in policy.action_required_capabilities:
            _reject(GoalPlanRejectReason.ACTION_POLICY_MISSING, "plan mutation proposes action without policy", mutation_id=mutation_id)
        if item.created_at_epoch < goals[item.goal_id].created_at_epoch:
            _reject(GoalPlanRejectReason.MUTATION_REFERENCE_UNKNOWN, "plan mutation predates goal", mutation_id=mutation_id)
    return instructions, goals, steps, mutations, actual_sha


def _delegation_risks(goal: AgentGoal, fact: object | None) -> tuple[GoalPlanRisk, ...]:
    if goal.delegation_id is None:
        return ()
    if fact is None:
        return (GoalPlanRisk.DELEGATED_GOAL_CONTINUITY,)
    risks: list[GoalPlanRisk] = []
    if _value(getattr(fact, "decision", "deny")) != "allow":
        risks.append(GoalPlanRisk.UPSTREAM_DELEGATION_DENIED)
    if str(getattr(fact, "original_principal_id", "")) != goal.original_principal_id:
        risks.append(GoalPlanRisk.DELEGATED_GOAL_CONTINUITY)
    if str(getattr(fact, "tenant_id", "")) != goal.tenant_id:
        risks.append(GoalPlanRisk.DELEGATED_GOAL_CONTINUITY)
    return tuple(risks)


def _instruction_context_risks(instruction: InstructionRecord, goal: AgentGoal, retrievals: Mapping[str, object]) -> tuple[GoalPlanRisk, ...]:
    risks: list[GoalPlanRisk] = []
    if instruction.goal_id not in {None, goal.goal_id}:
        risks.append(GoalPlanRisk.GOAL_PROVENANCE_BROKEN)
    if instruction.original_principal_id != goal.original_principal_id:
        risks.append(GoalPlanRisk.GOAL_PROVENANCE_BROKEN)
    if instruction.tenant_id != goal.tenant_id:
        risks.append(GoalPlanRisk.CROSS_TENANT)
    if instruction.session_id != goal.session_id:
        risks.append(GoalPlanRisk.CROSS_SESSION)
    if instruction.memory_retrieval_id is not None:
        retrieval = retrievals[instruction.memory_retrieval_id]
        if _value(getattr(retrieval, "decision", "deny")) != "allow":
            risks.append(GoalPlanRisk.UPSTREAM_MEMORY_DENIED)
        if str(getattr(retrieval, "tenant_id", "")) != goal.tenant_id or getattr(retrieval, "session_id", None) != goal.session_id:
            risks.append(GoalPlanRisk.MEMORY_CONTEXT_MISMATCH)
    return tuple(risks)


def _invariant_unsafe(invariant: object) -> bool:
    return _value(getattr(invariant, "state", "violated")) != "holds"


class AgentGoalPlanIntegrityAnalyzer:
    def __init__(self, policy: GoalPlanPolicy) -> None:
        _validate_policy(policy)
        self.policy = policy

    def evaluate(
        self,
        request: GoalPlanRequest,
        manifest: GoalPlanManifest,
        p8a_assessment: object,
        p8b_assessment: object,
        p7i_assessment: object,
    ) -> VerifiedGoalPlanIntegrityAssessment:
        pins = (
            request.graph_sha256,
            request.p8a_assessment_evidence_sha256,
            request.p8b_assessment_evidence_sha256,
            request.p7i_assessment_evidence_sha256,
        )
        expected = (
            self.policy.expected_graph_sha256,
            self.policy.expected_p8a_assessment_evidence_sha256,
            self.policy.expected_p8b_assessment_evidence_sha256,
            self.policy.expected_p7i_assessment_evidence_sha256,
        )
        if (
            request.graph_id != self.policy.expected_graph_id
            or request.graph_version != self.policy.expected_graph_version
            or not all(_is_sha256(value) for value in pins)
            or any(left.casefold() != right.casefold() for left, right in zip(pins, expected))
            or set(request.goal_ids) != set(self.policy.required_goal_ids)
            or set(request.step_ids) != set(self.policy.required_step_ids)
            or set(request.mutation_ids) != set(self.policy.required_mutation_ids)
            or len(set(request.goal_ids)) != len(request.goal_ids)
            or len(set(request.step_ids)) != len(request.step_ids)
            or len(set(request.mutation_ids)) != len(request.mutation_ids)
        ):
            _reject(GoalPlanRejectReason.REQUEST_INVALID, "goal/plan request identity/evidence/scope is invalid")

        delegations, retrievals, invariants = _validate_upstreams(self.policy, p8a_assessment, p8b_assessment, p7i_assessment)
        instructions, goals, steps, mutations, graph_sha = _validate_manifest(self.policy, request, manifest, delegations, retrievals, invariants)

        goal_delegation_risks: dict[str, tuple[GoalPlanRisk, ...]] = {
            goal_id: _delegation_risks(goal, delegations.get(goal.delegation_id) if goal.delegation_id else None)
            for goal_id, goal in goals.items()
        }

        steps_by_goal: dict[str, list[PlanStep]] = {goal_id: [] for goal_id in goals}
        for step in steps.values():
            steps_by_goal[step.goal_id].append(step)
        sequence_risks: dict[str, set[GoalPlanRisk]] = {step_id: set() for step_id in steps}
        for goal_id, goal_steps in steps_by_goal.items():
            ordered = sorted(goal_steps, key=lambda value: (value.sequence, value.step_id))
            sequences = [value.sequence for value in ordered]
            if len(sequences) > goals[goal_id].max_step_count:
                for value in ordered:
                    sequence_risks[value.step_id].add(GoalPlanRisk.STEP_LIMIT_EXCEEDED)
            if sequences != list(range(1, len(sequences) + 1)):
                for value in ordered:
                    sequence_risks[value.step_id].add(GoalPlanRisk.PLAN_SEQUENCE_INVALID)

        step_facts: list[PlanStepIntegrityFact] = []
        for step_id in sorted(steps):
            step = steps[step_id]
            goal = goals[step.goal_id]
            root = instructions[goal.root_instruction_id]
            risks: set[GoalPlanRisk] = set(sequence_risks[step_id])
            risks.update(goal_delegation_risks[goal.goal_id])
            if request.evaluated_at_epoch >= goal.expires_at_epoch:
                risks.add(GoalPlanRisk.EXPIRED_GOAL)
            if not step.source_instruction_ids:
                risks.add(GoalPlanRisk.PLAN_STEP_UNAUTHORIZED)
            source_items = [instructions[value] for value in step.source_instruction_ids]
            for instruction in source_items:
                risks.update(_instruction_context_risks(instruction, goal, retrievals))
            if goal.root_instruction_id not in step.source_instruction_ids:
                risks.add(GoalPlanRisk.GOAL_PROVENANCE_BROKEN)

            goal_actions = set(goal.allowed_action_classes)
            if step.action_class not in goal_actions:
                risks.add(GoalPlanRisk.GOAL_SCOPE_EXPANSION)
            if step.action_class not in set(root.allowed_action_classes):
                risks.add(GoalPlanRisk.GOAL_SCOPE_EXPANSION)

            required_capabilities = set(self.policy.action_required_capabilities[step.action_class])
            if set(step.capability_ids) != required_capabilities:
                risks.add(GoalPlanRisk.CAPABILITY_SCOPE_MISMATCH)
            if goal.delegation_id is not None:
                delegation = delegations[goal.delegation_id]
                delegated_capabilities = set(getattr(delegation, "requested_capability_ids", ()))
                if not required_capabilities.issubset(delegated_capabilities):
                    risks.add(GoalPlanRisk.CAPABILITY_SCOPE_MISMATCH)

            required_invariants = set(self.policy.action_required_p7i_invariants[step.action_class])
            if any(value not in invariants or _invariant_unsafe(invariants[value]) for value in required_invariants):
                risks.add(GoalPlanRisk.ARCHITECTURE_INVARIANT_UNSAFE)

            for retrieval_id in step.memory_retrieval_ids:
                retrieval = retrievals[retrieval_id]
                if _value(getattr(retrieval, "decision", "deny")) != "allow":
                    risks.add(GoalPlanRisk.UPSTREAM_MEMORY_DENIED)
                if str(getattr(retrieval, "tenant_id", "")) != goal.tenant_id:
                    risks.add(GoalPlanRisk.CROSS_TENANT)
                if getattr(retrieval, "session_id", None) != goal.session_id:
                    risks.add(GoalPlanRisk.CROSS_SESSION)

            low_authority_sources = [
                item
                for item in source_items
                if item.source in {InstructionSource.MEMORY, InstructionSource.TOOL_OUTPUT, InstructionSource.EXTERNAL_CONTENT}
                and _trust_rank(item.trust) < _trust_rank(root.trust)
            ]
            if step.action_class not in set(root.allowed_action_classes) and low_authority_sources:
                risks.add(GoalPlanRisk.INSTRUCTION_LAUNDERING)
                if any(item.source == InstructionSource.MEMORY for item in low_authority_sources):
                    risks.add(GoalPlanRisk.MEMORY_INSTRUCTION_ESCALATION)
                if any(item.source == InstructionSource.TOOL_OUTPUT for item in low_authority_sources):
                    risks.add(GoalPlanRisk.TOOL_OUTPUT_INSTRUCTION_ESCALATION)
            for item in low_authority_sources:
                if item.directive in {InstructionDirective.TERMINATE, InstructionDirective.ROLLBACK} and not item.sanitized:
                    risks.add(GoalPlanRisk.INSTRUCTION_PRECEDENCE_VIOLATION)

            active_termination = [
                item
                for item in instructions.values()
                if item.goal_id == goal.goal_id
                and item.directive == InstructionDirective.TERMINATE
                and item.issued_at_epoch <= step.created_at_epoch
                and item.precedence >= root.precedence
                and _trust_rank(item.trust) >= _trust_rank(root.trust)
            ]
            if active_termination and step.action_class != self.policy.rollback_action_by_action.get(step.action_class):
                risks.add(GoalPlanRisk.TERMINATION_BYPASS)

            if step.irreversible and step.action_class in self.policy.rollback_action_by_action:
                rollback_action = self.policy.rollback_action_by_action[step.action_class]
                rollback_steps = [
                    candidate
                    for candidate in steps_by_goal[goal.goal_id]
                    if candidate.rollback_for_step_id == step.step_id
                    and candidate.action_class == rollback_action
                    and candidate.sequence > step.sequence
                ]
                if not rollback_steps:
                    risks.add(GoalPlanRisk.ROLLBACK_BYPASS)
            if step.rollback_for_step_id is not None:
                target = steps[step.rollback_for_step_id]
                expected_rollback = self.policy.rollback_action_by_action.get(target.action_class)
                if expected_rollback != step.action_class or step.sequence <= target.sequence:
                    risks.add(GoalPlanRisk.ROLLBACK_BYPASS)

            ordered_risks = tuple(sorted(risks, key=lambda value: (-_risk_priority(value), value.value)))
            decision = IntegrityDecision.DENY if ordered_risks else IntegrityDecision.ALLOW
            step_facts.append(
                PlanStepIntegrityFact(
                    step_id=step.step_id,
                    goal_id=step.goal_id,
                    sequence=step.sequence,
                    agent_id=step.agent_id,
                    action_class=step.action_class,
                    decision=decision,
                    risks=ordered_risks,
                    source_instruction_ids=tuple(sorted(step.source_instruction_ids)),
                    capability_ids=tuple(sorted(step.capability_ids)),
                    memory_retrieval_ids=tuple(sorted(step.memory_retrieval_ids)),
                    required_p7i_invariant_ids=tuple(sorted(required_invariants)),
                    rollback_for_step_id=step.rollback_for_step_id,
                    risk_score=_risk_score(ordered_risks),
                )
            )

        mutation_facts: list[PlanMutationIntegrityFact] = []
        for mutation_id in sorted(mutations):
            mutation = mutations[mutation_id]
            goal = goals[mutation.goal_id]
            root = instructions[goal.root_instruction_id]
            source = instructions[mutation.source_instruction_id]
            risks: set[GoalPlanRisk] = set(goal_delegation_risks[goal.goal_id])
            risks.update(_instruction_context_risks(source, goal, retrievals))
            if source.precedence < root.precedence or _trust_rank(source.trust) < _trust_rank(root.trust):
                risks.add(GoalPlanRisk.PLAN_MUTATION_UNAUTHORIZED)
                if source.source in {InstructionSource.MEMORY, InstructionSource.TOOL_OUTPUT, InstructionSource.EXTERNAL_CONTENT} and not source.sanitized:
                    risks.add(GoalPlanRisk.INSTRUCTION_LAUNDERING)
                    if source.source == InstructionSource.MEMORY:
                        risks.add(GoalPlanRisk.MEMORY_INSTRUCTION_ESCALATION)
                    if source.source == InstructionSource.TOOL_OUTPUT:
                        risks.add(GoalPlanRisk.TOOL_OUTPUT_INSTRUCTION_ESCALATION)
            if mutation.proposed_action_class is not None:
                if mutation.proposed_action_class not in set(goal.allowed_action_classes) or mutation.proposed_action_class not in set(root.allowed_action_classes):
                    risks.add(GoalPlanRisk.GOAL_SCOPE_EXPANSION)
                required = set(self.policy.action_required_capabilities[mutation.proposed_action_class])
                if goal.delegation_id is not None:
                    delegated_capabilities = set(getattr(delegations[goal.delegation_id], "requested_capability_ids", ()))
                    if not required.issubset(delegated_capabilities):
                        risks.add(GoalPlanRisk.CAPABILITY_SCOPE_MISMATCH)
                if any(_invariant_unsafe(invariants[value]) for value in self.policy.action_required_p7i_invariants[mutation.proposed_action_class]):
                    risks.add(GoalPlanRisk.ARCHITECTURE_INVARIANT_UNSAFE)
            if mutation.mutation_type in {PlanMutationType.TERMINATE, PlanMutationType.ROLLBACK} and source.directive not in {InstructionDirective.TERMINATE, InstructionDirective.ROLLBACK, InstructionDirective.CONSTRAINT}:
                risks.add(GoalPlanRisk.PLAN_MUTATION_UNAUTHORIZED)
            for instruction_id in mutation.proposed_instruction_ids:
                candidate = instructions[instruction_id]
                if candidate.precedence > root.precedence and _trust_rank(candidate.trust) < _trust_rank(root.trust):
                    risks.add(GoalPlanRisk.INSTRUCTION_PRECEDENCE_VIOLATION)
            ordered_risks = tuple(sorted(risks, key=lambda value: (-_risk_priority(value), value.value)))
            mutation_facts.append(
                PlanMutationIntegrityFact(
                    mutation_id=mutation.mutation_id,
                    goal_id=mutation.goal_id,
                    mutation_type=mutation.mutation_type,
                    actor_agent_id=mutation.actor_agent_id,
                    source_instruction_id=mutation.source_instruction_id,
                    decision=IntegrityDecision.DENY if ordered_risks else IntegrityDecision.ALLOW,
                    risks=ordered_risks,
                    proposed_action_class=mutation.proposed_action_class,
                    risk_score=_risk_score(ordered_risks),
                )
            )

        step_by_goal: dict[str, list[PlanStepIntegrityFact]] = {goal_id: [] for goal_id in goals}
        for fact in step_facts:
            step_by_goal[fact.goal_id].append(fact)
        mutation_by_goal: dict[str, list[PlanMutationIntegrityFact]] = {goal_id: [] for goal_id in goals}
        for fact in mutation_facts:
            mutation_by_goal[fact.goal_id].append(fact)

        goal_facts: list[GoalIntegrityFact] = []
        for goal_id in sorted(goals):
            goal = goals[goal_id]
            denied_steps = tuple(sorted(value.step_id for value in step_by_goal[goal_id] if value.decision == IntegrityDecision.DENY))
            denied_mutations = tuple(sorted(value.mutation_id for value in mutation_by_goal[goal_id] if value.decision == IntegrityDecision.DENY))
            risks: set[GoalPlanRisk] = set(goal_delegation_risks[goal_id])
            for fact in step_by_goal[goal_id]:
                risks.update(fact.risks)
            for fact in mutation_by_goal[goal_id]:
                risks.update(fact.risks)
            if request.evaluated_at_epoch >= goal.expires_at_epoch:
                risks.add(GoalPlanRisk.EXPIRED_GOAL)
            ordered_risks = tuple(sorted(risks, key=lambda value: (-_risk_priority(value), value.value)))
            max_score = max([_risk_score(ordered_risks), *(value.risk_score for value in step_by_goal[goal_id]), *(value.risk_score for value in mutation_by_goal[goal_id])], default=0)
            goal_facts.append(
                GoalIntegrityFact(
                    goal_id=goal_id,
                    original_principal_id=goal.original_principal_id,
                    tenant_id=goal.tenant_id,
                    session_id=goal.session_id,
                    delegation_id=goal.delegation_id,
                    state=GoalIntegrityState.VIOLATED if ordered_risks else GoalIntegrityState.HOLDS,
                    risks=ordered_risks,
                    denied_step_ids=denied_steps,
                    denied_mutation_ids=denied_mutations,
                    max_risk_score=max_score,
                )
            )

        denied_steps = tuple(sorted(value.step_id for value in step_facts if value.decision == IntegrityDecision.DENY))
        denied_mutations = tuple(sorted(value.mutation_id for value in mutation_facts if value.decision == IntegrityDecision.DENY))
        unsafe_goals = tuple(sorted(value.goal_id for value in goal_facts if value.state == GoalIntegrityState.VIOLATED))
        max_risk = max([*(value.risk_score for value in step_facts), *(value.risk_score for value in mutation_facts), *(value.max_risk_score for value in goal_facts)], default=0)
        if set(request.declared_denied_step_ids) != set(denied_steps):
            _reject(GoalPlanRejectReason.DECLARED_STEP_DECISION_MISMATCH, "caller-declared denied steps differ from derived evidence")
        if set(request.declared_denied_mutation_ids) != set(denied_mutations):
            _reject(GoalPlanRejectReason.DECLARED_MUTATION_DECISION_MISMATCH, "caller-declared denied mutations differ from derived evidence")
        if set(request.declared_unsafe_goal_ids) != set(unsafe_goals):
            _reject(GoalPlanRejectReason.DECLARED_GOAL_STATE_MISMATCH, "caller-declared unsafe goals differ from derived evidence")
        if request.declared_max_integrity_risk_score != max_risk:
            _reject(GoalPlanRejectReason.DECLARED_MAX_RISK_MISMATCH, "caller-declared maximum integrity risk differs from derived evidence")

        prioritized = tuple(value.goal_id for value in sorted((value for value in goal_facts if value.state == GoalIntegrityState.VIOLATED), key=lambda value: (-value.max_risk_score, value.goal_id)))
        evidence_document = {
            "goals": [asdict(value) for value in goal_facts],
            "graph_sha256": graph_sha,
            "mutations": [asdict(value) for value in mutation_facts],
            "p7i_assessment_evidence_sha256": _digest(p7i_assessment),
            "p8a_assessment_evidence_sha256": _digest(p8a_assessment),
            "p8b_assessment_evidence_sha256": _digest(p8b_assessment),
            "prioritized_unsafe_goal_ids": list(prioritized),
            "steps": [asdict(value) for value in step_facts],
        }
        assessment_sha = hashlib.sha256(json.dumps(evidence_document, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()
        all_denied_risks = [risk for value in (*step_facts, *mutation_facts) if value.decision == IntegrityDecision.DENY for risk in value.risks]
        return VerifiedGoalPlanIntegrityAssessment(
            graph_id=manifest.graph_id,
            graph_version=manifest.version,
            graph_sha256=graph_sha,
            p8a_assessment_evidence_sha256=_digest(p8a_assessment),
            p8b_assessment_evidence_sha256=_digest(p8b_assessment),
            p7i_assessment_evidence_sha256=_digest(p7i_assessment),
            goal_count=len(goal_facts),
            safe_goal_count=len(goal_facts) - len(unsafe_goals),
            unsafe_goal_count=len(unsafe_goals),
            step_count=len(step_facts),
            allowed_step_count=len(step_facts) - len(denied_steps),
            denied_step_count=len(denied_steps),
            mutation_count=len(mutation_facts),
            allowed_mutation_count=len(mutation_facts) - len(denied_mutations),
            denied_mutation_count=len(denied_mutations),
            instruction_laundering_denial_count=sum(risk == GoalPlanRisk.INSTRUCTION_LAUNDERING for risk in all_denied_risks),
            goal_scope_expansion_denial_count=sum(risk == GoalPlanRisk.GOAL_SCOPE_EXPANSION for risk in all_denied_risks),
            termination_bypass_denial_count=sum(risk == GoalPlanRisk.TERMINATION_BYPASS for risk in all_denied_risks),
            rollback_bypass_denial_count=sum(risk == GoalPlanRisk.ROLLBACK_BYPASS for risk in all_denied_risks),
            max_integrity_risk_score=max_risk,
            prioritized_unsafe_goal_ids=prioritized,
            steps=tuple(step_facts),
            mutations=tuple(mutation_facts),
            goals=tuple(goal_facts),
            assessment_evidence_sha256=assessment_sha,
        )
