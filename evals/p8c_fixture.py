from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace
from typing import Mapping

from aegis.agentic.goal_plan_security import (
    AgentGoal,
    GoalPlanManifest,
    GoalPlanPolicy,
    GoalPlanRequest,
    InstructionDirective,
    InstructionRecord,
    InstructionSource,
    InstructionTrust,
    PlanMutation,
    PlanMutationType,
    PlanStep,
    goal_plan_manifest_digest,
    instruction_provenance_digest,
)

NOW = 2_200_400_000
GRAPH_ID = "aegisdesk-agent-goal-plan-integrity"
GRAPH_VERSION = "2026.08-p8c.1"
P8A_SHA = hashlib.sha256(b"p8a-for-p8c").hexdigest()
P8B_SHA = hashlib.sha256(b"p8b-for-p8c").hexdigest()
P7I_SHA = hashlib.sha256(b"p7i-for-p8c").hexdigest()
SANITIZATION_SHA = hashlib.sha256(b"approved-p8c-sanitization").hexdigest()

GOAL_RETRIEVAL = "goal-retrieval"
GOAL_TOOL = "goal-tool"
GOAL_RELEASE_INSPECT = "goal-release-inspect"
GOAL_RELEASE_DEPLOY = "goal-release-deploy"
GOAL_TELEMETRY = "goal-telemetry-change"
GOAL_IDS = (GOAL_RETRIEVAL, GOAL_TOOL, GOAL_RELEASE_INSPECT, GOAL_RELEASE_DEPLOY, GOAL_TELEMETRY)

INSTR_RETRIEVAL = "instr-user-retrieval"
INSTR_MEMORY_HINT = "instr-memory-hint"
INSTR_TOOL = "instr-delegated-tool"
INSTR_TOOL_OUTPUT = "instr-tool-output"
INSTR_RELEASE_INSPECT = "instr-release-inspect"
INSTR_RELEASE_DEPLOY = "instr-release-deploy"
INSTR_RELEASE_STOP = "instr-release-stop"
INSTR_TELEMETRY = "instr-telemetry-change"
INSTR_TELEMETRY_ROLLBACK = "instr-telemetry-rollback"
INSTRUCTION_IDS = (
    INSTR_RETRIEVAL,
    INSTR_MEMORY_HINT,
    INSTR_TOOL,
    INSTR_TOOL_OUTPUT,
    INSTR_RELEASE_INSPECT,
    INSTR_RELEASE_DEPLOY,
    INSTR_RELEASE_STOP,
    INSTR_TELEMETRY,
    INSTR_TELEMETRY_ROLLBACK,
)

STEP_RETRIEVAL = "step-retrieval-query"
STEP_TOOL = "step-tool-read"
STEP_RELEASE_INSPECT = "step-release-inspect"
STEP_RELEASE_DEPLOY = "step-release-deploy"
STEP_RELEASE_ROLLBACK = "step-release-rollback"
STEP_TELEMETRY_CHANGE = "step-telemetry-change"
STEP_TELEMETRY_ROLLBACK = "step-telemetry-rollback"
STEP_IDS = (
    STEP_RETRIEVAL,
    STEP_TOOL,
    STEP_RELEASE_INSPECT,
    STEP_RELEASE_DEPLOY,
    STEP_RELEASE_ROLLBACK,
    STEP_TELEMETRY_CHANGE,
    STEP_TELEMETRY_ROLLBACK,
)

MUTATION_RELEASE_REINSPECT = "mutation-release-reinspect"
MUTATION_TELEMETRY_ROLLBACK = "mutation-telemetry-rollback"
MUTATION_IDS = (MUTATION_RELEASE_REINSPECT, MUTATION_TELEMETRY_ROLLBACK)

ACTION_RETRIEVAL = "retrieval.query"
ACTION_TOOL_READ = "tool.read"
ACTION_MODEL_INSPECT = "model.inspect"
ACTION_MODEL_DEPLOY = "model.deploy"
ACTION_MODEL_ROLLBACK = "model.rollback"
ACTION_TELEMETRY_CHANGE = "telemetry.change"
ACTION_TELEMETRY_ROLLBACK = "telemetry.rollback"
ACTION_CLASSES = (
    ACTION_RETRIEVAL,
    ACTION_TOOL_READ,
    ACTION_MODEL_INSPECT,
    ACTION_MODEL_DEPLOY,
    ACTION_MODEL_ROLLBACK,
    ACTION_TELEMETRY_CHANGE,
    ACTION_TELEMETRY_ROLLBACK,
)

INV_TOOL = "INV-PRIVILEGED-TOOL-AUTHZ"
INV_TENANT = "INV-TENANT-DATA-CONFINEMENT"
INV_RELEASE = "INV-MODEL-RELEASE-INTEGRITY"
INV_TELEMETRY = "INV-SECURITY-TELEMETRY-CONTINUITY"
INV_ADMIN = "INV-ADMIN-NON-SELF-BYPASS"
INVARIANT_IDS = (INV_TOOL, INV_TENANT, INV_RELEASE, INV_TELEMETRY, INV_ADMIN)

RETRIEVAL_PREFS = "retrieval-user-preferences"


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _root_instruction(
    instruction_id: str,
    goal_id: str,
    source: InstructionSource,
    trust: InstructionTrust,
    precedence: int,
    tenant_id: str,
    session_id: str | None,
    principal: str,
    actions: tuple[str, ...],
    issued_at: int,
    owner: str,
    directive: InstructionDirective = InstructionDirective.OBJECTIVE,
) -> InstructionRecord:
    content = _hash(f"content:{instruction_id}")
    return InstructionRecord(
        instruction_id=instruction_id,
        goal_id=goal_id,
        source=source,
        directive=directive,
        trust=trust,
        precedence=precedence,
        tenant_id=tenant_id,
        session_id=session_id,
        original_principal_id=principal,
        content_sha256=content,
        provenance_sha256=_hash(f"provenance:{instruction_id}"),
        parent_instruction_id=None,
        memory_retrieval_id=None,
        tool_output_sha256=None,
        allowed_action_classes=actions,
        sanitized=False,
        sanitization_evidence_sha256=None,
        issued_at_epoch=issued_at,
        owner_id=owner,
        description=instruction_id,
    )


def _instructions() -> tuple[InstructionRecord, ...]:
    retrieval = _root_instruction(
        INSTR_RETRIEVAL, GOAL_RETRIEVAL, InstructionSource.USER_GOAL, InstructionTrust.USER_AUTHORIZED, 80,
        "tenant-a", "session-a", "user-a", (ACTION_RETRIEVAL,), NOW - 300, "agent-platform",
    )
    memory_content = _hash("content:memory-hint")
    memory = InstructionRecord(
        instruction_id=INSTR_MEMORY_HINT,
        goal_id=GOAL_RETRIEVAL,
        source=InstructionSource.MEMORY,
        directive=InstructionDirective.SUGGESTION,
        trust=InstructionTrust.CONTEXTUAL,
        precedence=30,
        tenant_id="tenant-a",
        session_id="session-a",
        original_principal_id="user-a",
        content_sha256=memory_content,
        provenance_sha256=instruction_provenance_digest(retrieval.provenance_sha256, memory_content),
        parent_instruction_id=INSTR_RETRIEVAL,
        memory_retrieval_id=RETRIEVAL_PREFS,
        tool_output_sha256=None,
        allowed_action_classes=(ACTION_RETRIEVAL,),
        sanitized=False,
        sanitization_evidence_sha256=None,
        issued_at_epoch=NOW - 250,
        owner_id="agent-platform",
        description="Retrieved user-preference hint; context only, never authority.",
    )
    tool = _root_instruction(
        INSTR_TOOL, GOAL_TOOL, InstructionSource.DELEGATED_GOAL, InstructionTrust.DELEGATED_AUTHORIZED, 70,
        "tenant-a", "session-a", "user-a", (ACTION_TOOL_READ,), NOW - 240, "tool-security",
    )
    tool_content = _hash("content:tool-output")
    tool_output = InstructionRecord(
        instruction_id=INSTR_TOOL_OUTPUT,
        goal_id=GOAL_TOOL,
        source=InstructionSource.TOOL_OUTPUT,
        directive=InstructionDirective.SUGGESTION,
        trust=InstructionTrust.UNTRUSTED,
        precedence=20,
        tenant_id="tenant-a",
        session_id="session-a",
        original_principal_id="user-a",
        content_sha256=tool_content,
        provenance_sha256=instruction_provenance_digest(tool.provenance_sha256, tool_content),
        parent_instruction_id=INSTR_TOOL,
        memory_retrieval_id=None,
        tool_output_sha256=_hash("tool-output-payload"),
        allowed_action_classes=(ACTION_TOOL_READ,),
        sanitized=False,
        sanitization_evidence_sha256=None,
        issued_at_epoch=NOW - 200,
        owner_id="tool-security",
        description="Tool output is treated as untrusted context.",
    )
    release_inspect = _root_instruction(
        INSTR_RELEASE_INSPECT, GOAL_RELEASE_INSPECT, InstructionSource.USER_GOAL, InstructionTrust.USER_AUTHORIZED, 80,
        "system", None, "release-admin", (ACTION_MODEL_INSPECT,), NOW - 220, "release-security",
    )
    release_deploy = _root_instruction(
        INSTR_RELEASE_DEPLOY, GOAL_RELEASE_DEPLOY, InstructionSource.USER_GOAL, InstructionTrust.USER_AUTHORIZED, 80,
        "system", None, "release-admin", (ACTION_MODEL_DEPLOY, ACTION_MODEL_ROLLBACK), NOW - 210, "release-security",
    )
    release_stop = _root_instruction(
        INSTR_RELEASE_STOP, GOAL_RELEASE_DEPLOY, InstructionSource.SYSTEM_POLICY, InstructionTrust.SYSTEM, 100,
        "system", None, "release-admin", (ACTION_MODEL_ROLLBACK,), NOW - 5, "release-security", InstructionDirective.TERMINATE,
    )
    telemetry = _root_instruction(
        INSTR_TELEMETRY, GOAL_TELEMETRY, InstructionSource.USER_GOAL, InstructionTrust.USER_AUTHORIZED, 80,
        "system", None, "security-admin", (ACTION_TELEMETRY_CHANGE, ACTION_TELEMETRY_ROLLBACK), NOW - 190, "security-platform",
    )
    telemetry_rollback = _root_instruction(
        INSTR_TELEMETRY_ROLLBACK, GOAL_TELEMETRY, InstructionSource.SYSTEM_POLICY, InstructionTrust.SYSTEM, 100,
        "system", None, "security-admin", (ACTION_TELEMETRY_ROLLBACK,), NOW - 180, "security-platform", InstructionDirective.ROLLBACK,
    )
    return (
        retrieval,
        memory,
        tool,
        tool_output,
        release_inspect,
        release_deploy,
        release_stop,
        telemetry,
        telemetry_rollback,
    )


def _goals() -> tuple[AgentGoal, ...]:
    return (
        AgentGoal(GOAL_RETRIEVAL, INSTR_RETRIEVAL, "user-a", "tenant-a", "session-a", "delegation-retrieval", (ACTION_RETRIEVAL,), 2, NOW - 300, NOW + 1800, "agent-platform", "Tenant retrieval goal."),
        AgentGoal(GOAL_TOOL, INSTR_TOOL, "user-a", "tenant-a", "session-a", "delegation-tool-child", (ACTION_TOOL_READ,), 2, NOW - 240, NOW + 1600, "tool-security", "Tenant tool-read goal."),
        AgentGoal(GOAL_RELEASE_INSPECT, INSTR_RELEASE_INSPECT, "release-admin", "system", None, "delegation-release-inspect", (ACTION_MODEL_INSPECT,), 2, NOW - 220, NOW + 1400, "release-security", "Inspect model release."),
        AgentGoal(GOAL_RELEASE_DEPLOY, INSTR_RELEASE_DEPLOY, "release-admin", "system", None, "delegation-release-deploy", (ACTION_MODEL_DEPLOY, ACTION_MODEL_ROLLBACK), 3, NOW - 210, NOW + 1200, "release-security", "Deploy model with rollback boundary."),
        AgentGoal(GOAL_TELEMETRY, INSTR_TELEMETRY, "security-admin", "system", None, "delegation-telemetry-configure", (ACTION_TELEMETRY_CHANGE, ACTION_TELEMETRY_ROLLBACK), 3, NOW - 190, NOW + 1200, "security-platform", "Modify telemetry with rollback boundary."),
    )


def _steps() -> tuple[PlanStep, ...]:
    return (
        PlanStep(STEP_RETRIEVAL, GOAL_RETRIEVAL, 1, "agent-retrieval-a", ACTION_RETRIEVAL, (INSTR_RETRIEVAL, INSTR_MEMORY_HINT), ("search.read", "tenant.retrieve"), (RETRIEVAL_PREFS,), False, None, NOW - 180, "agent-platform", "Retrieve tenant data."),
        PlanStep(STEP_TOOL, GOAL_TOOL, 1, "agent-tool-executor-a", ACTION_TOOL_READ, (INSTR_TOOL, INSTR_TOOL_OUTPUT), ("tool.read",), (), False, None, NOW - 170, "tool-security", "Read from privileged tool under delegated scope."),
        PlanStep(STEP_RELEASE_INSPECT, GOAL_RELEASE_INSPECT, 1, "agent-release", ACTION_MODEL_INSPECT, (INSTR_RELEASE_INSPECT,), ("model.inspect",), (), False, None, NOW - 160, "release-security", "Inspect release metadata."),
        PlanStep(STEP_RELEASE_DEPLOY, GOAL_RELEASE_DEPLOY, 1, "agent-release", ACTION_MODEL_DEPLOY, (INSTR_RELEASE_DEPLOY,), ("model.deploy",), (), True, None, NOW - 150, "release-security", "Deploy release."),
        PlanStep(STEP_RELEASE_ROLLBACK, GOAL_RELEASE_DEPLOY, 2, "agent-release", ACTION_MODEL_ROLLBACK, (INSTR_RELEASE_DEPLOY,), ("model.deploy",), (), False, STEP_RELEASE_DEPLOY, NOW - 140, "release-security", "Rollback deployment if required."),
        PlanStep(STEP_TELEMETRY_CHANGE, GOAL_TELEMETRY, 1, "agent-observability", ACTION_TELEMETRY_CHANGE, (INSTR_TELEMETRY,), ("telemetry.configure",), (), True, None, NOW - 130, "security-observability", "Apply telemetry change."),
        PlanStep(STEP_TELEMETRY_ROLLBACK, GOAL_TELEMETRY, 2, "agent-observability", ACTION_TELEMETRY_ROLLBACK, (INSTR_TELEMETRY, INSTR_TELEMETRY_ROLLBACK), ("telemetry.configure",), (), False, STEP_TELEMETRY_CHANGE, NOW - 120, "security-observability", "Rollback telemetry change."),
    )


def _mutations() -> tuple[PlanMutation, ...]:
    return (
        PlanMutation(MUTATION_RELEASE_REINSPECT, GOAL_RELEASE_INSPECT, "agent-release-orchestrator", STEP_RELEASE_INSPECT, PlanMutationType.APPEND, INSTR_RELEASE_INSPECT, ACTION_MODEL_INSPECT, (INSTR_RELEASE_INSPECT,), NOW - 100, "release-security", "Optional reinspection remains in goal scope."),
        PlanMutation(MUTATION_TELEMETRY_ROLLBACK, GOAL_TELEMETRY, "agent-security", STEP_TELEMETRY_CHANGE, PlanMutationType.ROLLBACK, INSTR_TELEMETRY_ROLLBACK, ACTION_TELEMETRY_ROLLBACK, (INSTR_TELEMETRY, INSTR_TELEMETRY_ROLLBACK), NOW - 90, "security-platform", "System-authorized rollback mutation."),
    )


def make_upstreams(
    *,
    denied_delegations: frozenset[str] = frozenset(),
    denied_retrievals: frozenset[str] = frozenset(),
    unsafe_invariants: frozenset[str] = frozenset(),
) -> dict[str, object]:
    delegation_specs = {
        "delegation-retrieval": ("user-a", "tenant-a", ("search.read", "tenant.retrieve")),
        "delegation-tool-child": ("user-a", "tenant-a", ("tool.read",)),
        "delegation-release-inspect": ("release-admin", "system", ("model.inspect",)),
        "delegation-release-deploy": ("release-admin", "system", ("model.deploy",)),
        "delegation-telemetry-configure": ("security-admin", "system", ("telemetry.configure",)),
    }
    p8a = SimpleNamespace(
        assessment_evidence_sha256=P8A_SHA,
        exact_delegation_graph_binding_verified=True,
        agent_identity_continuity_verified=True,
        authority_non_amplification_verified=True,
        delegations=tuple(
            SimpleNamespace(
                delegation_id=delegation_id,
                decision="deny" if delegation_id in denied_delegations else "allow",
                original_principal_id=principal,
                tenant_id=tenant,
                requested_capability_ids=capabilities,
            )
            for delegation_id, (principal, tenant, capabilities) in delegation_specs.items()
        ),
    )
    p8b = SimpleNamespace(
        assessment_evidence_sha256=P8B_SHA,
        exact_memory_graph_binding_verified=True,
        memory_provenance_verified=True,
        retrieval_trust_labels_derived_from_evidence=True,
        revocation_and_supersession_enforced=True,
        retrievals=(
            SimpleNamespace(
                retrieval_id=RETRIEVAL_PREFS,
                decision="deny" if RETRIEVAL_PREFS in denied_retrievals else "allow",
                tenant_id="tenant-a",
                session_id="session-a",
                trust_by_memory={"memory-user-preference": "user_asserted"},
            ),
        ),
    )
    p7i = SimpleNamespace(
        assessment_evidence_sha256=P7I_SHA,
        exact_catalog_binding_verified=True,
        blast_radius_derived_from_evidence=True,
        counterevidence_preserved=True,
        invariants=tuple(SimpleNamespace(invariant_id=invariant_id, state="violated" if invariant_id in unsafe_invariants else "holds") for invariant_id in INVARIANT_IDS),
    )
    return {"p8a": p8a, "p8b": p8b, "p7i": p7i}


def build_fixture() -> dict[str, object]:
    instructions = _instructions()
    goals = _goals()
    steps = _steps()
    mutations = _mutations()
    manifest = GoalPlanManifest(
        graph_id=GRAPH_ID,
        version=GRAPH_VERSION,
        p8a_assessment_evidence_sha256=P8A_SHA,
        p8b_assessment_evidence_sha256=P8B_SHA,
        p7i_assessment_evidence_sha256=P7I_SHA,
        created_at_epoch=NOW - 350,
        instructions=instructions,
        goals=goals,
        steps=steps,
        mutations=mutations,
    )
    graph_sha = goal_plan_manifest_digest(manifest)
    policy = GoalPlanPolicy(
        expected_graph_id=GRAPH_ID,
        expected_graph_version=GRAPH_VERSION,
        expected_graph_sha256=graph_sha,
        expected_p8a_assessment_evidence_sha256=P8A_SHA,
        expected_p8b_assessment_evidence_sha256=P8B_SHA,
        expected_p7i_assessment_evidence_sha256=P7I_SHA,
        required_instruction_ids=frozenset(item.instruction_id for item in instructions),
        required_goal_ids=frozenset(item.goal_id for item in goals),
        required_step_ids=frozenset(item.step_id for item in steps),
        required_mutation_ids=frozenset(item.mutation_id for item in mutations),
        trusted_owner_ids=frozenset({"agent-platform", "tool-security", "release-security", "security-platform", "security-observability"}),
        trusted_agent_ids=frozenset({"agent-retrieval-a", "agent-tool-executor-a", "agent-release", "agent-observability"}),
        trusted_mutation_agent_ids=frozenset({"agent-release-orchestrator", "agent-security"}),
        allowed_sanitization_evidence_sha256=frozenset({SANITIZATION_SHA}),
        expected_instruction_source={item.instruction_id: item.source for item in instructions},
        expected_instruction_directive={item.instruction_id: item.directive for item in instructions},
        expected_instruction_trust={item.instruction_id: item.trust for item in instructions},
        expected_instruction_precedence={item.instruction_id: item.precedence for item in instructions},
        expected_instruction_allowed_actions={item.instruction_id: frozenset(item.allowed_action_classes) for item in instructions},
        expected_goal_root_instruction={item.goal_id: item.root_instruction_id for item in goals},
        expected_goal_principal={item.goal_id: item.original_principal_id for item in goals},
        expected_goal_tenant={item.goal_id: item.tenant_id for item in goals},
        expected_goal_session={item.goal_id: item.session_id for item in goals},
        expected_goal_delegation={item.goal_id: item.delegation_id for item in goals},
        expected_goal_allowed_actions={item.goal_id: frozenset(item.allowed_action_classes) for item in goals},
        expected_goal_max_steps={item.goal_id: item.max_step_count for item in goals},
        action_required_capabilities={
            ACTION_RETRIEVAL: frozenset({"search.read", "tenant.retrieve"}),
            ACTION_TOOL_READ: frozenset({"tool.read"}),
            ACTION_MODEL_INSPECT: frozenset({"model.inspect"}),
            ACTION_MODEL_DEPLOY: frozenset({"model.deploy"}),
            ACTION_MODEL_ROLLBACK: frozenset({"model.deploy"}),
            ACTION_TELEMETRY_CHANGE: frozenset({"telemetry.configure"}),
            ACTION_TELEMETRY_ROLLBACK: frozenset({"telemetry.configure"}),
        },
        action_required_p7i_invariants={
            ACTION_RETRIEVAL: frozenset({INV_TENANT}),
            ACTION_TOOL_READ: frozenset({INV_TOOL}),
            ACTION_MODEL_INSPECT: frozenset({INV_RELEASE}),
            ACTION_MODEL_DEPLOY: frozenset({INV_RELEASE}),
            ACTION_MODEL_ROLLBACK: frozenset({INV_RELEASE}),
            ACTION_TELEMETRY_CHANGE: frozenset({INV_TELEMETRY, INV_ADMIN}),
            ACTION_TELEMETRY_ROLLBACK: frozenset({INV_TELEMETRY, INV_ADMIN}),
        },
        rollback_action_by_action={
            ACTION_MODEL_DEPLOY: ACTION_MODEL_ROLLBACK,
            ACTION_TELEMETRY_CHANGE: ACTION_TELEMETRY_ROLLBACK,
        },
        irreversible_action_classes=frozenset({ACTION_MODEL_DEPLOY, ACTION_TELEMETRY_CHANGE}),
    )
    request = GoalPlanRequest(
        graph_id=GRAPH_ID,
        graph_version=GRAPH_VERSION,
        graph_sha256=graph_sha,
        p8a_assessment_evidence_sha256=P8A_SHA,
        p8b_assessment_evidence_sha256=P8B_SHA,
        p7i_assessment_evidence_sha256=P7I_SHA,
        evaluated_at_epoch=NOW,
        goal_ids=tuple(sorted(item.goal_id for item in goals)),
        step_ids=tuple(sorted(item.step_id for item in steps)),
        mutation_ids=tuple(sorted(item.mutation_id for item in mutations)),
        declared_denied_step_ids=(),
        declared_denied_mutation_ids=(),
        declared_unsafe_goal_ids=(),
        declared_max_integrity_risk_score=0,
    )
    return {"manifest": manifest, "policy": policy, "request": request, **make_upstreams()}


def replace_manifest_item(manifest: GoalPlanManifest, collection: str, item_id: str, **changes: object) -> GoalPlanManifest:
    values = list(getattr(manifest, collection))
    key = {"instructions": "instruction_id", "goals": "goal_id", "steps": "step_id", "mutations": "mutation_id"}[collection]
    for index, item in enumerate(values):
        if getattr(item, key) == item_id:
            values[index] = replace(item, **changes)
            return replace(manifest, **{collection: tuple(values)})
    raise KeyError(item_id)
