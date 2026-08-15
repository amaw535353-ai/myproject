from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace

from aegis.agentic.state_machine_security import (
    AgentStateMachineSecurityAnalyzer,
    AgentStateTransitionManifest,
    AgentStateTransitionPolicy,
    AgentStateTransitionRequest,
    ConcurrencyControl,
    LeaseRecord,
    StateObject,
    StateObjectType,
    StateTransition,
    TransitionDecision,
    TransitionIntent,
    agent_state_transition_manifest_digest,
)

NOW = 1_786_796_800
GRAPH_ID = "aegis-agent-state-transition-graph"
GRAPH_VERSION = "1"
OWNER = "platform-security"

P8D_DIGEST = hashlib.sha256(b"p8d-state-race-evidence").hexdigest()
P8F_DIGEST = hashlib.sha256(b"p8f-state-race-evidence").hexdigest()
P8G_DIGEST = hashlib.sha256(b"p8g-state-race-evidence").hexdigest()


def sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


OBJECT_IDS = (
    "state-ticket",
    "state-release",
    "state-telemetry",
    "state-policy",
    "state-task",
    "state-memory",
)
LEASE_IDS = ("lease-telemetry",)
TRANSITION_IDS = (
    "transition-task-read",
    "transition-ticket-1",
    "transition-ticket-2",
    "transition-release",
    "transition-telemetry",
    "transition-policy",
    "transition-memory",
    "transition-task-cancel",
)


def make_upstreams(
    *,
    denied_observations=frozenset(),
    denied_actions=frozenset(),
    denied_messages=frozenset(),
    p8d_digest=P8D_DIGEST,
    p8f_digest=P8F_DIGEST,
    p8g_digest=P8G_DIGEST,
    verified=True,
):
    observation_specs = (
        ("obs-ticket-1", "allow"),
        ("obs-ticket-2", "allow"),
        ("obs-release", "allow"),
        ("obs-telemetry", "allow"),
        ("obs-policy", "allow"),
        ("obs-memory", "allow"),
    )
    observations = tuple(
        SimpleNamespace(
            observation_id=oid,
            decision="deny" if oid in denied_observations else decision,
        )
        for oid, decision in observation_specs
    )
    actions = tuple(
        SimpleNamespace(
            action_id=aid,
            outcome="deny" if aid in denied_actions else "allow",
        )
        for aid in ("action-ticket", "action-release", "action-telemetry", "action-policy")
    )
    message_specs = (
        ("msg-task-read", "agent-orchestrator", "tenant-A"),
        ("msg-ticket-1", "agent-tool", "tenant-A"),
        ("msg-ticket-2", "agent-tool", "tenant-A"),
        ("msg-release", "agent-release", "platform"),
        ("msg-telemetry", "agent-security", "platform"),
        ("msg-policy", "agent-policy", "platform"),
        ("msg-memory", "agent-memory", "tenant-A"),
        ("msg-task-cancel", "agent-orchestrator", "tenant-A"),
    )
    messages = tuple(
        SimpleNamespace(
            message_id=mid,
            sender_agent_id=sender,
            tenant_id=tenant,
            decision="deny" if mid in denied_messages else "allow",
        )
        for mid, sender, tenant in message_specs
    )
    return {
        "p8d": SimpleNamespace(
            assessment_evidence_sha256=p8d_digest,
            exact_tool_observation_graph_binding_verified=verified,
            caller_declared_tool_observation_safety_trusted=False,
            observations=observations,
        ),
        "p8f": SimpleNamespace(
            assessment_evidence_sha256=p8f_digest,
            exact_human_approval_graph_binding_verified=verified,
            caller_declared_approval_safety_trusted=False,
            actions=actions,
        ),
        "p8g": SimpleNamespace(
            assessment_evidence_sha256=p8g_digest,
            exact_agent_message_graph_binding_verified=verified,
            caller_declared_message_safety_trusted=False,
            messages=messages,
        ),
    }


def _objects() -> tuple[StateObject, ...]:
    return (
        StateObject("state-ticket", StateObjectType.TOOL_RESOURCE, "tenant-A", 10, sha("ticket-v10"), OWNER, "Tenant ticket state."),
        StateObject("state-release", StateObjectType.RELEASE, "platform", 42, sha("release-v42"), OWNER, "Model release slot."),
        StateObject("state-telemetry", StateObjectType.TELEMETRY, "platform", 7, sha("telemetry-v7"), OWNER, "Security telemetry config."),
        StateObject("state-policy", StateObjectType.POLICY, "platform", 12, sha("policy-v12"), OWNER, "Authorization policy."),
        StateObject("state-task", StateObjectType.TASK, "tenant-A", 3, sha("task-v3"), OWNER, "Agent task lifecycle."),
        StateObject("state-memory", StateObjectType.MEMORY, "tenant-A", 5, sha("memory-v5"), OWNER, "Tenant agent memory metadata."),
    )


def _leases() -> tuple[LeaseRecord, ...]:
    return (
        LeaseRecord(
            "lease-telemetry",
            "state-telemetry",
            "agent-security",
            NOW - 100,
            NOW + 120,
            OWNER,
            "Short-lived lease for telemetry config mutation.",
        ),
    )


def _transitions() -> tuple[StateTransition, ...]:
    return (
        StateTransition(
            "transition-task-read",
            "state-task",
            "msg-task-read",
            None,
            None,
            "agent-orchestrator",
            "user-a",
            "tenant-A",
            TransitionIntent.READ,
            ConcurrencyControl.EXPECTED_VERSION,
            3,
            sha("task-v3"),
            3,
            sha("task-v3"),
            None,
            None,
            None,
            None,
            sha("payload-task-read"),
            False,
            NOW - 80,
            NOW - 79,
            OWNER,
            "Read current task state.",
        ),
        StateTransition(
            "transition-ticket-1",
            "state-ticket",
            "msg-ticket-1",
            "action-ticket",
            "obs-ticket-1",
            "agent-tool",
            "user-a",
            "tenant-A",
            TransitionIntent.MUTATE,
            ConcurrencyControl.EXPECTED_VERSION,
            10,
            sha("ticket-v10"),
            11,
            sha("ticket-v11"),
            "idem-ticket-1",
            None,
            10,
            sha("ticket-v10"),
            sha("payload-ticket-1"),
            False,
            NOW - 70,
            NOW - 69,
            OWNER,
            "First safe ticket mutation.",
        ),
        StateTransition(
            "transition-ticket-2",
            "state-ticket",
            "msg-ticket-2",
            "action-ticket",
            "obs-ticket-2",
            "agent-tool",
            "user-a",
            "tenant-A",
            TransitionIntent.MUTATE,
            ConcurrencyControl.EXPECTED_VERSION,
            11,
            sha("ticket-v11"),
            12,
            sha("ticket-v12"),
            "idem-ticket-2",
            None,
            11,
            sha("ticket-v11"),
            sha("payload-ticket-2"),
            False,
            NOW - 60,
            NOW - 59,
            OWNER,
            "Second safe ticket mutation after observing v11.",
        ),
        StateTransition(
            "transition-release",
            "state-release",
            "msg-release",
            "action-release",
            "obs-release",
            "agent-release",
            "release-admin",
            "platform",
            TransitionIntent.COMMIT,
            ConcurrencyControl.IDEMPOTENCY_KEY,
            42,
            sha("release-v42"),
            43,
            sha("release-v43"),
            "idem-release-v43",
            None,
            42,
            sha("release-v42"),
            sha("payload-release"),
            True,
            NOW - 50,
            NOW - 49,
            OWNER,
            "Irreversible release commit protected by idempotency and exact state.",
        ),
        StateTransition(
            "transition-telemetry",
            "state-telemetry",
            "msg-telemetry",
            "action-telemetry",
            "obs-telemetry",
            "agent-security",
            "security-admin",
            "platform",
            TransitionIntent.MUTATE,
            ConcurrencyControl.LEASE,
            7,
            sha("telemetry-v7"),
            8,
            sha("telemetry-v8"),
            "idem-telemetry-v8",
            "lease-telemetry",
            7,
            sha("telemetry-v7"),
            sha("payload-telemetry"),
            False,
            NOW - 40,
            NOW - 39,
            OWNER,
            "Lease-protected telemetry config mutation.",
        ),
        StateTransition(
            "transition-policy",
            "state-policy",
            "msg-policy",
            "action-policy",
            "obs-policy",
            "agent-policy",
            "security-admin",
            "platform",
            TransitionIntent.MUTATE,
            ConcurrencyControl.SERIALIZABLE,
            12,
            sha("policy-v12"),
            13,
            sha("policy-v13"),
            "idem-policy-v13",
            None,
            12,
            sha("policy-v12"),
            sha("payload-policy"),
            False,
            NOW - 30,
            NOW - 29,
            OWNER,
            "Serializable authorization-policy mutation.",
        ),
        StateTransition(
            "transition-memory",
            "state-memory",
            "msg-memory",
            None,
            None,
            "agent-memory",
            "user-a",
            "tenant-A",
            TransitionIntent.MUTATE,
            ConcurrencyControl.EXPECTED_VERSION,
            5,
            sha("memory-v5"),
            6,
            sha("memory-v6"),
            "idem-memory-v6",
            None,
            None,
            None,
            sha("payload-memory"),
            False,
            NOW - 20,
            NOW - 19,
            OWNER,
            "Version-checked tenant memory metadata update.",
        ),
        StateTransition(
            "transition-task-cancel",
            "state-task",
            "msg-task-cancel",
            None,
            None,
            "agent-orchestrator",
            "user-a",
            "tenant-A",
            TransitionIntent.CANCEL,
            ConcurrencyControl.EXPECTED_VERSION,
            3,
            sha("task-v3"),
            4,
            sha("task-cancelled-v4"),
            "idem-task-cancel",
            None,
            None,
            None,
            sha("payload-task-cancel"),
            False,
            NOW - 10,
            NOW - 9,
            OWNER,
            "Cancel task after its safe read.",
        ),
    )


def build_fixture():
    objects = _objects()
    leases = _leases()
    transitions = _transitions()
    manifest = AgentStateTransitionManifest(
        GRAPH_ID,
        GRAPH_VERSION,
        P8D_DIGEST,
        P8F_DIGEST,
        P8G_DIGEST,
        NOW - 120,
        objects,
        leases,
        transitions,
    )
    digest = agent_state_transition_manifest_digest(manifest)
    policy = AgentStateTransitionPolicy(
        expected_graph_id=GRAPH_ID,
        expected_graph_version=GRAPH_VERSION,
        expected_graph_sha256=digest,
        expected_p8d_assessment_evidence_sha256=P8D_DIGEST,
        expected_p8f_assessment_evidence_sha256=P8F_DIGEST,
        expected_p8g_assessment_evidence_sha256=P8G_DIGEST,
        required_object_ids=frozenset(o.object_id for o in objects),
        required_lease_ids=frozenset(l.lease_id for l in leases),
        required_transition_ids=frozenset(t.transition_id for t in transitions),
        trusted_owner_ids=frozenset({OWNER}),
        expected_object_profiles={
            o.object_id: (o.object_type, o.tenant_id, o.version, o.state_sha256)
            for o in objects
        },
        allowed_intents_by_object={
            "state-ticket": frozenset({TransitionIntent.READ, TransitionIntent.MUTATE, TransitionIntent.ROLLBACK}),
            "state-release": frozenset({TransitionIntent.READ, TransitionIntent.RESERVE, TransitionIntent.COMMIT, TransitionIntent.ROLLBACK}),
            "state-telemetry": frozenset({TransitionIntent.READ, TransitionIntent.MUTATE, TransitionIntent.ROLLBACK}),
            "state-policy": frozenset({TransitionIntent.READ, TransitionIntent.MUTATE, TransitionIntent.ROLLBACK}),
            "state-task": frozenset({TransitionIntent.READ, TransitionIntent.CANCEL, TransitionIntent.ROLLBACK}),
            "state-memory": frozenset({TransitionIntent.READ, TransitionIntent.MUTATE, TransitionIntent.ROLLBACK}),
        },
        allowed_controls_by_object={
            "state-ticket": frozenset({ConcurrencyControl.EXPECTED_VERSION, ConcurrencyControl.SERIALIZABLE}),
            "state-release": frozenset({ConcurrencyControl.IDEMPOTENCY_KEY, ConcurrencyControl.SERIALIZABLE}),
            "state-telemetry": frozenset({ConcurrencyControl.LEASE}),
            "state-policy": frozenset({ConcurrencyControl.SERIALIZABLE, ConcurrencyControl.EXPECTED_VERSION}),
            "state-task": frozenset({ConcurrencyControl.EXPECTED_VERSION, ConcurrencyControl.IDEMPOTENCY_KEY}),
            "state-memory": frozenset({ConcurrencyControl.EXPECTED_VERSION}),
        },
        approval_required_object_ids=frozenset({"state-ticket", "state-release", "state-telemetry", "state-policy"}),
        observation_required_object_ids=frozenset({"state-ticket", "state-release", "state-telemetry", "state-policy"}),
        lease_required_object_ids=frozenset({"state-telemetry"}),
        irreversible_object_ids=frozenset({"state-release"}),
    )
    ctx = {"manifest": manifest, "policy": policy, **make_upstreams()}
    ctx["request"] = truthful_request(ctx)
    return ctx


def truthful_request(ctx):
    facts, versions, _hashes = AgentStateMachineSecurityAnalyzer(ctx["policy"]).derive(
        ctx["manifest"], ctx["p8d"], ctx["p8f"], ctx["p8g"], NOW
    )
    return AgentStateTransitionRequest(
        graph_id=GRAPH_ID,
        graph_version=GRAPH_VERSION,
        graph_sha256=ctx["policy"].expected_graph_sha256,
        p8d_assessment_evidence_sha256=P8D_DIGEST,
        p8f_assessment_evidence_sha256=P8F_DIGEST,
        p8g_assessment_evidence_sha256=P8G_DIGEST,
        evaluated_at_epoch=NOW,
        transition_ids=tuple(sorted(t.transition_id for t in ctx["manifest"].transitions)),
        declared_denied_transition_ids=tuple(
            sorted(f.transition_id for f in facts if f.decision == TransitionDecision.DENY)
        ),
        declared_risks_by_transition={f.transition_id: f.risks for f in facts},
        declared_final_versions=dict(versions),
    )


def replace_item(manifest: AgentStateTransitionManifest, collection: str, item_id: str, **changes):
    attr = {"objects": "object_id", "leases": "lease_id", "transitions": "transition_id"}[collection]
    values = []
    found = False
    for item in getattr(manifest, collection):
        if getattr(item, attr) == item_id:
            values.append(replace(item, **changes))
            found = True
        else:
            values.append(item)
    if not found:
        raise KeyError(item_id)
    return replace(manifest, **{collection: tuple(values)})


def rebind(ctx, *, truthful=False):
    digest = agent_state_transition_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    if truthful:
        ctx["request"] = truthful_request(ctx)
    return ctx


def clone_context():
    return dict(build_fixture())
