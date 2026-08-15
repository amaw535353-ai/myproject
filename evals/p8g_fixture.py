from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace

from aegis.agentic.message_security import (
    AgentMessage,
    AgentMessageManifest,
    AgentMessagePolicy,
    AgentMessageRequest,
    AgentMessageProtocolSecurityAnalyzer,
    MessageChannelPolicy,
    MessageChannelType,
    MessageDecision,
    MessageIntent,
    agent_message_manifest_digest,
)

NOW = 1_786_795_600
GRAPH_ID = "aegis-agent-message-protocol-graph"
GRAPH_VERSION = "1"
OWNER = "platform-security"

P8A_DIGEST = hashlib.sha256(b"p8a-message-evidence").hexdigest()
P8C_DIGEST = hashlib.sha256(b"p8c-message-evidence").hexdigest()
P8F_DIGEST = hashlib.sha256(b"p8f-message-evidence").hexdigest()


def sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


AGENT_ORCH = "agent-orchestrator-a"
AGENT_RETRIEVAL = "agent-retrieval-a"
AGENT_TOOL_BROKER = "agent-tool-broker-a"
AGENT_TOOL_EXECUTOR = "agent-tool-executor-a"
AGENT_RELEASE_ORCH = "agent-release-orchestrator"
AGENT_RELEASE = "agent-release"
AGENT_SECURITY = "agent-security"
AGENT_OBSERVABILITY = "agent-observability"
AGENT_POLICY = "agent-policy-controller"
EXTERNAL_ADVISOR = "external-advisor"

INTERNAL_AGENTS = frozenset({
    AGENT_ORCH, AGENT_RETRIEVAL, AGENT_TOOL_BROKER, AGENT_TOOL_EXECUTOR,
    AGENT_RELEASE_ORCH, AGENT_RELEASE, AGENT_SECURITY, AGENT_OBSERVABILITY, AGENT_POLICY,
})
EXTERNAL_SENDERS = frozenset({EXTERNAL_ADVISOR})
IDENTITY_DIGESTS = {agent: sha(f"identity:{agent}") for agent in INTERNAL_AGENTS | EXTERNAL_SENDERS}

CHANNEL_IDS = (
    "channel-retrieval",
    "channel-tool-root",
    "channel-tool-child",
    "channel-release",
    "channel-telemetry",
    "channel-policy",
    "channel-external-advisory",
)
MESSAGE_IDS = (
    "msg-retrieval",
    "msg-tool-root",
    "msg-tool-child",
    "msg-release",
    "msg-telemetry",
    "msg-policy",
    "msg-external-advisory",
)

CAP_SEARCH_READ = "search.read"
CAP_TENANT_RETRIEVE = "tenant.retrieve"
CAP_TOOL_READ = "tool.read"
CAP_MODEL_DEPLOY = "model.deploy"
CAP_TELEMETRY_CONFIGURE = "telemetry.configure"
CAP_POLICY_WRITE = "policy.write"


def make_upstreams(
    *,
    denied_delegations=frozenset(),
    denied_steps=frozenset(),
    denied_actions=frozenset(),
    p8a_digest=P8A_DIGEST,
    p8c_digest=P8C_DIGEST,
    p8f_digest=P8F_DIGEST,
    verified=True,
):
    delegation_specs = (
        ("delegation-retrieval", None, "user-a", "tenant-A", (CAP_SEARCH_READ, CAP_TENANT_RETRIEVE)),
        ("delegation-tool-root", None, "user-a", "tenant-A", (CAP_TOOL_READ,)),
        ("delegation-tool-child", "delegation-tool-root", "user-a", "tenant-A", (CAP_TOOL_READ,)),
        ("delegation-release", None, "release-admin", "platform", (CAP_MODEL_DEPLOY,)),
        ("delegation-telemetry", None, "security-admin", "platform", (CAP_TELEMETRY_CONFIGURE,)),
        ("delegation-policy", None, "security-admin", "platform", (CAP_POLICY_WRITE,)),
    )
    delegations = tuple(
        SimpleNamespace(
            delegation_id=did,
            parent_delegation_id=parent,
            original_principal_id=principal,
            tenant_id=tenant,
            requested_capability_ids=caps,
            decision="deny" if did in denied_delegations else "allow",
        )
        for did, parent, principal, tenant, caps in delegation_specs
    )
    step_specs = (
        ("step-retrieval", "goal-retrieval"),
        ("step-tool", "goal-tool"),
        ("step-release", "goal-release"),
        ("step-telemetry", "goal-telemetry"),
        ("step-policy", "goal-policy"),
        ("step-advisory", "goal-advisory"),
    )
    steps = tuple(
        SimpleNamespace(step_id=sid, goal_id=gid, decision="deny" if sid in denied_steps else "allow")
        for sid, gid in step_specs
    )
    action_specs = ("action-release", "action-telemetry", "action-policy")
    actions = tuple(
        SimpleNamespace(action_id=aid, outcome="deny" if aid in denied_actions else "allow")
        for aid in action_specs
    )
    return {
        "p8a": SimpleNamespace(
            assessment_evidence_sha256=p8a_digest,
            exact_delegation_graph_binding_verified=verified,
            caller_declared_delegation_authorization_trusted=False,
            delegations=delegations,
        ),
        "p8c": SimpleNamespace(
            assessment_evidence_sha256=p8c_digest,
            exact_goal_plan_graph_binding_verified=verified,
            caller_declared_goal_safety_trusted=False,
            steps=steps,
        ),
        "p8f": SimpleNamespace(
            assessment_evidence_sha256=p8f_digest,
            exact_human_approval_graph_binding_verified=verified,
            caller_declared_approval_safety_trusted=False,
            actions=actions,
        ),
    }


def _channels() -> tuple[MessageChannelPolicy, ...]:
    return (
        MessageChannelPolicy(
            "channel-retrieval", MessageChannelType.DIRECT, OWNER,
            (AGENT_ORCH,), (AGENT_RETRIEVAL,), (MessageIntent.REQUEST,), "tenant-A",
            "agent-message-v1", 2, (CAP_SEARCH_READ, CAP_TENANT_RETRIEVE), False, None, 180,
            "Tenant orchestrator to retrieval agent."
        ),
        MessageChannelPolicy(
            "channel-tool-root", MessageChannelType.BROKERED, OWNER,
            (AGENT_ORCH,), (AGENT_TOOL_BROKER,), (MessageIntent.REQUEST,), "tenant-A",
            "agent-message-v1", 2, (CAP_TOOL_READ,), False, None, 180,
            "Tenant orchestrator to tool broker."
        ),
        MessageChannelPolicy(
            "channel-tool-child", MessageChannelType.BROKERED, OWNER,
            (AGENT_TOOL_BROKER,), (AGENT_TOOL_EXECUTOR,), (MessageIntent.COMMAND,), "tenant-A",
            "agent-message-v1", 2, (CAP_TOOL_READ,), False, None, 150,
            "Tool broker to executor."
        ),
        MessageChannelPolicy(
            "channel-release", MessageChannelType.DIRECT, OWNER,
            (AGENT_RELEASE_ORCH,), (AGENT_RELEASE,), (MessageIntent.COMMAND,), "shared",
            "agent-message-v1", 2, (CAP_MODEL_DEPLOY,), True, "action-release", 120,
            "Release command channel."
        ),
        MessageChannelPolicy(
            "channel-telemetry", MessageChannelType.BUS, OWNER,
            (AGENT_SECURITY,), (AGENT_OBSERVABILITY,), (MessageIntent.COMMAND,), "system",
            "agent-message-v1", 2, (CAP_TELEMETRY_CONFIGURE,), True, "action-telemetry", 120,
            "Security telemetry command channel."
        ),
        MessageChannelPolicy(
            "channel-policy", MessageChannelType.BUS, OWNER,
            (AGENT_SECURITY,), (AGENT_POLICY,), (MessageIntent.COMMAND,), "system",
            "agent-message-v1", 2, (CAP_POLICY_WRITE,), True, "action-policy", 120,
            "Authorization-policy command channel."
        ),
        MessageChannelPolicy(
            "channel-external-advisory", MessageChannelType.EXTERNAL, OWNER,
            (EXTERNAL_ADVISOR,), (AGENT_SECURITY,), (MessageIntent.INFORMATION,), "external",
            "agent-message-v1", 2, (), False, None, 90,
            "Authenticated but non-authoritative external advisory channel."
        ),
    )


def _messages() -> tuple[AgentMessage, ...]:
    return (
        AgentMessage(
            "msg-retrieval", "channel-retrieval", AGENT_ORCH, AGENT_RETRIEVAL,
            IDENTITY_DIGESTS[AGENT_ORCH], "user-a", "tenant-A", "task-retrieval", "goal-retrieval", "step-retrieval",
            "delegation-retrieval", None, MessageIntent.REQUEST, "agent-message-v1", 2,
            (CAP_SEARCH_READ, CAP_TENANT_RETRIEVE), sha("payload-retrieval"), None, "nonce-retrieval",
            NOW - 30, NOW + 120, OWNER, "Safe tenant retrieval request."
        ),
        AgentMessage(
            "msg-tool-root", "channel-tool-root", AGENT_ORCH, AGENT_TOOL_BROKER,
            IDENTITY_DIGESTS[AGENT_ORCH], "user-a", "tenant-A", "task-tool", "goal-tool", "step-tool",
            "delegation-tool-root", None, MessageIntent.REQUEST, "agent-message-v1", 2,
            (CAP_TOOL_READ,), sha("payload-tool-root"), None, "nonce-tool-root",
            NOW - 28, NOW + 120, OWNER, "Safe root tool request."
        ),
        AgentMessage(
            "msg-tool-child", "channel-tool-child", AGENT_TOOL_BROKER, AGENT_TOOL_EXECUTOR,
            IDENTITY_DIGESTS[AGENT_TOOL_BROKER], "user-a", "tenant-A", "task-tool", "goal-tool", "step-tool",
            "delegation-tool-child", None, MessageIntent.COMMAND, "agent-message-v1", 2,
            (CAP_TOOL_READ,), sha("payload-tool-child"), "msg-tool-root", "nonce-tool-child",
            NOW - 24, NOW + 100, OWNER, "Safe delegated tool command."
        ),
        AgentMessage(
            "msg-release", "channel-release", AGENT_RELEASE_ORCH, AGENT_RELEASE,
            IDENTITY_DIGESTS[AGENT_RELEASE_ORCH], "release-admin", "platform", "task-release", "goal-release", "step-release",
            "delegation-release", "action-release", MessageIntent.COMMAND, "agent-message-v1", 2,
            (CAP_MODEL_DEPLOY,), sha("payload-release"), None, "nonce-release",
            NOW - 20, NOW + 80, OWNER, "Approved model release command."
        ),
        AgentMessage(
            "msg-telemetry", "channel-telemetry", AGENT_SECURITY, AGENT_OBSERVABILITY,
            IDENTITY_DIGESTS[AGENT_SECURITY], "security-admin", "platform", "task-telemetry", "goal-telemetry", "step-telemetry",
            "delegation-telemetry", "action-telemetry", MessageIntent.COMMAND, "agent-message-v1", 2,
            (CAP_TELEMETRY_CONFIGURE,), sha("payload-telemetry"), None, "nonce-telemetry",
            NOW - 18, NOW + 80, OWNER, "Approved telemetry change command."
        ),
        AgentMessage(
            "msg-policy", "channel-policy", AGENT_SECURITY, AGENT_POLICY,
            IDENTITY_DIGESTS[AGENT_SECURITY], "security-admin", "platform", "task-policy", "goal-policy", "step-policy",
            "delegation-policy", "action-policy", MessageIntent.COMMAND, "agent-message-v1", 2,
            (CAP_POLICY_WRITE,), sha("payload-policy"), None, "nonce-policy",
            NOW - 16, NOW + 80, OWNER, "Approved authorization-policy command."
        ),
        AgentMessage(
            "msg-external-advisory", "channel-external-advisory", EXTERNAL_ADVISOR, AGENT_SECURITY,
            IDENTITY_DIGESTS[EXTERNAL_ADVISOR], "external-advisor", "external", "task-advisory", "goal-advisory", "step-advisory",
            None, None, MessageIntent.INFORMATION, "agent-message-v1", 2,
            (), sha("payload-advisory"), None, "nonce-advisory",
            NOW - 10, NOW + 60, OWNER, "Authenticated external information with no command authority."
        ),
    )


def build_fixture():
    channels = _channels()
    messages = _messages()
    manifest = AgentMessageManifest(
        GRAPH_ID, GRAPH_VERSION, P8A_DIGEST, P8C_DIGEST, P8F_DIGEST, NOW - 60, channels, messages
    )
    digest = agent_message_manifest_digest(manifest)
    policy = AgentMessagePolicy(
        expected_graph_id=GRAPH_ID,
        expected_graph_version=GRAPH_VERSION,
        expected_graph_sha256=digest,
        expected_p8a_assessment_evidence_sha256=P8A_DIGEST,
        expected_p8c_assessment_evidence_sha256=P8C_DIGEST,
        expected_p8f_assessment_evidence_sha256=P8F_DIGEST,
        required_channel_ids=frozenset(c.channel_id for c in channels),
        required_message_ids=frozenset(m.message_id for m in messages),
        trusted_owner_ids=frozenset({OWNER}),
        trusted_internal_agent_ids=INTERNAL_AGENTS,
        known_external_sender_ids=EXTERNAL_SENDERS,
        expected_sender_identity_sha256=IDENTITY_DIGESTS,
        expected_channel_profiles={
            c.channel_id: (
                c.channel_type, tuple(c.allowed_sender_ids), tuple(c.allowed_receiver_ids),
                tuple(c.allowed_intents), c.tenant_scope, c.required_schema_version,
                c.protocol_version, tuple(c.allowed_capability_ids), c.command_requires_approval,
                c.required_approval_action_id, c.max_message_age_seconds,
            )
            for c in channels
        },
    )
    ctx = {"manifest": manifest, "policy": policy, **make_upstreams()}
    ctx["request"] = truthful_request(ctx)
    return ctx


def truthful_request(ctx):
    facts = AgentMessageProtocolSecurityAnalyzer(ctx["policy"]).derive(
        ctx["manifest"], ctx["p8a"], ctx["p8c"], ctx["p8f"], NOW
    )
    return AgentMessageRequest(
        graph_id=GRAPH_ID,
        graph_version=GRAPH_VERSION,
        graph_sha256=ctx["policy"].expected_graph_sha256,
        p8a_assessment_evidence_sha256=P8A_DIGEST,
        p8c_assessment_evidence_sha256=P8C_DIGEST,
        p8f_assessment_evidence_sha256=P8F_DIGEST,
        evaluated_at_epoch=NOW,
        message_ids=tuple(sorted(m.message_id for m in ctx["manifest"].messages)),
        declared_denied_message_ids=tuple(sorted(f.message_id for f in facts if f.decision == MessageDecision.DENY)),
        declared_risks_by_message={f.message_id: f.risks for f in facts},
    )


def replace_item(manifest: AgentMessageManifest, collection: str, item_id: str, **changes):
    attr = {"channels": "channel_id", "messages": "message_id"}[collection]
    items = []
    found = False
    for item in getattr(manifest, collection):
        if getattr(item, attr) == item_id:
            items.append(replace(item, **changes))
            found = True
        else:
            items.append(item)
    if not found:
        raise KeyError(item_id)
    return replace(manifest, **{collection: tuple(items)})


def rebind(ctx, *, truthful=False):
    digest = agent_message_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    if truthful:
        ctx["request"] = truthful_request(ctx)
    return ctx


def clone_context():
    return dict(build_fixture())
