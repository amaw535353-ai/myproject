from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from types import SimpleNamespace

from aegis.agentic.tool_observation_security import (
    AgentToolObservationIntegrityAnalyzer,
    EnvironmentSnapshot,
    ObservationDecision,
    ObservationTrust,
    ToolContract,
    ToolEffect,
    ToolInvocation,
    ToolObservation,
    ToolObservationManifest,
    ToolObservationPolicy,
    ToolObservationRequest,
    ToolResult,
    tool_observation_manifest_digest,
)

NOW = 1_786_792_400
GRAPH_ID = "aegis-agent-tool-observation-graph"
GRAPH_VERSION = "1"
OWNER = "platform-security"
TENANT = "tenant-A"

P8A_DIGEST = hashlib.sha256(b"p8a-delegation-evidence-p8d").hexdigest()
P8C_DIGEST = hashlib.sha256(b"p8c-goal-plan-evidence-p8d").hexdigest()
P7I_DIGEST = hashlib.sha256(b"p7i-invariant-evidence-p8d").hexdigest()
ATTEST_SEARCH = hashlib.sha256(b"search-attestation").hexdigest()
ATTEST_TICKET = hashlib.sha256(b"ticket-attestation").hexdigest()
ATTEST_RELEASE = hashlib.sha256(b"release-attestation").hexdigest()
ATTEST_TELEMETRY = hashlib.sha256(b"telemetry-attestation").hexdigest()


def sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def ack(side_effect_id: str, payload_sha256: str, version: int) -> str:
    return hashlib.sha256(f"{side_effect_id}:{payload_sha256}:{version}".encode()).hexdigest()


@dataclass(frozen=True)
class UpstreamDecisionFact:
    decision: str
    delegation_id: str = ""
    step_id: str = ""


def make_upstreams(*, denied_delegations: frozenset[str] = frozenset(), denied_steps: frozenset[str] = frozenset(), unsafe_invariants: frozenset[str] = frozenset(), p8a_digest: str = P8A_DIGEST, p8c_digest: str = P8C_DIGEST, p7i_digest: str = P7I_DIGEST):
    delegations = tuple(
        UpstreamDecisionFact("deny" if did in denied_delegations else "allow", delegation_id=did)
        for did in ("delegation-retrieval", "delegation-tool-child", "delegation-release-deploy", "delegation-telemetry")
    )
    steps = tuple(
        UpstreamDecisionFact("deny" if sid in denied_steps else "allow", step_id=sid)
        for sid in ("step-search", "step-ticket", "step-release", "step-telemetry")
    )
    return {
        "p8a": SimpleNamespace(
            assessment_evidence_sha256=p8a_digest,
            exact_agent_delegation_graph_binding_verified=True,
            caller_declared_delegation_authorization_trusted=False,
            delegations=delegations,
        ),
        "p8c": SimpleNamespace(
            assessment_evidence_sha256=p8c_digest,
            exact_goal_plan_graph_binding_verified=True,
            caller_declared_goal_plan_safety_trusted=False,
            steps=steps,
        ),
        "p7i": SimpleNamespace(
            assessment_evidence_sha256=p7i_digest,
            exact_architecture_binding_verified=True,
            caller_declared_architecture_safety_trusted=False,
            unsafe_invariant_ids=tuple(sorted(unsafe_invariants)),
        ),
    }


def _manifest() -> ToolObservationManifest:
    contracts = (
        ToolContract("tool-search", OWNER, TENANT, ToolEffect.READ_ONLY, False, 120, False, ("INV-TOOL-TENANT-BOUNDARY",), "Tenant search tool"),
        ToolContract("tool-ticket", OWNER, TENANT, ToolEffect.MUTATING, True, 120, True, ("INV-TOOL-AUTHORIZATION",), "Tenant ticket mutation tool"),
        ToolContract("tool-release", OWNER, "shared", ToolEffect.IRREVERSIBLE, True, 90, True, ("INV-RELEASE-CONTROL-PLANE",), "Release deployment tool"),
        ToolContract("tool-telemetry", OWNER, "system", ToolEffect.MUTATING, True, 180, True, ("INV-ADMIN-NON-SELF-BYPASS",), "Security telemetry configuration tool"),
    )
    snapshots = (
        EnvironmentSnapshot("snap-tenant-v10", TENANT, 10, sha("tenant-state-v10"), NOW - 40, OWNER, "Tenant state before mutation"),
        EnvironmentSnapshot("snap-tenant-v11", TENANT, 11, sha("tenant-state-v11"), NOW - 12, OWNER, "Tenant state after ticket mutation"),
        EnvironmentSnapshot("snap-release-v42", "platform", 42, sha("release-state-v42"), NOW - 40, OWNER, "Release state before deployment"),
        EnvironmentSnapshot("snap-release-v43", "platform", 43, sha("release-state-v43"), NOW - 8, OWNER, "Release state after deployment"),
        EnvironmentSnapshot("snap-security-v7", "platform", 7, sha("security-state-v7"), NOW - 40, OWNER, "Security state before telemetry update"),
        EnvironmentSnapshot("snap-security-v8", "platform", 8, sha("security-state-v8"), NOW - 6, OWNER, "Security state after telemetry update"),
    )
    invocations = (
        ToolInvocation("invoke-search", "tool-search", "agent-retrieval-a", "user-a", TENANT, "task-search", "goal-search", "step-search", "delegation-retrieval", sha("args-search"), "snap-tenant-v10", NOW - 20, OWNER, "Search tenant knowledge"),
        ToolInvocation("invoke-ticket", "tool-ticket", "agent-tool-executor", "user-a", TENANT, "task-ticket", "goal-ticket", "step-ticket", "delegation-tool-child", sha("args-ticket"), "snap-tenant-v10", NOW - 18, OWNER, "Update tenant ticket"),
        ToolInvocation("invoke-release", "tool-release", "agent-release-executor", "release-admin", "platform", "task-release", "goal-release", "step-release", "delegation-release-deploy", sha("args-release"), "snap-release-v42", NOW - 16, OWNER, "Deploy approved release"),
        ToolInvocation("invoke-telemetry", "tool-telemetry", "agent-security-orchestrator", "security-admin", "platform", "task-telemetry", "goal-telemetry", "step-telemetry", "delegation-telemetry", sha("args-telemetry"), "snap-security-v7", NOW - 14, OWNER, "Update telemetry routing"),
    )
    payload_search = sha("payload-search")
    payload_ticket = sha("payload-ticket")
    payload_release = sha("payload-release")
    payload_telemetry = sha("payload-telemetry")
    results = (
        ToolResult("result-search", "invoke-search", "tool-search", sha("args-search"), payload_search, "nonce-search", "snap-tenant-v10", 10, sha("tenant-state-v10"), None, None, None, NOW - 19, NOW + 80, OWNER, "Search result"),
        ToolResult("result-ticket", "invoke-ticket", "tool-ticket", sha("args-ticket"), payload_ticket, "nonce-ticket", "snap-tenant-v10", 11, sha("tenant-state-v11"), "side-ticket-1", ack("side-ticket-1", payload_ticket, 11), ATTEST_TICKET, NOW - 13, NOW + 80, OWNER, "Ticket mutation result"),
        ToolResult("result-release", "invoke-release", "tool-release", sha("args-release"), payload_release, "nonce-release", "snap-release-v42", 43, sha("release-state-v43"), "side-release-1", ack("side-release-1", payload_release, 43), ATTEST_RELEASE, NOW - 9, NOW + 60, OWNER, "Release deployment result"),
        ToolResult("result-telemetry", "invoke-telemetry", "tool-telemetry", sha("args-telemetry"), payload_telemetry, "nonce-telemetry", "snap-security-v7", 8, sha("security-state-v8"), "side-telemetry-1", ack("side-telemetry-1", payload_telemetry, 8), ATTEST_TELEMETRY, NOW - 7, NOW + 120, OWNER, "Telemetry mutation result"),
    )
    observations = (
        ToolObservation("obs-search", "result-search", "invoke-search", "tool-search", "user-a", TENANT, "task-search", "goal-search", "step-search", "snap-tenant-v10", 10, sha("tenant-state-v10"), payload_search, ObservationTrust.TOOL_ASSERTED, OWNER, "Search observation"),
        ToolObservation("obs-ticket", "result-ticket", "invoke-ticket", "tool-ticket", "user-a", TENANT, "task-ticket", "goal-ticket", "step-ticket", "snap-tenant-v11", 11, sha("tenant-state-v11"), payload_ticket, ObservationTrust.VERIFIED, OWNER, "Ticket observation"),
        ToolObservation("obs-release", "result-release", "invoke-release", "tool-release", "release-admin", "platform", "task-release", "goal-release", "step-release", "snap-release-v43", 43, sha("release-state-v43"), payload_release, ObservationTrust.VERIFIED, OWNER, "Release observation"),
        ToolObservation("obs-telemetry", "result-telemetry", "invoke-telemetry", "tool-telemetry", "security-admin", "platform", "task-telemetry", "goal-telemetry", "step-telemetry", "snap-security-v8", 8, sha("security-state-v8"), payload_telemetry, ObservationTrust.VERIFIED, OWNER, "Telemetry observation"),
    )
    return ToolObservationManifest(GRAPH_ID, GRAPH_VERSION, P8A_DIGEST, P8C_DIGEST, P7I_DIGEST, NOW - 50, contracts, snapshots, invocations, results, observations)


def build_fixture():
    manifest = _manifest()
    digest = tool_observation_manifest_digest(manifest)
    policy = ToolObservationPolicy(
        expected_graph_id=GRAPH_ID,
        expected_graph_version=GRAPH_VERSION,
        expected_graph_sha256=digest,
        expected_p8a_assessment_evidence_sha256=P8A_DIGEST,
        expected_p8c_assessment_evidence_sha256=P8C_DIGEST,
        expected_p7i_assessment_evidence_sha256=P7I_DIGEST,
        required_contract_ids=frozenset(x.tool_id for x in manifest.contracts),
        required_snapshot_ids=frozenset(x.snapshot_id for x in manifest.snapshots),
        required_invocation_ids=frozenset(x.invocation_id for x in manifest.invocations),
        required_result_ids=frozenset(x.result_id for x in manifest.results),
        required_observation_ids=frozenset(x.observation_id for x in manifest.observations),
        trusted_owner_ids=frozenset({OWNER}),
        expected_contract_tenant_scope={x.tool_id: x.tenant_scope for x in manifest.contracts},
        expected_contract_effect={x.tool_id: x.effect for x in manifest.contracts},
        expected_contract_authoritative={x.tool_id: x.authoritative_result for x in manifest.contracts},
        expected_contract_max_age={x.tool_id: x.max_result_age_seconds for x in manifest.contracts},
        expected_contract_requires_ack={x.tool_id: x.requires_side_effect_ack for x in manifest.contracts},
        expected_contract_invariant_ids={x.tool_id: frozenset(x.required_p7i_invariant_ids) for x in manifest.contracts},
        expected_snapshot_tenant={x.snapshot_id: x.tenant_id for x in manifest.snapshots},
        expected_snapshot_state_version={x.snapshot_id: x.state_version for x in manifest.snapshots},
        expected_snapshot_state_sha256={x.snapshot_id: x.state_sha256 for x in manifest.snapshots},
        allowed_attestation_sha256=frozenset({ATTEST_TICKET, ATTEST_RELEASE, ATTEST_TELEMETRY}),
    )
    ctx = {"manifest": manifest, "policy": policy, **make_upstreams()}
    ctx["request"] = truthful_request_for_context(ctx)
    return ctx


def truthful_request_for_context(ctx):
    p = ctx["policy"]
    facts = AgentToolObservationIntegrityAnalyzer(p).derive(ctx["manifest"], ctx["p8a"], ctx["p8c"], ctx["p7i"], NOW)
    return ToolObservationRequest(
        graph_id=p.expected_graph_id,
        graph_version=p.expected_graph_version,
        graph_sha256=p.expected_graph_sha256,
        p8a_assessment_evidence_sha256=p.expected_p8a_assessment_evidence_sha256,
        p8c_assessment_evidence_sha256=p.expected_p8c_assessment_evidence_sha256,
        p7i_assessment_evidence_sha256=p.expected_p7i_assessment_evidence_sha256,
        evaluated_at_epoch=NOW,
        observation_ids=tuple(sorted(p.required_observation_ids)),
        declared_denied_observation_ids=tuple(sorted(f.observation_id for f in facts if f.decision == ObservationDecision.DENY)),
        declared_risks_by_observation={f.observation_id: f.risks for f in facts},
    )


def replace_manifest_item(manifest: ToolObservationManifest, collection: str, item_id: str, **changes):
    attr = {"contracts": "tool_id", "snapshots": "snapshot_id", "invocations": "invocation_id", "results": "result_id", "observations": "observation_id"}[collection]
    items = []
    for item in getattr(manifest, collection):
        items.append(replace(item, **changes) if getattr(item, attr) == item_id else item)
    return replace(manifest, **{collection: tuple(items)})


def rebind(ctx, *, truthful: bool = False):
    digest = tool_observation_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    if truthful:
        ctx["request"] = truthful_request_for_context(ctx)
    return ctx


def clone_context(ctx=None):
    src = ctx or build_fixture()
    return dict(src)


def truthful_unsafe_contexts():
    base = build_fixture()

    replay = clone_context(base)
    replay["manifest"] = replace_manifest_item(replay["manifest"], "results", "result-ticket", result_nonce="nonce-search")
    rebind(replay, truthful=True)

    stale = clone_context(base)
    stale["manifest"] = replace_manifest_item(stale["manifest"], "results", "result-search", expires_at_epoch=NOW - 1)
    rebind(stale, truthful=True)

    laundering = clone_context(base)
    laundering["manifest"] = replace_manifest_item(laundering["manifest"], "observations", "obs-search", claimed_trust=ObservationTrust.VERIFIED)
    rebind(laundering, truthful=True)

    side_effect = clone_context(base)
    side_effect["manifest"] = replace_manifest_item(side_effect["manifest"], "results", "result-ticket", side_effect_ack_sha256=None)
    rebind(side_effect, truthful=True)

    environment = clone_context(base)
    environment["manifest"] = replace_manifest_item(environment["manifest"], "observations", "obs-ticket", environment_state_sha256=sha("spoofed-env"))
    rebind(environment, truthful=True)

    upstream = clone_context(base)
    upstream.update(make_upstreams(denied_steps=frozenset({"step-ticket"})))
    upstream["request"] = truthful_request_for_context(upstream)

    return {
        "replay": replay,
        "stale": stale,
        "laundering": laundering,
        "side_effect": side_effect,
        "environment": environment,
        "upstream": upstream,
    }
