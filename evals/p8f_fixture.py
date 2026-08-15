from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace

from aegis.agentic.human_approval_security import (
    ActionRisk,
    ApprovalDecision,
    ApprovalOutcome,
    AutonomyLevel,
    HumanApprovalManifest,
    HumanApprovalPolicy,
    HumanApprovalRecord,
    HumanApprovalRequest,
    HumanApprovalRule,
    HumanHandoffAutonomySecurityAnalyzer,
    PendingHumanAction,
    human_approval_manifest_digest,
)

NOW = 1_786_794_600
GRAPH_ID = "aegis-human-approval-autonomy-graph"
GRAPH_VERSION = "1"
OWNER = "platform-security"
P8C_DIGEST = hashlib.sha256(b"p8c-human-approval").hexdigest()
P8D_DIGEST = hashlib.sha256(b"p8d-human-approval").hexdigest()
P8E_DIGEST = hashlib.sha256(b"p8e-human-approval").hexdigest()


def sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


RULE_IDS = ("rule-search", "rule-ticket", "rule-release", "rule-telemetry", "rule-policy")
ACTION_IDS = ("action-search", "action-ticket", "action-release", "action-telemetry", "action-policy")
APPROVAL_IDS = ("approval-ticket", "approval-release-ops", "approval-release-security", "approval-telemetry", "approval-policy")


def make_upstreams(*, denied_steps=frozenset(), denied_observations=frozenset(), denied_runs=frozenset(), p8c_digest=P8C_DIGEST, p8d_digest=P8D_DIGEST, p8e_digest=P8E_DIGEST, verified=True):
    steps = tuple(SimpleNamespace(step_id=sid, goal_id=gid, decision="deny" if sid in denied_steps else "allow") for sid, gid in (
        ("step-search", "goal-search"), ("step-ticket", "goal-ticket"), ("step-release", "goal-release"), ("step-telemetry", "goal-telemetry"), ("step-policy", "goal-policy")
    ))
    observations = tuple(SimpleNamespace(observation_id=oid, step_id=sid, decision="deny" if oid in denied_observations else "allow") for oid, sid in (
        ("obs-search", "step-search"), ("obs-ticket", "step-ticket"), ("obs-release", "step-release"), ("obs-telemetry", "step-telemetry"), ("obs-policy", "step-policy")
    ))
    runs = tuple(SimpleNamespace(run_id=rid, decision="deny" if rid in denied_runs else "allow") for rid in ("run-search", "run-ticket", "run-release", "run-telemetry", "run-policy"))
    return {
        "p8c": SimpleNamespace(assessment_evidence_sha256=p8c_digest, exact_goal_plan_graph_binding_verified=verified, caller_declared_goal_safety_trusted=False, steps=steps),
        "p8d": SimpleNamespace(assessment_evidence_sha256=p8d_digest, exact_tool_observation_graph_binding_verified=verified, caller_declared_tool_observation_safety_trusted=False, observations=observations),
        "p8e": SimpleNamespace(assessment_evidence_sha256=p8e_digest, exact_execution_budget_graph_binding_verified=verified, caller_declared_resource_safety_trusted=False, runs=runs),
    }


def _manifest() -> HumanApprovalManifest:
    rules = (
        HumanApprovalRule("rule-search", "search", ActionRisk.LOW, AutonomyLevel.UNSUPERVISED, False, ("observer",), 0, False, False, 600, "Low-risk search can proceed without a human."),
        HumanApprovalRule("rule-ticket", "ticket_update", ActionRisk.SENSITIVE, AutonomyLevel.CONDITIONAL, True, ("ops_approver",), 1, False, True, 600, "Ticket mutation requires one operations reviewer."),
        HumanApprovalRule("rule-release", "release_deploy", ActionRisk.IRREVERSIBLE, AutonomyLevel.SUPERVISED, True, ("release_approver", "security_approver"), 2, True, False, 300, "Release deployment requires two independent reviewers."),
        HumanApprovalRule("rule-telemetry", "telemetry_change", ActionRisk.HIGH, AutonomyLevel.SUPERVISED, True, ("security_approver",), 1, False, False, 300, "Telemetry change requires security review."),
        HumanApprovalRule("rule-policy", "policy_change", ActionRisk.HIGH, AutonomyLevel.SUPERVISED, True, ("security_approver",), 1, False, True, 300, "Authorization-policy change requires security review."),
    )
    actions = (
        PendingHumanAction("action-search", "run-search", "goal-search", "step-search", "delegation-retrieval", "user-a", "tenant-A", "agent-retrieval", "search", sha("args-search"), sha("plan-search"), AutonomyLevel.UNSUPERVISED, "user-a", False, NOW - 60, OWNER, "Read-only tenant search."),
        PendingHumanAction("action-ticket", "run-ticket", "goal-ticket", "step-ticket", "delegation-tool-child", "user-a", "tenant-A", "agent-tool", "ticket_update", sha("args-ticket"), sha("plan-ticket"), AutonomyLevel.CONDITIONAL, "user-a", False, NOW - 50, OWNER, "Mutate tenant ticket."),
        PendingHumanAction("action-release", "run-release", "goal-release", "step-release", "delegation-release", "release-admin", "platform", "agent-release", "release_deploy", sha("args-release"), sha("plan-release"), AutonomyLevel.SUPERVISED, "release-admin", True, NOW - 45, OWNER, "Deploy approved model release."),
        PendingHumanAction("action-telemetry", "run-telemetry", "goal-telemetry", "step-telemetry", "delegation-security", "security-admin", "platform", "agent-security", "telemetry_change", sha("args-telemetry"), sha("plan-telemetry"), AutonomyLevel.SUPERVISED, "security-admin", False, NOW - 40, OWNER, "Modify security telemetry routing."),
        PendingHumanAction("action-policy", "run-policy", "goal-policy", "step-policy", "delegation-security", "security-admin", "platform", "agent-policy", "policy_change", sha("args-policy"), sha("plan-policy"), AutonomyLevel.SUPERVISED, "security-admin", False, NOW - 35, OWNER, "Modify authorization policy."),
    )
    approvals = (
        HumanApprovalRecord("approval-ticket", "action-ticket", "reviewer-ops", "ops_approver", "group-ops", ApprovalDecision.APPROVE, sha("args-ticket"), sha("plan-ticket"), None, "nonce-ticket", NOW - 30, NOW + 300, OWNER, "Approve ticket update."),
        HumanApprovalRecord("approval-release-ops", "action-release", "reviewer-release", "release_approver", "group-release", ApprovalDecision.APPROVE, sha("args-release"), sha("plan-release"), None, "nonce-release-ops", NOW - 25, NOW + 240, OWNER, "Release-operations approval."),
        HumanApprovalRecord("approval-release-security", "action-release", "reviewer-security", "security_approver", "group-security", ApprovalDecision.APPROVE, sha("args-release"), sha("plan-release"), None, "nonce-release-security", NOW - 20, NOW + 240, OWNER, "Independent security approval."),
        HumanApprovalRecord("approval-telemetry", "action-telemetry", "reviewer-security", "security_approver", "group-security", ApprovalDecision.APPROVE, sha("args-telemetry"), sha("plan-telemetry"), None, "nonce-telemetry", NOW - 18, NOW + 240, OWNER, "Approve telemetry change."),
        HumanApprovalRecord("approval-policy", "action-policy", "reviewer-security-2", "security_approver", "group-security-2", ApprovalDecision.APPROVE, sha("args-policy"), sha("plan-policy"), None, "nonce-policy", NOW - 16, NOW + 240, OWNER, "Approve policy change."),
    )
    return HumanApprovalManifest(GRAPH_ID, GRAPH_VERSION, P8C_DIGEST, P8D_DIGEST, P8E_DIGEST, NOW - 90, rules, actions, approvals)


def build_fixture():
    manifest = _manifest()
    graph_sha = human_approval_manifest_digest(manifest)
    policy = HumanApprovalPolicy(
        expected_graph_id=GRAPH_ID,
        expected_graph_version=GRAPH_VERSION,
        expected_graph_sha256=graph_sha,
        expected_p8c_assessment_evidence_sha256=P8C_DIGEST,
        expected_p8d_assessment_evidence_sha256=P8D_DIGEST,
        expected_p8e_assessment_evidence_sha256=P8E_DIGEST,
        required_rule_ids=frozenset(r.rule_id for r in manifest.rules),
        required_action_ids=frozenset(a.action_id for a in manifest.actions),
        required_approval_ids=frozenset(a.approval_id for a in manifest.approvals),
        trusted_owner_ids=frozenset({OWNER}),
        reviewer_roles_by_identity={
            "reviewer-ops": frozenset({"ops_approver"}),
            "reviewer-release": frozenset({"release_approver"}),
            "reviewer-security": frozenset({"security_approver"}),
            "reviewer-security-2": frozenset({"security_approver"}),
        },
        reviewer_group_by_identity={
            "reviewer-ops": "group-ops",
            "reviewer-release": "group-release",
            "reviewer-security": "group-security",
            "reviewer-security-2": "group-security-2",
        },
        expected_rule_profiles={r.rule_id: (r.action_class, r.risk, r.maximum_autonomy, r.requires_human, tuple(r.required_reviewer_roles), r.minimum_approver_count, r.requires_independent_approvers, r.allow_edit, r.max_approval_age_seconds) for r in manifest.rules},
        expected_action_bindings={a.action_id: (a.run_id, a.goal_id, a.step_id, a.delegation_id, a.original_principal_id, a.tenant_id, a.actor_agent_id, a.action_class, a.requested_autonomy, a.requester_identity_id, a.irreversible) for a in manifest.actions},
    )
    ctx = {"manifest": manifest, "policy": policy, **make_upstreams()}
    ctx["request"] = truthful_request(ctx)
    return ctx


def truthful_request(ctx) -> HumanApprovalRequest:
    facts = HumanHandoffAutonomySecurityAnalyzer(ctx["policy"]).derive(ctx["manifest"], ctx["p8c"], ctx["p8d"], ctx["p8e"], NOW)
    return HumanApprovalRequest(
        graph_id=GRAPH_ID,
        graph_version=GRAPH_VERSION,
        graph_sha256=ctx["policy"].expected_graph_sha256,
        p8c_assessment_evidence_sha256=P8C_DIGEST,
        p8d_assessment_evidence_sha256=P8D_DIGEST,
        p8e_assessment_evidence_sha256=P8E_DIGEST,
        evaluated_at_epoch=NOW,
        action_ids=tuple(sorted(a.action_id for a in ctx["manifest"].actions)),
        declared_allowed_action_ids=tuple(sorted(f.action_id for f in facts if f.outcome == ApprovalOutcome.ALLOW)),
        declared_denied_action_ids=tuple(sorted(f.action_id for f in facts if f.outcome == ApprovalOutcome.DENY)),
        declared_paused_action_ids=tuple(sorted(f.action_id for f in facts if f.outcome == ApprovalOutcome.PAUSE)),
        declared_risks_by_action={f.action_id: f.risks for f in facts},
    )


def replace_item(manifest: HumanApprovalManifest, collection: str, item_id: str, **changes):
    attr = {"rules": "rule_id", "actions": "action_id", "approvals": "approval_id"}[collection]
    values = []
    found = False
    for item in getattr(manifest, collection):
        if getattr(item, attr) == item_id:
            values.append(replace(item, **changes)); found = True
        else:
            values.append(item)
    if not found:
        raise KeyError(item_id)
    return replace(manifest, **{collection: tuple(values)})


def rebind(ctx, *, truthful=False):
    digest = human_approval_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    if truthful:
        ctx["request"] = truthful_request(ctx)
    return ctx


def clone_context():
    return dict(build_fixture())
