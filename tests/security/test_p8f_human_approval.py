from __future__ import annotations

from dataclasses import replace
import pytest

from aegis.agentic.human_approval_security import (
    ApprovalDecision,
    ApprovalOutcome,
    ApprovalRisk,
    AutonomyLevel,
    HumanApprovalSecurityRejected,
    HumanHandoffAutonomySecurityAnalyzer,
    human_approval_manifest_digest,
)
from evals.p8f_fixture import NOW, build_fixture, clone_context, rebind, replace_item, truthful_request
from evals.p8f_human_approval import CASES, EXPECTED_ADVERSARIAL_CASES, benign_contexts, hardened_attack_succeeds, run


def evaluate(ctx):
    return HumanHandoffAutonomySecurityAnalyzer(ctx["policy"]).evaluate(ctx["request"], ctx["manifest"], ctx["p8c"], ctx["p8d"], ctx["p8e"])


def test_clean_fixture_allows_all_actions():
    result = evaluate(build_fixture())
    assert result.action_count == 5
    assert result.allowed_action_count == 5
    assert result.denied_action_count == 0
    assert result.paused_action_count == 0
    assert result.approval_required_count == 4
    assert result.network_operations == 0


def test_release_requires_two_independent_approvers():
    ctx = clone_context()
    ctx["manifest"] = replace(ctx["manifest"], approvals=tuple(a for a in ctx["manifest"].approvals if a.approval_id != "approval-release-security"))
    required = set(ctx["policy"].required_approval_ids); required.remove("approval-release-security")
    ctx["policy"] = replace(ctx["policy"], required_approval_ids=frozenset(required))
    rebind(ctx); ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    fact = next(f for f in result.actions if f.action_id == "action-release")
    assert fact.outcome == ApprovalOutcome.PAUSE
    assert ApprovalRisk.INSUFFICIENT_APPROVER_COUNT in fact.risks


def test_self_approval_is_denied():
    ctx = clone_context()
    roles = dict(ctx["policy"].reviewer_roles_by_identity); groups = dict(ctx["policy"].reviewer_group_by_identity)
    roles["user-a"] = frozenset({"ops_approver"}); groups["user-a"] = "group-ops"
    ctx["policy"] = replace(ctx["policy"], reviewer_roles_by_identity=roles, reviewer_group_by_identity=groups)
    ctx["manifest"] = replace_item(ctx["manifest"], "approvals", "approval-ticket", reviewer_identity_id="user-a")
    rebind(ctx); ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    fact = next(f for f in result.actions if f.action_id == "action-ticket")
    assert fact.outcome == ApprovalOutcome.DENY
    assert ApprovalRisk.SELF_APPROVAL in fact.risks


def test_approval_replay_is_denied():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "approvals", "approval-ticket", approval_nonce="nonce-telemetry")
    rebind(ctx); ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    assert result.replay_or_stale_approval_denial_count >= 1


def test_plan_binding_prevents_approval_reuse_after_plan_change():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "approvals", "approval-ticket", bound_plan_sha256="f" * 64)
    rebind(ctx); ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    fact = next(f for f in result.actions if f.action_id == "action-ticket")
    assert ApprovalRisk.PLAN_BINDING_MISMATCH in fact.risks


def test_irreversible_action_cannot_disable_human_stop_by_repinning_policy():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "rules", "rule-release", requires_human=False, minimum_approver_count=0, requires_independent_approvers=False)
    profiles = dict(ctx["policy"].expected_rule_profiles)
    r = next(x for x in ctx["manifest"].rules if x.rule_id == "rule-release")
    profiles[r.rule_id] = (r.action_class, r.risk, r.maximum_autonomy, r.requires_human, tuple(r.required_reviewer_roles), r.minimum_approver_count, r.requires_independent_approvers, r.allow_edit, r.max_approval_age_seconds)
    ctx["policy"] = replace(ctx["policy"], expected_rule_profiles=profiles)
    rebind(ctx); ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    fact = next(f for f in result.actions if f.action_id == "action-release")
    assert ApprovalRisk.HUMAN_STOP_BYPASS in fact.risks
    assert fact.outcome == ApprovalOutcome.DENY


def test_autonomy_level_non_amplification():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "actions", "action-ticket", requested_autonomy=AutonomyLevel.UNSUPERVISED)
    bindings = dict(ctx["policy"].expected_action_bindings)
    a = next(x for x in ctx["manifest"].actions if x.action_id == "action-ticket")
    bindings[a.action_id] = (a.run_id, a.goal_id, a.step_id, a.delegation_id, a.original_principal_id, a.tenant_id, a.actor_agent_id, a.action_class, a.requested_autonomy, a.requester_identity_id, a.irreversible)
    ctx["policy"] = replace(ctx["policy"], expected_action_bindings=bindings)
    rebind(ctx); ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    fact = next(f for f in result.actions if f.action_id == "action-ticket")
    assert ApprovalRisk.AUTONOMY_LEVEL_EXCEEDED in fact.risks


def test_truthful_pause_and_reject_are_accepted_evidence_states():
    contexts = benign_contexts()
    assert evaluate(contexts[1][1]).paused_action_count == 1
    assert evaluate(contexts[2][1]).denied_action_count == 1


def test_all_adversarial_cases_fail_closed():
    assert len(CASES) == EXPECTED_ADVERSARIAL_CASES == 92
    failures = [case_id for case_id, mutation in CASES if hardened_attack_succeeds(mutation(clone_context()))]
    assert failures == []


def test_evaluator_metrics_and_hashes_are_stable():
    result = run()
    assert result["vulnerable_asr"] == "92/92"
    assert result["hardened_asr"] == "0/92"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
    assert len(result["graph_sha256"]) == len(result["dataset_sha256"]) == len(result["fixture_sha256"]) == len(result["clean_assessment_sha256"]) == 64


def test_graph_digest_is_deterministic():
    ctx = build_fixture()
    assert human_approval_manifest_digest(ctx["manifest"]) == ctx["request"].graph_sha256


def test_expired_approval_is_evidence_derived_not_caller_overridable():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "approvals", "approval-ticket", expires_at_epoch=NOW - 1)
    rebind(ctx)
    with pytest.raises(HumanApprovalSecurityRejected):
        evaluate(ctx)


def test_edit_requires_explicit_rule_support_and_new_argument_digest():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "approvals", "approval-ticket", decision=ApprovalDecision.EDIT, edited_args_sha256="e" * 64)
    rebind(ctx); ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    fact = next(f for f in result.actions if f.action_id == "action-ticket")
    assert fact.outcome == ApprovalOutcome.ALLOW


def test_claim_boundary_flags_are_explicit():
    result = evaluate(build_fixture())
    assert result.caller_declared_approval_safety_trusted is False
    assert result.production_human_identity_attestation is False
    assert result.production_approval_workflow_enforcement is False
    assert result.production_pam_or_iam_integration is False
    assert result.cryptographic_human_signature_verification is False
    assert result.legal_consent_or_compliance_certification is False
