from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.architecture.control_plane_security import (
    AdministrativeOperation,
    ControlPlaneRejectReason,
    ControlPlaneRejected,
    SecurityControlPlaneChangeAnalyzer,
    control_plane_manifest_digest,
)
from evals.p7h_control_plane import ADVERSARIAL_CASES, run
from evals.p7h_fixture import (
    ALL_CONTROLS,
    CTRL_CHANGE_APPROVAL,
    NOW,
    REQ_CONTROL_CHANGE,
    build_fixture,
    make_upstreams,
    replace_manifest_item,
)


def evaluate(ctx):
    return SecurityControlPlaneChangeAnalyzer(ctx["policy"]).evaluate(
        ctx["request"], ctx["manifest"], ctx["p7b"], ctx["p7e"], ctx["p7f"], ctx["p7g"], ctx["posture"]
    )


def test_baseline_is_fully_controlled():
    result = evaluate(build_fixture())
    assert result.route_count == 8
    assert result.exposed_route_count == 0
    assert result.controlled_route_count == 8
    assert result.break_glass_route_count == 1
    assert result.max_exposed_risk_score == 0
    assert result.network_operations == 0
    assert result.caller_admin_approval_trusted is False


def test_manifest_digest_is_deterministic():
    ctx = build_fixture()
    assert control_plane_manifest_digest(ctx["manifest"]) == ctx["request"].control_plane_sha256
    assert ctx["request"].control_plane_sha256 == "c7a3e96a0227eabe57ae56326047d583af46e95decf49a8d8a958cd3e76f9525"


def test_all_adversarial_cases_fail_closed():
    from evals.p7h_control_plane import _clone, _evaluate_hardened
    failures = []
    for case_id, mutation in ADVERSARIAL_CASES:
        if _evaluate_hardened(mutation(_clone())):
            failures.append(case_id)
    assert failures == []


def test_evaluator_metrics_are_exact():
    result = run()
    assert result["adversarial_cases"] == 92
    assert result["vulnerable_asr"] == "92/92"
    assert result["hardened_asr"] == "0/92"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
    assert result["dataset_sha256"] == "96a007b13658518dfe5d0b507114b71111300ecef30bbdabf8d91493daac177d"
    assert result["fixture_sha256"] == "b0c8732204c57e29f517ac69fa55e9168d999d8b8a96897a30f1165f200a82f0"


def test_exposed_admin_path_is_derived_not_trusted():
    ctx = build_fixture()
    upstreams = make_upstreams(exposed_p7b_paths=frozenset({"p7b-admin-release"}))
    for key in ("p7b", "p7e", "p7f", "p7g", "posture"):
        ctx[key] = upstreams[key]
    ctx["request"] = replace(ctx["request"], declared_exposed_route_ids=("route-release-promote",), declared_max_exposed_risk_score=113)
    result = evaluate(ctx)
    fact = next(item for item in result.routes if item.route_id == "route-release-promote")
    assert fact.exposed is True
    assert fact.exposure_reasons == ("admin_privilege_path_exposed",)
    assert fact.risk_score == 113


def test_telemetry_blind_spot_exposes_all_change_paths():
    ctx = build_fixture()
    upstreams = make_upstreams(blind_spot_requirements=frozenset({REQ_CONTROL_CHANGE}))
    for key in ("p7b", "p7e", "p7f", "p7g", "posture"):
        ctx[key] = upstreams[key]
    ctx["request"] = replace(ctx["request"], declared_exposed_route_ids=tuple(sorted(ctx["request"].route_ids)), declared_max_exposed_risk_score=111)
    result = evaluate(ctx)
    assert result.exposed_route_count == 8
    assert result.critical_resource_exposed_route_count == 7
    assert result.max_exposed_risk_score == 111


def test_exceptioned_change_approval_control_is_visible():
    ctx = build_fixture()
    statuses = {control_id: "satisfied" for control_id in ALL_CONTROLS}
    statuses[CTRL_CHANGE_APPROVAL] = "exceptioned"
    upstreams = make_upstreams(statuses=statuses)
    for key in ("p7b", "p7e", "p7f", "p7g", "posture"):
        ctx[key] = upstreams[key]
    ctx["request"] = replace(ctx["request"], declared_exposed_route_ids=tuple(sorted(ctx["request"].route_ids)), declared_max_exposed_risk_score=103)
    result = evaluate(ctx)
    assert result.exposed_route_count == 8
    assert all(CTRL_CHANGE_APPROVAL in item.exceptioned_control_ids for item in result.routes)


def test_policy_rejects_self_approval_configuration():
    ctx = build_fixture()
    policy = ctx["policy"]
    approvals = dict(policy.expected_approval_principal_ids)
    approvals["route-authz-update"] = frozenset({"admin-authz", "approver-security"})
    policy = replace(policy, expected_approval_principal_ids=approvals, trusted_approver_ids=policy.trusted_approver_ids | {"admin-authz"})
    with pytest.raises(ControlPlaneRejected) as exc:
        SecurityControlPlaneChangeAnalyzer(policy)
    assert exc.value.reason == ControlPlaneRejectReason.POLICY_INVALID


def test_route_missing_ticket_rejected():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "routes", "route-egress-update", change_ticket_id="")
    with pytest.raises(ControlPlaneRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason in {ControlPlaneRejectReason.MANIFEST_DIGEST_MISMATCH, ControlPlaneRejectReason.ROUTE_TICKET_INVALID}


def test_breakglass_requires_emergency_reason():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "routes", "route-trust-breakglass", emergency_reason=None)
    with pytest.raises(ControlPlaneRejected):
        evaluate(ctx)


def test_stale_route_verification_rejected():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "routes", "route-egress-update", verified_at_epoch=NOW - 10000)
    with pytest.raises(ControlPlaneRejected):
        evaluate(ctx)


def test_coherent_self_authorization_mutation_is_exposed():
    ctx = build_fixture()
    resource_id = "resource-authorization-policy"
    bindings = ("p7b:p7b-admin-authz",)
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "resources", resource_id, upstream_binding_ids=bindings)
    policy = ctx["policy"]
    mapping = dict(policy.expected_resource_upstream_binding_ids)
    mapping[resource_id] = frozenset(bindings)
    manifest_sha = control_plane_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(policy, expected_resource_upstream_binding_ids=mapping, expected_control_plane_sha256=manifest_sha)
    ctx["request"] = replace(ctx["request"], control_plane_sha256=manifest_sha, declared_exposed_route_ids=("route-authz-update",), declared_max_exposed_risk_score=117)
    result = evaluate(ctx)
    fact = next(item for item in result.routes if item.route_id == "route-authz-update")
    assert fact.self_authorization_mutation is True
    assert "self_authorization_mutation" in fact.exposure_reasons


def test_coherent_self_audit_mutation_is_exposed():
    ctx = build_fixture()
    resource_id = "resource-telemetry-configuration"
    bindings = (f"p7g:{REQ_CONTROL_CHANGE}", "p7g:req-failover")
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "resources", resource_id, upstream_binding_ids=bindings)
    policy = ctx["policy"]
    mapping = dict(policy.expected_resource_upstream_binding_ids)
    mapping[resource_id] = frozenset(bindings)
    manifest_sha = control_plane_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(policy, expected_resource_upstream_binding_ids=mapping, expected_control_plane_sha256=manifest_sha)
    ctx["request"] = replace(ctx["request"], control_plane_sha256=manifest_sha, declared_exposed_route_ids=("route-telemetry-update",), declared_max_exposed_risk_score=120)
    result = evaluate(ctx)
    fact = next(item for item in result.routes if item.route_id == "route-telemetry-update")
    assert fact.self_audit_mutation is True
    assert "self_audit_mutation" in fact.exposure_reasons


def test_coherent_critical_delete_is_exposed():
    ctx = build_fixture()
    route_id = "route-egress-update"
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "routes", route_id, operation=AdministrativeOperation.DELETE)
    policy = ctx["policy"]
    operations = dict(policy.expected_route_operation)
    operations[route_id] = AdministrativeOperation.DELETE
    manifest_sha = control_plane_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(policy, expected_route_operation=operations, expected_control_plane_sha256=manifest_sha)
    ctx["request"] = replace(ctx["request"], control_plane_sha256=manifest_sha, declared_exposed_route_ids=(route_id,), declared_max_exposed_risk_score=115)
    result = evaluate(ctx)
    fact = next(item for item in result.routes if item.route_id == route_id)
    assert "critical_destructive_operation" in fact.exposure_reasons
    assert fact.risk_score == 115
