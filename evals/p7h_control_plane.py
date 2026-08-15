from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Callable

from aegis.architecture.control_plane_security import (
    AdministrativeOperation,
    AdministrativePrincipalType,
    ControlPlaneManifest,
    ControlPlaneRejected,
    ControlPlaneResourceType,
    ControlPlaneSensitivity,
    SecurityControlPlaneChangeAnalyzer,
    control_plane_manifest_digest,
)
from evals.p7h_fixture import (
    ALL_CONTROLS,
    CATALOG_SHA,
    CTRL_CHANGE_APPROVAL,
    NOW,
    P7B_SHA,
    P7E_SHA,
    P7F_SHA,
    P7G_SHA,
    POSTURE_SHA,
    REQ_CONTROL_CHANGE,
    build_fixture,
    make_upstreams,
    replace_manifest_item,
)
from aegis.vulnerable.control_plane_security import VulnerableAdminApprovedChangeReporter

Mutation = Callable[[dict[str, object]], dict[str, object]]


def _clone() -> dict[str, object]:
    return dict(build_fixture())


def _manifest(ctx: dict[str, object]) -> ControlPlaneManifest:
    return ctx["manifest"]  # type: ignore[return-value]


def _with_manifest(ctx: dict[str, object], manifest: ControlPlaneManifest) -> dict[str, object]:
    ctx["manifest"] = manifest
    return ctx


def _mut_request(field: str, value: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["request"] = replace(ctx["request"], **{field: value})
        return ctx
    return mutate


def _mut_manifest(field: str, value: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        return _with_manifest(ctx, replace(_manifest(ctx), **{field: value}))
    return mutate


def _mut_principal(principal_id: str, **changes: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        return _with_manifest(ctx, replace_manifest_item(_manifest(ctx), "principals", principal_id, **changes))
    return mutate


def _mut_resource(resource_id: str, **changes: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        return _with_manifest(ctx, replace_manifest_item(_manifest(ctx), "resources", resource_id, **changes))
    return mutate


def _mut_route(route_id: str, **changes: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        return _with_manifest(ctx, replace_manifest_item(_manifest(ctx), "routes", route_id, **changes))
    return mutate


def _drop(collection: str, key: str, item_id: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        manifest = _manifest(ctx)
        values = tuple(item for item in getattr(manifest, collection) if getattr(item, key) != item_id)
        return _with_manifest(ctx, replace(manifest, **{collection: values}))
    return mutate


def _duplicate(collection: str, key: str, item_id: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        manifest = _manifest(ctx)
        values = list(getattr(manifest, collection))
        item = next(item for item in values if getattr(item, key) == item_id)
        values.append(item)
        return _with_manifest(ctx, replace(manifest, **{collection: tuple(values)}))
    return mutate


def _upstream_mut(name: str, **changes: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx[name] = SimpleNamespace(**{**vars(ctx[name]), **changes})
        return ctx
    return mutate


def _posture_duplicate_control(ctx: dict[str, object]) -> dict[str, object]:
    posture = ctx["posture"]
    assessments = tuple(getattr(posture, "assessments"))
    ctx["posture"] = SimpleNamespace(**{**vars(posture), "assessments": assessments + (assessments[0],)})
    return ctx


def _posture_bad_summary(ctx: dict[str, object]) -> dict[str, object]:
    posture = ctx["posture"]
    ctx["posture"] = SimpleNamespace(**{**vars(posture), "satisfied_control_ids": tuple()})
    return ctx


def _coherent_resource_binding(resource_id: str, new_bindings: tuple[str, ...]) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        manifest = replace_manifest_item(_manifest(ctx), "resources", resource_id, upstream_binding_ids=new_bindings)
        policy = ctx["policy"]
        mapping = dict(policy.expected_resource_upstream_binding_ids)
        mapping[resource_id] = frozenset(new_bindings)
        policy = replace(policy, expected_resource_upstream_binding_ids=mapping)
        manifest_sha = control_plane_manifest_digest(manifest)
        policy = replace(policy, expected_control_plane_sha256=manifest_sha)
        request = replace(ctx["request"], control_plane_sha256=manifest_sha)
        ctx.update(manifest=manifest, policy=policy, request=request)
        return ctx
    return mutate


def _coherent_route_operation(route_id: str, operation: AdministrativeOperation) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        manifest = replace_manifest_item(_manifest(ctx), "routes", route_id, operation=operation)
        policy = ctx["policy"]
        mapping = dict(policy.expected_route_operation)
        mapping[route_id] = operation
        policy = replace(policy, expected_route_operation=mapping)
        manifest_sha = control_plane_manifest_digest(manifest)
        policy = replace(policy, expected_control_plane_sha256=manifest_sha)
        request = replace(ctx["request"], control_plane_sha256=manifest_sha)
        ctx.update(manifest=manifest, policy=policy, request=request)
        return ctx
    return mutate


def _exposed_p7b(path_id: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        upstreams = make_upstreams(exposed_p7b_paths=frozenset({path_id}))
        for key in ("p7b", "p7e", "p7f", "p7g", "posture"):
            ctx[key] = upstreams[key]
        return ctx
    return mutate


def _exposed_p7e(path_id: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        upstreams = make_upstreams(exposed_p7e_paths=frozenset({path_id}))
        for key in ("p7b", "p7e", "p7f", "p7g", "posture"):
            ctx[key] = upstreams[key]
        return ctx
    return mutate


def _exposed_p7f(scenario_id: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        upstreams = make_upstreams(exposed_p7f_scenarios=frozenset({scenario_id}))
        for key in ("p7b", "p7e", "p7f", "p7g", "posture"):
            ctx[key] = upstreams[key]
        return ctx
    return mutate


def _blind_telemetry(requirement_id: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        upstreams = make_upstreams(blind_spot_requirements=frozenset({requirement_id}))
        for key in ("p7b", "p7e", "p7f", "p7g", "posture"):
            ctx[key] = upstreams[key]
        return ctx
    return mutate


def _control_status(control_id: str, status: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        statuses = {value: "satisfied" for value in ALL_CONTROLS}
        statuses[control_id] = status
        upstreams = make_upstreams(statuses=statuses)
        for key in ("p7b", "p7e", "p7f", "p7g", "posture"):
            ctx[key] = upstreams[key]
        return ctx
    return mutate


def _bad_policy_self_approval(ctx: dict[str, object]) -> dict[str, object]:
    policy = ctx["policy"]
    mapping = dict(policy.expected_approval_principal_ids)
    mapping["route-authz-update"] = frozenset({"admin-authz", "approver-security"})
    ctx["policy"] = replace(policy, expected_approval_principal_ids=mapping, trusted_approver_ids=policy.trusted_approver_ids | {"admin-authz"})
    return ctx


ADVERSARIAL_CASES: tuple[tuple[str, Mutation], ...] = (
    ("request-control-plane-id-substitution", _mut_request("control_plane_id", "evil-plane")),
    ("request-version-substitution", _mut_request("control_plane_version", "evil-version")),
    ("request-manifest-digest-substitution", _mut_request("control_plane_sha256", "1" * 64)),
    ("request-p7b-digest-substitution", _mut_request("p7b_assessment_evidence_sha256", "2" * 64)),
    ("request-p7e-digest-substitution", _mut_request("p7e_assessment_evidence_sha256", "3" * 64)),
    ("request-p7f-digest-substitution", _mut_request("p7f_assessment_evidence_sha256", "4" * 64)),
    ("request-p7g-digest-substitution", _mut_request("p7g_assessment_evidence_sha256", "5" * 64)),
    ("request-posture-digest-substitution", _mut_request("posture_evidence_sha256", "6" * 64)),
    ("request-route-omission", _mut_request("route_ids", tuple(sorted(set(build_fixture()["request"].route_ids) - {"route-authz-update"})))),
    ("request-route-duplicate", _mut_request("route_ids", build_fixture()["request"].route_ids + ("route-authz-update",))),
    ("manifest-schema-substitution", _mut_manifest("schema_version", "evil-schema")),
    ("manifest-id-substitution", _mut_manifest("control_plane_id", "evil-plane")),
    ("manifest-version-substitution", _mut_manifest("version", "evil-version")),
    ("manifest-p7b-digest-substitution", _mut_manifest("p7b_assessment_evidence_sha256", "7" * 64)),
    ("manifest-p7e-digest-substitution", _mut_manifest("p7e_assessment_evidence_sha256", "8" * 64)),
    ("manifest-p7f-digest-substitution", _mut_manifest("p7f_assessment_evidence_sha256", "9" * 64)),
    ("manifest-p7g-digest-substitution", _mut_manifest("p7g_assessment_evidence_sha256", "a" * 64)),
    ("manifest-posture-digest-substitution", _mut_manifest("posture_evidence_sha256", "b" * 64)),
    ("manifest-stale", _mut_manifest("created_at_epoch", NOW - 90_000)),
    ("manifest-future", _mut_manifest("created_at_epoch", NOW + 100)),
    ("manifest-description-repin-attack", _mut_resource("resource-egress-policy", description="tampered description")),
    ("principal-omission", _drop("principals", "principal_id", "admin-authz")),
    ("principal-duplicate", _duplicate("principals", "principal_id", "admin-authz")),
    ("principal-owner-untrusted", _mut_principal("admin-authz", owner_id="attacker")),
    ("principal-type-drift", _mut_principal("admin-authz", principal_type=AdministrativePrincipalType.HUMAN_ADMIN)),
    ("principal-path-drift", _mut_principal("admin-authz", p7b_path_ids=("p7b-admin-release",))),
    ("principal-path-unknown", _mut_principal("admin-authz", p7b_path_ids=("unknown-path",))),
    ("principal-breakglass-drift", _mut_principal("admin-authz", break_glass_capable=True)),
    ("resource-omission", _drop("resources", "resource_id", "resource-egress-policy")),
    ("resource-duplicate", _duplicate("resources", "resource_id", "resource-egress-policy")),
    ("resource-owner-untrusted", _mut_resource("resource-egress-policy", owner_id="attacker")),
    ("resource-type-drift", _mut_resource("resource-egress-policy", resource_type=ControlPlaneResourceType.TRUST_STORE)),
    ("resource-sensitivity-downgrade", _mut_resource("resource-egress-policy", sensitivity=ControlPlaneSensitivity.LOW)),
    ("resource-binding-drift", _mut_resource("resource-egress-policy", upstream_binding_ids=("p7e:p7e-path-model-egress",))),
    ("resource-binding-unknown", _mut_resource("resource-egress-policy", upstream_binding_ids=("p7e:unknown", "p7e:p7e-path-tool-egress"))),
    ("resource-control-drift", _mut_resource("resource-egress-policy", required_control_ids=("CTRL-ADMIN-AUTHZ",))),
    ("resource-control-unknown", _mut_resource("resource-egress-policy", required_control_ids=("CTRL-UNKNOWN",))),
    ("resource-telemetry-drift", _mut_resource("resource-egress-policy", required_telemetry_requirement_ids=(REQ_CONTROL_CHANGE,))),
    ("resource-telemetry-unknown", _mut_resource("resource-egress-policy", required_telemetry_requirement_ids=("req-unknown",))),
    ("resource-sod-drift", _mut_resource("resource-egress-policy", separation_of_duties_required=False)),
    ("resource-breakglass-drift", _mut_resource("resource-egress-policy", break_glass_permitted=True)),
    ("resource-empty-version", _mut_resource("resource-egress-policy", current_version="")),
    ("route-omission", _drop("routes", "route_id", "route-egress-update")),
    ("route-duplicate", _duplicate("routes", "route_id", "route-egress-update")),
    ("route-owner-untrusted", _mut_route("route-egress-update", owner_id="attacker")),
    ("route-principal-unknown", _mut_route("route-egress-update", principal_id="unknown-admin")),
    ("route-resource-unknown", _mut_route("route-egress-update", resource_id="unknown-resource")),
    ("route-principal-drift", _mut_route("route-egress-update", principal_id="admin-authz")),
    ("route-resource-drift", _mut_route("route-egress-update", resource_id="resource-trust-store")),
    ("route-operation-drift", _mut_route("route-egress-update", operation=AdministrativeOperation.DELETE)),
    ("route-execution-identity-untrusted", _mut_route("route-egress-update", execution_identity_id="attacker-exec")),
    ("route-execution-identity-drift", _mut_route("route-egress-update", execution_identity_id="exec-trust-controller")),
    ("route-approval-drift", _mut_route("route-egress-update", approval_principal_ids=("approver-security",))),
    ("route-approver-untrusted", _mut_route("route-egress-update", approval_principal_ids=("approver-security", "attacker"))),
    ("policy-self-approval", _bad_policy_self_approval),
    ("route-control-drift", _mut_route("route-egress-update", required_control_ids=("CTRL-ADMIN-AUTHZ",))),
    ("route-control-unknown", _mut_route("route-egress-update", required_control_ids=("CTRL-UNKNOWN",))),
    ("route-telemetry-drift", _mut_route("route-egress-update", telemetry_requirement_ids=(REQ_CONTROL_CHANGE,))),
    ("route-telemetry-unknown", _mut_route("route-egress-update", telemetry_requirement_ids=("req-unknown",))),
    ("route-proposed-version-drift", _mut_route("route-egress-update", proposed_version="egress-v999")),
    ("route-proposed-version-current", _mut_route("route-egress-update", proposed_version="egress-v6")),
    ("route-target-digest-invalid", _mut_route("route-egress-update", target_state_sha256="not-a-hash")),
    ("route-breakglass-drift", _mut_route("route-egress-update", break_glass=True, emergency_reason="fake emergency")),
    ("breakglass-missing-emergency-reason", _mut_route("route-trust-breakglass", emergency_reason=None)),
    ("non-breakglass-emergency-reason", _mut_route("route-egress-update", emergency_reason="should-not-exist")),
    ("route-ticket-empty", _mut_route("route-egress-update", change_ticket_id="")),
    ("route-observation-stale", _mut_route("route-egress-update", verified_at_epoch=NOW - 10_000)),
    ("route-observation-future", _mut_route("route-egress-update", verified_at_epoch=NOW + 100)),
    ("p7b-unverified", _upstream_mut("p7b", exact_identity_graph_binding_verified=False)),
    ("p7b-digest-mismatch", _upstream_mut("p7b", assessment_evidence_sha256="c" * 64)),
    ("p7e-unverified", _upstream_mut("p7e", exact_dependency_graph_binding_verified=False)),
    ("p7e-digest-mismatch", _upstream_mut("p7e", assessment_evidence_sha256="d" * 64)),
    ("p7f-unverified", _upstream_mut("p7f", exact_resilience_plan_binding_verified=False)),
    ("p7f-digest-mismatch", _upstream_mut("p7f", assessment_evidence_sha256="e" * 64)),
    ("p7g-unverified", _upstream_mut("p7g", exact_telemetry_plan_binding_verified=False)),
    ("p7g-digest-mismatch", _upstream_mut("p7g", assessment_evidence_sha256="f" * 64)),
    ("posture-unverified", _upstream_mut("posture", control_catalog_verified=False)),
    ("posture-digest-mismatch", _upstream_mut("posture", posture_evidence_sha256="0" * 64)),
    ("control-catalog-mismatch", _upstream_mut("posture", control_catalog_sha256="1" * 64)),
    ("control-evidence-duplicate", _posture_duplicate_control),
    ("control-summary-inconsistent", _posture_bad_summary),
    ("caller-hides-exposed-admin-path", _exposed_p7b("p7b-admin-release")),
    ("caller-hides-exposed-egress-target", _exposed_p7e("p7e-path-model-egress")),
    ("caller-hides-exposed-fallback-target", _exposed_p7f("scenario-model-unavailable")),
    ("caller-hides-change-telemetry-blind-spot", _blind_telemetry(REQ_CONTROL_CHANGE)),
    ("caller-hides-exceptioned-change-control", _control_status(CTRL_CHANGE_APPROVAL, "exceptioned")),
    ("caller-hides-not-evaluated-change-control", _control_status(CTRL_CHANGE_APPROVAL, "not_evaluated")),
    ("caller-declares-fake-exposed-route", _mut_request("declared_exposed_route_ids", ("route-egress-update",))),
    ("caller-declares-fake-risk", _mut_request("declared_max_exposed_risk_score", 999)),
    ("coherent-self-authorization-mutation", _coherent_resource_binding("resource-authorization-policy", ("p7b:p7b-admin-authz",))),
    ("coherent-self-audit-mutation", _coherent_resource_binding("resource-telemetry-configuration", (f"p7g:{REQ_CONTROL_CHANGE}", "p7g:req-failover"))),
    ("coherent-critical-delete-route", _coherent_route_operation("route-egress-update", AdministrativeOperation.DELETE)),
)


def _evaluate_hardened(ctx: dict[str, object]) -> bool:
    try:
        analyzer = SecurityControlPlaneChangeAnalyzer(ctx["policy"])
        result = analyzer.evaluate(ctx["request"], ctx["manifest"], ctx["p7b"], ctx["p7e"], ctx["p7f"], ctx["p7g"], ctx["posture"])
    except ControlPlaneRejected:
        return False
    return result.exposed_route_count == 0


def _benign_contexts() -> tuple[tuple[str, dict[str, object]], ...]:
    base = _clone()

    exposed_admin = _clone()
    upstreams = make_upstreams(exposed_p7b_paths=frozenset({"p7b-admin-release"}))
    for key in ("p7b", "p7e", "p7f", "p7g", "posture"):
        exposed_admin[key] = upstreams[key]
    exposed_admin["request"] = replace(exposed_admin["request"], declared_exposed_route_ids=("route-release-promote",), declared_max_exposed_risk_score=113)

    blind = _clone()
    upstreams = make_upstreams(blind_spot_requirements=frozenset({REQ_CONTROL_CHANGE}))
    for key in ("p7b", "p7e", "p7f", "p7g", "posture"):
        blind[key] = upstreams[key]
    blind["request"] = replace(blind["request"], declared_exposed_route_ids=tuple(sorted(blind["request"].route_ids)), declared_max_exposed_risk_score=111)
    return (("clean-control-plane", base), ("truthful-exposed-admin-path", exposed_admin), ("truthful-telemetry-blind-spot", blind))


def run() -> dict[str, object]:
    weak = VulnerableAdminApprovedChangeReporter()
    vulnerable_successes = 0
    hardened_successes = 0
    case_results: list[dict[str, object]] = []
    for case_id, mutation in ADVERSARIAL_CASES:
        ctx = mutation(_clone())
        weak_result = weak.evaluate(declared_admin_approved=True, declared_change_safe=True, declared_exposed_route_count=0, declared_max_risk_score=0)
        vulnerable_success = weak_result.accepted
        hardened_success = _evaluate_hardened(ctx)
        vulnerable_successes += int(vulnerable_success)
        hardened_successes += int(hardened_success)
        case_results.append({"case_id": case_id, "vulnerable_success": vulnerable_success, "hardened_success": hardened_success})

    benign_results: list[dict[str, object]] = []
    false_positives = 0
    safe_task_successes = 0
    for case_id, ctx in _benign_contexts():
        analyzer = SecurityControlPlaneChangeAnalyzer(ctx["policy"])
        accepted = True
        try:
            analyzer.evaluate(ctx["request"], ctx["manifest"], ctx["p7b"], ctx["p7e"], ctx["p7f"], ctx["p7g"], ctx["posture"])
        except ControlPlaneRejected:
            accepted = False
        false_positives += int(not accepted)
        safe_task_successes += int(accepted)
        benign_results.append({"case_id": case_id, "accepted": accepted})

    dataset_document = [case_id for case_id, _ in ADVERSARIAL_CASES]
    dataset_sha = hashlib.sha256(json.dumps(dataset_document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    fixture = build_fixture()
    fixture_document = {
        "manifest_sha256": fixture["request"].control_plane_sha256,
        "route_ids": list(fixture["request"].route_ids),
        "principal_ids": sorted(item.principal_id for item in fixture["manifest"].principals),
        "resource_ids": sorted(item.resource_id for item in fixture["manifest"].resources),
        "p7b_sha256": P7B_SHA,
        "p7e_sha256": P7E_SHA,
        "p7f_sha256": P7F_SHA,
        "p7g_sha256": P7G_SHA,
        "posture_sha256": POSTURE_SHA,
        "control_catalog_sha256": CATALOG_SHA,
    }
    fixture_sha = hashlib.sha256(json.dumps(fixture_document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "adversarial_cases": len(ADVERSARIAL_CASES),
        "vulnerable_asr": f"{vulnerable_successes}/{len(ADVERSARIAL_CASES)}",
        "hardened_asr": f"{hardened_successes}/{len(ADVERSARIAL_CASES)}",
        "hardened_fpr": f"{false_positives}/{len(benign_results)}",
        "safe_task_rate": f"{safe_task_successes}/{len(benign_results)}",
        "control_plane_sha256": fixture["request"].control_plane_sha256,
        "dataset_sha256": dataset_sha,
        "fixture_sha256": fixture_sha,
        "cases": case_results,
        "benign": benign_results,
    }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2, sort_keys=True))
    assert result["vulnerable_asr"].startswith(f"{result['adversarial_cases']}/")
    assert result["hardened_asr"].startswith("0/")
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
