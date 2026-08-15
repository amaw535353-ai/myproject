from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Callable

from aegis.architecture.invariant_blast_radius import (
    InvariantAssessmentRejected,
    InvariantSeverity,
    SecurityArchitectureInvariantAnalyzer,
    invariant_catalog_digest,
)
from aegis.vulnerable.invariant_blast_radius import VulnerableDeclaredArchitectureSafety
from evals.p7i_fixture import (
    CONTROLS,
    NOW,
    OBJECT_IDS,
    build_fixture,
    make_upstreams,
    replace_invariant,
    truthful_declarations,
)

Mutation = Callable[[dict[str, object]], dict[str, object]]


def _clone() -> dict[str, object]:
    return dict(build_fixture())


def _request(field: str, value: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["request"] = replace(ctx["request"], **{field: value})
        return ctx
    return mutate


def _catalog(field: str, value: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["catalog"] = replace(ctx["catalog"], **{field: value})
        return ctx
    return mutate


def _repin(ctx: dict[str, object]) -> dict[str, object]:
    digest = invariant_catalog_digest(ctx["catalog"])
    ctx["policy"] = replace(ctx["policy"], expected_catalog_sha256=digest)
    ctx["request"] = replace(ctx["request"], catalog_sha256=digest)
    return ctx


def _invariant(invariant_id: str, **changes: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["catalog"] = replace_invariant(ctx["catalog"], invariant_id, **changes)
        return _repin(ctx)
    return mutate


def _drop_invariant(invariant_id: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["catalog"] = replace(ctx["catalog"], invariants=tuple(item for item in ctx["catalog"].invariants if item.invariant_id != invariant_id))
        return _repin(ctx)
    return mutate


def _duplicate_invariant(invariant_id: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        item = next(item for item in ctx["catalog"].invariants if item.invariant_id == invariant_id)
        ctx["catalog"] = replace(ctx["catalog"], invariants=ctx["catalog"].invariants + (item,))
        return _repin(ctx)
    return mutate


def _upstream_attr(source: str, field: str, value: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx[source] = SimpleNamespace(**{**vars(ctx[source]), field: value})
        return ctx
    return mutate


def _empty_inventory(source: str) -> Mutation:
    collection = {"p7f": "scenarios", "p7g": "requirements"}.get(source, "paths")
    return _upstream_attr(source, collection, ())


def _duplicate_inventory(source: str) -> Mutation:
    collection = {"p7f": "scenarios", "p7g": "requirements"}.get(source, "paths")
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        items = tuple(getattr(ctx[source], collection))
        ctx[source] = SimpleNamespace(**{**vars(ctx[source]), collection: items + (items[0],)})
        return ctx
    return mutate


def _unsafe(*bindings: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        upstreams = make_upstreams(unsafe_bindings=frozenset(bindings))
        for key in (*OBJECT_IDS.keys(), "posture"):
            ctx[key] = upstreams[key]
        return ctx
    return mutate


def _control(control_id: str, status: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        statuses = {key: "satisfied" for key in CONTROLS}
        statuses[control_id] = status
        upstreams = make_upstreams(control_statuses=statuses)
        for key in (*OBJECT_IDS.keys(), "posture"):
            ctx[key] = upstreams[key]
        return ctx
    return mutate


def _posture_duplicate(ctx: dict[str, object]) -> dict[str, object]:
    posture = ctx["posture"]
    assessments = tuple(posture.assessments)
    ctx["posture"] = SimpleNamespace(**{**vars(posture), "assessments": assessments + (assessments[0],)})
    return ctx


def _posture_summary(field: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        posture = ctx["posture"]
        ctx["posture"] = SimpleNamespace(**{**vars(posture), field: ("CTRL-AUTHZ",)})
        return ctx
    return mutate


def _policy_map_omit(field: str, key: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        policy = ctx["policy"]
        mapping = dict(getattr(policy, field))
        mapping.pop(key)
        ctx["policy"] = replace(policy, **{field: mapping})
        return ctx
    return mutate


def _policy_bad_layer_floor(ctx: dict[str, object]) -> dict[str, object]:
    policy = ctx["policy"]
    mapping = dict(policy.min_distinct_layers_by_invariant)
    mapping["INV-PRIVILEGED-TOOL-AUTHZ"] = 1
    ctx["policy"] = replace(policy, min_distinct_layers_by_invariant=mapping)
    return ctx


def _policy_unsupported_binding(ctx: dict[str, object]) -> dict[str, object]:
    policy = ctx["policy"]
    mapping = dict(policy.expected_binding_ids_by_invariant)
    mapping["INV-PRIVILEGED-TOOL-AUTHZ"] = frozenset({"evil:object", "p6d:CTRL-AUTHZ"})
    ctx["policy"] = replace(policy, expected_binding_ids_by_invariant=mapping)
    return ctx


def _replace_id(ctx: dict[str, object]) -> dict[str, object]:
    values = list(ctx["catalog"].invariants)
    for index, item in enumerate(values):
        if item.invariant_id == "INV-PRIVILEGED-TOOL-AUTHZ":
            values[index] = replace(item, invariant_id="INV-ATTACKER-SUBSTITUTE")
            break
    ctx["catalog"] = replace(ctx["catalog"], invariants=tuple(values))
    return _repin(ctx)


BASE_REQ = build_fixture()["request"]

ADVERSARIAL_CASES: tuple[tuple[str, Mutation], ...] = (
    ("request-catalog-id-substitution", _request("catalog_id", "evil-catalog")),
    ("request-version-substitution", _request("catalog_version", "evil-version")),
    ("request-catalog-digest-substitution", _request("catalog_sha256", "1" * 64)),
    ("request-p7a-digest-substitution", _request("p7a_assessment_evidence_sha256", "2" * 64)),
    ("request-p7b-digest-substitution", _request("p7b_assessment_evidence_sha256", "3" * 64)),
    ("request-p7c-digest-substitution", _request("p7c_assessment_evidence_sha256", "4" * 64)),
    ("request-p7d-digest-substitution", _request("p7d_assessment_evidence_sha256", "5" * 64)),
    ("request-p7e-digest-substitution", _request("p7e_assessment_evidence_sha256", "6" * 64)),
    ("request-p7f-digest-substitution", _request("p7f_assessment_evidence_sha256", "7" * 64)),
    ("request-p7g-digest-substitution", _request("p7g_assessment_evidence_sha256", "8" * 64)),
    ("request-p7h-digest-substitution", _request("p7h_assessment_evidence_sha256", "9" * 64)),
    ("request-posture-digest-substitution", _request("posture_evidence_sha256", "a" * 64)),
    ("request-invariant-omission", _request("invariant_ids", BASE_REQ.invariant_ids[:-1])),
    ("request-invariant-duplicate", _request("invariant_ids", BASE_REQ.invariant_ids + (BASE_REQ.invariant_ids[0],))),
    ("request-invariant-extra", _request("invariant_ids", BASE_REQ.invariant_ids + ("INV-EXTRA",))),
    ("catalog-schema-substitution", _catalog("schema_version", "evil-schema")),
    ("catalog-id-substitution", _catalog("catalog_id", "evil-catalog")),
    ("catalog-version-substitution", _catalog("version", "evil-version")),
    ("catalog-stale", _catalog("created_at_epoch", NOW - 90_000)),
    ("catalog-future", _catalog("created_at_epoch", NOW + 100)),
    ("catalog-p7a-pin-substitution", _catalog("p7a_assessment_evidence_sha256", "b" * 64)),
    ("catalog-p7b-pin-substitution", _catalog("p7b_assessment_evidence_sha256", "c" * 64)),
    ("catalog-p7c-pin-substitution", _catalog("p7c_assessment_evidence_sha256", "d" * 64)),
    ("catalog-p7d-pin-substitution", _catalog("p7d_assessment_evidence_sha256", "e" * 64)),
    ("catalog-p7e-pin-substitution", _catalog("p7e_assessment_evidence_sha256", "f" * 64)),
    ("catalog-p7f-pin-substitution", _catalog("p7f_assessment_evidence_sha256", "0" * 64)),
    ("catalog-p7g-pin-substitution", _catalog("p7g_assessment_evidence_sha256", "1" * 64)),
    ("catalog-p7h-pin-substitution", _catalog("p7h_assessment_evidence_sha256", "2" * 64)),
    ("catalog-posture-pin-substitution", _catalog("posture_evidence_sha256", "3" * 64)),
    ("catalog-content-tamper-without-repin", _catalog("invariants", tuple(replace(item, description=item.description + " tampered") if item.invariant_id == "INV-FAILOVER-NON-WEAKENING" else item for item in build_fixture()["catalog"].invariants))),
    ("invariant-omission", _drop_invariant("INV-SECRET-TRUST-CONFINEMENT")),
    ("invariant-duplicate", _duplicate_invariant("INV-SECRET-TRUST-CONFINEMENT")),
    ("invariant-id-substitution", _replace_id),
    ("invariant-owner-untrusted", _invariant("INV-SECRET-TRUST-CONFINEMENT", owner_id="attacker")),
    ("invariant-severity-downgrade", _invariant("INV-SECRET-TRUST-CONFINEMENT", severity=InvariantSeverity.LOW)),
    ("invariant-title-empty", _invariant("INV-SECRET-TRUST-CONFINEMENT", title="")),
    ("invariant-description-empty", _invariant("INV-SECRET-TRUST-CONFINEMENT", description="")),
    ("invariant-binding-omission", _invariant("INV-SECRET-TRUST-CONFINEMENT", required_binding_ids=("p7d:secret-tool-credential", "p7e:dep-tool-provider", "p6d:CTRL-SECRETS"))),
    ("invariant-binding-duplicate", _invariant("INV-SECRET-TRUST-CONFINEMENT", required_binding_ids=build_fixture()["catalog"].invariants[2].required_binding_ids + ("p7d:secret-tool-credential",))),
    ("invariant-binding-unknown", _invariant("INV-SECRET-TRUST-CONFINEMENT", required_binding_ids=("p7d:unknown", "p7e:dep-tool-provider", "p7g:telemetry-egress", "p7h:route-trust-rotate", "p6d:CTRL-SECRETS"))),
    ("invariant-asset-drift", _invariant("INV-SECRET-TRUST-CONFINEMENT", protected_asset_ids=("asset-attacker",))),
    ("invariant-identity-drift", _invariant("INV-SECRET-TRUST-CONFINEMENT", affected_identity_ids=("identity-attacker",))),
    ("invariant-dependency-drift", _invariant("INV-SECRET-TRUST-CONFINEMENT", dependency_ids=("dependency-attacker",))),
    ("invariant-route-drift", _invariant("INV-SECRET-TRUST-CONFINEMENT", control_plane_route_ids=("route-egress-update",))),
    ("invariant-control-drift", _invariant("INV-SECRET-TRUST-CONFINEMENT", required_control_ids=("CTRL-SECRETS",))),
    ("invariant-control-unknown", _invariant("INV-SECRET-TRUST-CONFINEMENT", required_control_ids=("CTRL-UNKNOWN",))),
    ("policy-map-coverage-omission", _policy_map_omit("expected_asset_ids_by_invariant", "INV-SECRET-TRUST-CONFINEMENT")),
    ("policy-layer-floor-invalid", _policy_bad_layer_floor),
    ("policy-unsupported-binding-source", _policy_unsupported_binding),
    ("p7a-unverified", _upstream_attr("p7a", "exact_architecture_binding_verified", False)),
    ("p7a-digest-mismatch", _upstream_attr("p7a", "assessment_evidence_sha256", "4" * 64)),
    ("p7a-empty-inventory", _empty_inventory("p7a")),
    ("p7a-duplicate-inventory", _duplicate_inventory("p7a")),
    ("p7b-unverified", _upstream_attr("p7b", "exact_identity_graph_binding_verified", False)),
    ("p7b-digest-mismatch", _upstream_attr("p7b", "assessment_evidence_sha256", "5" * 64)),
    ("p7b-empty-inventory", _empty_inventory("p7b")),
    ("p7b-duplicate-inventory", _duplicate_inventory("p7b")),
    ("p7c-unverified", _upstream_attr("p7c", "exact_data_graph_binding_verified", False)),
    ("p7c-digest-mismatch", _upstream_attr("p7c", "assessment_evidence_sha256", "6" * 64)),
    ("p7c-empty-inventory", _empty_inventory("p7c")),
    ("p7c-duplicate-inventory", _duplicate_inventory("p7c")),
    ("p7d-unverified", _upstream_attr("p7d", "exact_secret_graph_binding_verified", False)),
    ("p7d-digest-mismatch", _upstream_attr("p7d", "assessment_evidence_sha256", "7" * 64)),
    ("p7d-empty-inventory", _empty_inventory("p7d")),
    ("p7d-duplicate-inventory", _duplicate_inventory("p7d")),
    ("p7e-unverified", _upstream_attr("p7e", "exact_dependency_graph_binding_verified", False)),
    ("p7e-digest-mismatch", _upstream_attr("p7e", "assessment_evidence_sha256", "8" * 64)),
    ("p7f-unverified", _upstream_attr("p7f", "exact_resilience_plan_binding_verified", False)),
    ("p7f-digest-mismatch", _upstream_attr("p7f", "assessment_evidence_sha256", "9" * 64)),
    ("p7g-unverified", _upstream_attr("p7g", "exact_telemetry_plan_binding_verified", False)),
    ("p7g-digest-mismatch", _upstream_attr("p7g", "assessment_evidence_sha256", "a" * 64)),
    ("p7h-unverified", _upstream_attr("p7h", "exact_control_plane_binding_verified", False)),
    ("p7h-digest-mismatch", _upstream_attr("p7h", "assessment_evidence_sha256", "b" * 64)),
    ("posture-unverified", _upstream_attr("posture", "control_catalog_verified", False)),
    ("posture-digest-mismatch", _upstream_attr("posture", "posture_evidence_sha256", "c" * 64)),
    ("control-catalog-mismatch", _upstream_attr("posture", "control_catalog_sha256", "d" * 64)),
    ("posture-control-duplicate", _posture_duplicate),
    ("posture-satisfied-summary-inconsistent", _posture_summary("satisfied_control_ids")),
    ("posture-exception-summary-inconsistent", _posture_summary("exceptioned_control_ids")),
    ("posture-not-evaluated-summary-inconsistent", _posture_summary("not_evaluated_control_ids")),
    ("caller-hides-p7a-exposure", _unsafe("p7a:attack-tool-to-control")),
    ("caller-hides-p7b-exposure", _unsafe("p7b:priv-tenant-cross")),
    ("caller-hides-p7c-exfiltration", _unsafe("p7c:data-tenant-egress")),
    ("caller-hides-p7d-secret-exposure", _unsafe("p7d:secret-model-signing")),
    ("caller-hides-p7e-dependency-exposure", _unsafe("p7e:dep-model-provider")),
    ("caller-hides-p7f-failover-exposure", _unsafe("p7f:failover-tool")),
    ("caller-hides-p7g-blind-spot", _unsafe("p7g:telemetry-admin")),
    ("caller-hides-p7h-control-plane-exposure", _unsafe("p7h:route-assurance-update")),
    ("caller-hides-exceptioned-control", _control("CTRL-ASSURANCE", "exceptioned")),
    ("caller-hides-not-evaluated-control", _control("CTRL-TELEMETRY", "not_evaluated")),
    ("caller-declares-fake-violated-invariant", _request("declared_violated_invariant_ids", ("INV-SECRET-TRUST-CONFINEMENT",))),
    ("caller-declares-fake-degraded-invariant", _request("declared_degraded_invariant_ids", ("INV-FAILOVER-NON-WEAKENING",))),
    ("caller-declares-fake-blast-radius", _request("declared_cross_layer_blast_radius", 999)),
    ("caller-declares-fake-max-risk", _request("declared_max_blast_radius_score", 999)),
    ("cross-layer-tool-chain-masked", _unsafe("p7a:attack-tool-to-control", "p7b:priv-tool-admin", "p7d:secret-tool-credential", "p7e:dep-tool-provider")),
    ("cross-layer-tenant-chain-masked", _unsafe("p7a:attack-user-to-data", "p7b:priv-tenant-cross", "p7c:data-tenant-egress", "p7e:dep-model-provider")),
    ("cross-layer-telemetry-chain-masked", _unsafe("p7d:secret-telemetry", "p7e:dep-telemetry", "p7f:failover-telemetry", "p7g:telemetry-admin")),
    ("cross-layer-admin-chain-masked", _unsafe("p7a:attack-admin-to-control", "p7b:priv-control-admin", "p7g:telemetry-admin", "p7h:route-authz-update")),
)


def _hardened_attack_succeeds(ctx: dict[str, object]) -> bool:
    try:
        result = SecurityArchitectureInvariantAnalyzer(ctx["policy"]).evaluate(
            ctx["request"], ctx["catalog"], ctx["p7a"], ctx["p7b"], ctx["p7c"], ctx["p7d"], ctx["p7e"], ctx["p7f"], ctx["p7g"], ctx["p7h"], ctx["posture"]
        )
    except InvariantAssessmentRejected:
        return False
    return result.violated_invariant_count == 0 and result.degraded_invariant_count == 0 and result.cross_layer_blast_radius == 0


def _truthful_state(*, unsafe_bindings: frozenset[str] = frozenset(), statuses: dict[str, str] | None = None) -> dict[str, object]:
    ctx = _clone()
    upstreams = make_upstreams(unsafe_bindings=unsafe_bindings, control_statuses=statuses)
    for key in (*OBJECT_IDS.keys(), "posture"):
        ctx[key] = upstreams[key]
    declarations = truthful_declarations(ctx["catalog"], unsafe_bindings=unsafe_bindings, control_statuses=statuses)
    ctx["request"] = replace(ctx["request"], **declarations)
    return ctx


def benign_contexts() -> tuple[tuple[str, dict[str, object]], ...]:
    statuses = {key: "satisfied" for key in CONTROLS}
    statuses["CTRL-TELEMETRY"] = "exceptioned"
    return (
        ("clean-all-invariants-hold", _truthful_state()),
        ("truthful-tenant-data-violation", _truthful_state(unsafe_bindings=frozenset({"p7c:data-tenant-egress"}))),
        ("truthful-telemetry-control-degradation", _truthful_state(statuses=statuses)),
    )


def run() -> dict[str, object]:
    weak = VulnerableDeclaredArchitectureSafety()
    vulnerable_successes = 0
    hardened_successes = 0
    cases: list[dict[str, object]] = []
    for case_id, mutation in ADVERSARIAL_CASES:
        ctx = mutation(_clone())
        vulnerable = weak.evaluate(declared_all_invariants_hold=True, declared_blast_radius=0, declared_cross_layer_risk=0).accepted
        hardened = _hardened_attack_succeeds(ctx)
        vulnerable_successes += int(vulnerable)
        hardened_successes += int(hardened)
        cases.append({"case_id": case_id, "vulnerable_success": vulnerable, "hardened_success": hardened})

    benign_results: list[dict[str, object]] = []
    false_positives = 0
    safe_successes = 0
    for case_id, ctx in benign_contexts():
        accepted = True
        try:
            SecurityArchitectureInvariantAnalyzer(ctx["policy"]).evaluate(
                ctx["request"], ctx["catalog"], ctx["p7a"], ctx["p7b"], ctx["p7c"], ctx["p7d"], ctx["p7e"], ctx["p7f"], ctx["p7g"], ctx["p7h"], ctx["posture"]
            )
        except InvariantAssessmentRejected:
            accepted = False
        false_positives += int(not accepted)
        safe_successes += int(accepted)
        benign_results.append({"case_id": case_id, "accepted": accepted})

    fixture = build_fixture()
    dataset_sha = hashlib.sha256(json.dumps([case_id for case_id, _ in ADVERSARIAL_CASES], separators=(",", ":")).encode()).hexdigest()
    fixture_document = {
        "catalog_sha256": fixture["request"].catalog_sha256,
        "invariant_ids": list(fixture["request"].invariant_ids),
        "p7a_sha256": fixture["request"].p7a_assessment_evidence_sha256,
        "p7b_sha256": fixture["request"].p7b_assessment_evidence_sha256,
        "p7c_sha256": fixture["request"].p7c_assessment_evidence_sha256,
        "p7d_sha256": fixture["request"].p7d_assessment_evidence_sha256,
        "p7e_sha256": fixture["request"].p7e_assessment_evidence_sha256,
        "p7f_sha256": fixture["request"].p7f_assessment_evidence_sha256,
        "p7g_sha256": fixture["request"].p7g_assessment_evidence_sha256,
        "p7h_sha256": fixture["request"].p7h_assessment_evidence_sha256,
        "posture_sha256": fixture["request"].posture_evidence_sha256,
    }
    fixture_sha = hashlib.sha256(json.dumps(fixture_document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "adversarial_cases": len(ADVERSARIAL_CASES),
        "vulnerable_asr": f"{vulnerable_successes}/{len(ADVERSARIAL_CASES)}",
        "hardened_asr": f"{hardened_successes}/{len(ADVERSARIAL_CASES)}",
        "hardened_fpr": f"{false_positives}/{len(benign_results)}",
        "safe_task_rate": f"{safe_successes}/{len(benign_results)}",
        "catalog_sha256": fixture["request"].catalog_sha256,
        "dataset_sha256": dataset_sha,
        "fixture_sha256": fixture_sha,
        "cases": cases,
        "benign": benign_results,
    }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2, sort_keys=True))
    assert result["vulnerable_asr"] == f"{result['adversarial_cases']}/{result['adversarial_cases']}"
    assert result["hardened_asr"] == f"0/{result['adversarial_cases']}"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
