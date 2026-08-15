from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.architecture.invariant_blast_radius import (
    InvariantAssessmentRejected,
    InvariantRejectReason,
    InvariantState,
    SecurityArchitectureInvariantAnalyzer,
    invariant_catalog_digest,
)
from evals.p7i_fixture import CONTROLS, build_fixture, make_upstreams, truthful_declarations
from evals.p7i_invariant_blast_radius import ADVERSARIAL_CASES, _clone, _hardened_attack_succeeds, benign_contexts, run


def evaluate(ctx):
    return SecurityArchitectureInvariantAnalyzer(ctx["policy"]).evaluate(
        ctx["request"], ctx["catalog"], ctx["p7a"], ctx["p7b"], ctx["p7c"], ctx["p7d"], ctx["p7e"], ctx["p7f"], ctx["p7g"], ctx["p7h"], ctx["posture"]
    )


def test_baseline_all_invariants_hold():
    result = evaluate(build_fixture())
    assert result.invariant_count == 8
    assert result.holding_invariant_count == 8
    assert result.degraded_invariant_count == 0
    assert result.violated_invariant_count == 0
    assert result.cross_layer_blast_radius == 0
    assert result.max_blast_radius_score == 0
    assert result.network_operations == 0
    assert result.caller_declared_architecture_safety_trusted is False


def test_catalog_digest_is_deterministic():
    ctx = build_fixture()
    assert invariant_catalog_digest(ctx["catalog"]) == ctx["request"].catalog_sha256
    assert ctx["request"].catalog_sha256 == "999edcda89df9c878bbc01b3cf6cd1ee3ea2895929892f8e5f2057db9a02f530"


def test_evaluator_metrics_and_hashes_are_exact():
    result = run()
    assert result["adversarial_cases"] == 98
    assert result["vulnerable_asr"] == "98/98"
    assert result["hardened_asr"] == "0/98"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
    assert result["dataset_sha256"] == "aeef85e381df1d6ad37356d01ad9bff62400ce1796daf4874a9c8d2d7fae6691"
    assert result["fixture_sha256"] == "fe8734dd7398df94a7d437810f1090dfc81f452f8a50762d7b58d83fb6737d07"


def test_all_adversarial_cases_fail_closed():
    failures = [case_id for case_id, mutation in ADVERSARIAL_CASES if _hardened_attack_succeeds(mutation(_clone()))]
    assert failures == []


def test_truthful_tenant_violation_reports_blast_radius():
    ctx = dict(benign_contexts()[1][1])
    result = evaluate(ctx)
    assert result.violated_invariant_count == 1
    assert result.degraded_invariant_count == 0
    assert result.cross_layer_blast_radius == 6
    assert result.max_blast_radius_score == 125
    fact = next(item for item in result.invariants if item.invariant_id == "INV-TENANT-DATA-CONFINEMENT")
    assert fact.state == InvariantState.VIOLATED
    assert fact.violating_binding_ids == ("p7c:data-tenant-egress",)
    assert len(fact.mitigating_binding_ids) == 7


def test_truthful_telemetry_control_exception_degrades_without_forging_violation():
    ctx = dict(benign_contexts()[2][1])
    result = evaluate(ctx)
    assert result.violated_invariant_count == 0
    assert result.degraded_invariant_count == 4
    assert result.cross_layer_blast_radius == 21
    assert result.max_blast_radius_score == 116
    assert result.prioritized_invariant_ids[0] == "INV-ADMIN-NON-SELF-BYPASS"


def test_multi_layer_tool_violation_prioritizes_cross_layer_blast_radius():
    ctx = build_fixture()
    unsafe = frozenset({"p7a:attack-tool-to-control", "p7b:priv-tool-admin", "p7d:secret-tool-credential", "p7e:dep-tool-provider"})
    upstreams = make_upstreams(unsafe_bindings=unsafe)
    for key in ("p7a", "p7b", "p7c", "p7d", "p7e", "p7f", "p7g", "p7h", "posture"):
        ctx[key] = upstreams[key]
    ctx["request"] = replace(ctx["request"], **truthful_declarations(ctx["catalog"], unsafe_bindings=unsafe))
    result = evaluate(ctx)
    tool = next(item for item in result.invariants if item.invariant_id == "INV-PRIVILEGED-TOOL-AUTHZ")
    assert tool.state == InvariantState.VIOLATED
    assert tool.exposed_layer_ids == ("p7a", "p7b", "p7d", "p7e")
    assert tool.blast_radius_score > 140


def test_unknown_binding_rejected_even_after_catalog_repin():
    from evals.p7i_fixture import replace_invariant
    ctx = build_fixture()
    ctx["catalog"] = replace_invariant(ctx["catalog"], "INV-FAILOVER-NON-WEAKENING", required_binding_ids=("p7f:unknown", "p7e:dep-model-provider", "p7g:telemetry-egress", "p7h:route-fallback-update", "p6d:CTRL-FAILOVER"))
    digest = invariant_catalog_digest(ctx["catalog"])
    ctx["policy"] = replace(ctx["policy"], expected_catalog_sha256=digest)
    ctx["request"] = replace(ctx["request"], catalog_sha256=digest)
    with pytest.raises(InvariantAssessmentRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason in {InvariantRejectReason.INVARIANT_BINDING_DRIFT, InvariantRejectReason.INVARIANT_BINDING_UNKNOWN}


def test_severity_downgrade_rejected_after_catalog_repin():
    from evals.p7i_fixture import replace_invariant
    from aegis.architecture.invariant_blast_radius import InvariantSeverity
    ctx = build_fixture()
    ctx["catalog"] = replace_invariant(ctx["catalog"], "INV-ASSURANCE-GATE-NON-BYPASS", severity=InvariantSeverity.LOW)
    digest = invariant_catalog_digest(ctx["catalog"])
    ctx["policy"] = replace(ctx["policy"], expected_catalog_sha256=digest)
    ctx["request"] = replace(ctx["request"], catalog_sha256=digest)
    with pytest.raises(InvariantAssessmentRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == InvariantRejectReason.INVARIANT_SEVERITY_DOWNGRADE


def test_caller_cannot_hide_blast_radius():
    ctx = build_fixture()
    upstreams = make_upstreams(unsafe_bindings=frozenset({"p7h:route-assurance-update"}))
    for key in ("p7a", "p7b", "p7c", "p7d", "p7e", "p7f", "p7g", "p7h", "posture"):
        ctx[key] = upstreams[key]
    with pytest.raises(InvariantAssessmentRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == InvariantRejectReason.DECLARED_STATE_MISMATCH


def test_posture_control_summary_inconsistency_rejected():
    ctx = build_fixture()
    posture = ctx["posture"]
    ctx["posture"] = type(posture)(**{**vars(posture), "satisfied_control_ids": ()})
    with pytest.raises(InvariantAssessmentRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == InvariantRejectReason.CONTROL_EVIDENCE_INVALID


def test_policy_requires_cross_layer_floor():
    ctx = build_fixture()
    floors = dict(ctx["policy"].min_distinct_layers_by_invariant)
    floors["INV-ADMIN-NON-SELF-BYPASS"] = 1
    with pytest.raises(InvariantAssessmentRejected) as exc:
        SecurityArchitectureInvariantAnalyzer(replace(ctx["policy"], min_distinct_layers_by_invariant=floors))
    assert exc.value.reason == InvariantRejectReason.POLICY_INVALID


def test_counterevidence_preserved_for_violated_invariant():
    ctx = dict(benign_contexts()[1][1])
    result = evaluate(ctx)
    fact = next(item for item in result.invariants if item.invariant_id == "INV-TENANT-DATA-CONFINEMENT")
    assert "p7c:data-tenant-egress" in fact.violating_binding_ids
    assert "p7a:attack-user-to-data" in fact.mitigating_binding_ids
    assert result.counterevidence_preserved is True


def test_claim_boundary_flags_are_explicit():
    result = evaluate(build_fixture())
    assert result.exhaustive_attack_coverage is False
    assert result.formal_end_to_end_security_proof is False
    assert result.production_asset_inventory is False
    assert result.production_dependency_discovery is False
    assert result.production_control_plane_enforcement is False
    assert result.compliance_certification is False
