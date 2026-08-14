from __future__ import annotations

import pytest

from aegis.architecture.attack_paths import AttackPathRejected
from aegis.assurance.posture_reporting import ControlStatus
from evals.p7a_attack_paths import adversarial_variants, benign_variants, build_fixture, run_hardened


def test_p7a_happy_path_derives_one_exposed_secret_path_and_two_controlled_paths():
    verified = run_hardened(build_fixture())
    assert verified.topology_path_count == 3
    assert verified.exposed_path_count == 1
    assert verified.controlled_path_count == 2
    assert verified.critical_exposed_path_count == 1
    assert verified.max_exposed_risk_score == 106
    exposed = [path for path in verified.paths if path.exposed]
    assert len(exposed) == 1
    assert exposed[0].target_asset_id == "secret-store"
    assert "CTRL-TOOL-AUTH" in exposed[0].exceptioned_control_ids
    assert "CTRL-LEAST-PRIVILEGE" in exposed[0].mitigating_control_ids
    assert exposed[0].trust_boundary_crossings == 4


def test_p7a_verified_output_keeps_explicit_non_claims():
    verified = run_hardened(build_fixture())
    assert verified.exact_architecture_binding_verified
    assert verified.required_graph_coverage_verified
    assert verified.trust_boundaries_policy_pinned
    assert verified.exact_posture_binding_verified
    assert verified.control_status_derived_from_p6d
    assert verified.missing_and_exceptioned_controls_visible
    assert not verified.caller_summary_trusted
    assert not verified.production_asset_discovery
    assert not verified.production_exploitability_assessment
    assert not verified.formal_reachability_proof
    assert not verified.external_red_team_evidence
    assert verified.network_operations == 0


@pytest.mark.parametrize("name,fixture", adversarial_variants(), ids=lambda item: item if isinstance(item, str) else None)
def test_p7a_adversarial_variants_fail_closed(name, fixture):
    with pytest.raises(AttackPathRejected):
        run_hardened(fixture)


@pytest.mark.parametrize("fixture", benign_variants(), ids=["exceptioned-control-visible", "all-controls-satisfied", "not-evaluated-control-visible"])
def test_p7a_benign_architecture_assessments_pass(fixture):
    verified = run_hardened(fixture)
    assert verified.topology_path_count == 3


def test_p7a_all_satisfied_posture_has_no_exposed_path():
    verified = run_hardened(build_fixture(ControlStatus.SATISFIED))
    assert verified.exposed_path_count == 0
    assert verified.max_exposed_risk_score == 0
    assert verified.prioritized_exposed_path_ids == ()


def test_p7a_not_evaluated_tool_auth_remains_visible_as_exposure():
    verified = run_hardened(build_fixture(ControlStatus.NOT_EVALUATED))
    assert verified.exposed_path_count == 1
    exposed = next(path for path in verified.paths if path.exposed)
    assert exposed.not_evaluated_control_ids == ("CTRL-TOOL-AUTH",)
    assert verified.max_exposed_risk_score == 102
