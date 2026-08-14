from __future__ import annotations

import pytest

from aegis.architecture.privilege_paths import PrivilegePathRejected
from aegis.assurance.posture_reporting import ControlStatus
from evals.p7b_privilege_paths import (
    CAP_LOAD_MODEL,
    CAP_READ_SECRET,
    adversarial_variants,
    benign_variants,
    build_fixture,
    run_hardened,
)


def test_p7b_default_fixture_derives_two_sensitive_capability_paths():
    verified = run_hardened(build_fixture())
    assert verified.topology_path_count == 2
    target_paths = [p for p in verified.paths if p.target_capability_id in {CAP_READ_SECRET, CAP_LOAD_MODEL}]
    assert len(target_paths) == 2
    assert verified.exposed_path_count == 1
    assert verified.controlled_path_count == 1
    assert verified.critical_exposed_path_count == 1
    assert verified.max_exposed_risk_score == 139


def test_p7b_default_exposure_is_tool_authorization_gap_to_secret_capability():
    verified = run_hardened(build_fixture())
    exposed = [path for path in verified.paths if path.exposed]
    assert len(exposed) == 1
    path = exposed[0]
    assert path.entry_principal_id == "external-user-principal"
    assert path.target_capability_id == CAP_READ_SECRET
    assert path.final_principal_id == "secret-broker-principal"
    assert path.privilege_increase == 4
    assert path.scope_increase == 3
    assert path.exceptioned_control_ids == ("CTRL-TOOL-AUTH",)
    assert "CTRL-CREDENTIAL-BROKER" in path.mitigating_control_ids
    assert "CTRL-LEAST-PRIVILEGE" in path.mitigating_control_ids


def test_p7b_verified_output_keeps_explicit_nonclaims():
    verified = run_hardened(build_fixture())
    assert verified.exact_identity_graph_binding_verified
    assert verified.exact_architecture_binding_verified
    assert verified.exact_p7a_assessment_binding_verified
    assert verified.exact_p6d_posture_binding_verified
    assert verified.principal_capability_policy_pinned
    assert verified.delegation_routes_policy_pinned
    assert verified.privilege_amplification_derived_from_evidence
    assert verified.mitigating_controls_visible
    assert not verified.caller_summary_trusted
    assert not verified.production_iam_discovery
    assert not verified.real_credential_testing
    assert not verified.production_exploitability_assessment
    assert not verified.formal_authorization_proof
    assert verified.network_operations == 0


@pytest.mark.parametrize("name,fixture", adversarial_variants(), ids=lambda item: item if isinstance(item, str) else None)
def test_p7b_adversarial_variants_fail_closed(name, fixture):
    with pytest.raises(PrivilegePathRejected):
        run_hardened(fixture)


@pytest.mark.parametrize("fixture", benign_variants(), ids=["exceptioned-tool-auth-visible", "all-controls-satisfied", "not-evaluated-tool-auth-visible"])
def test_p7b_benign_identity_assessments_pass(fixture):
    verified = run_hardened(fixture)
    assert verified.topology_path_count == 2


def test_p7b_all_satisfied_controls_preserve_legitimate_delegations_without_exposure():
    verified = run_hardened(build_fixture(ControlStatus.SATISFIED))
    assert verified.exposed_path_count == 0
    assert verified.controlled_path_count == 2
    assert verified.max_exposed_risk_score == 0
    assert verified.prioritized_exposed_path_ids == ()


def test_p7b_not_evaluated_tool_authorization_remains_visible():
    verified = run_hardened(build_fixture(ControlStatus.NOT_EVALUATED))
    assert verified.exposed_path_count == 1
    exposed = next(path for path in verified.paths if path.exposed)
    assert exposed.target_capability_id == CAP_READ_SECRET
    assert exposed.not_evaluated_control_ids == ("CTRL-TOOL-AUTH",)
    assert verified.max_exposed_risk_score == 134
