from __future__ import annotations

from aegis.security.phase4_controls import (
    PHASE4_BOUNDARY_CLAIMS,
    PHASE4_CONTROLS,
    PHASE4_PROHIBITED_CLAIMS,
    Phase4EvidencePosture,
    expected_phase4_milestones,
    phase4_evidence_register,
)
from evals.p4q_phase4_exit_gate import build_report


def test_phase4_registry_is_complete_ordered_and_non_production() -> None:
    assert tuple(item.milestone for item in PHASE4_CONTROLS) == expected_phase4_milestones()
    assert len(PHASE4_CONTROLS) == 16
    assert all(item.supported_claims for item in PHASE4_CONTROLS)
    assert all(item.residual_assumptions for item in PHASE4_CONTROLS)
    assert all(item.production_ready is False for item in PHASE4_CONTROLS)
    assert all(item.operationally_external is False for item in PHASE4_CONTROLS)
    assert all(item.independent_failure_domain is False for item in PHASE4_CONTROLS)


def test_phase4_supported_claims_do_not_cross_prohibited_boundary() -> None:
    for item in PHASE4_CONTROLS:
        for claim in item.supported_claims:
            lowered = claim.casefold()
            assert all(prohibited.casefold() not in lowered for prohibited in PHASE4_PROHIBITED_CLAIMS)


def test_phase4_evidence_posture_distribution_is_explicit() -> None:
    counts = {
        posture: sum(item.posture is posture for item in PHASE4_CONTROLS)
        for posture in Phase4EvidencePosture
    }
    assert counts == {
        Phase4EvidencePosture.DEFAULT_LOCAL: 7,
        Phase4EvidencePosture.POLICY_BOUNDARY: 2,
        Phase4EvidencePosture.SYNTHETIC_LAB: 7,
    }


def test_phase4_global_production_and_distributed_claims_remain_false() -> None:
    for name in (
        "production_external_checkpoint_adapter",
        "production_external_lifecycle_provider",
        "production_checkpoint_durability",
        "production_disaster_recovery",
        "distributed_transaction",
        "distributed_consensus",
        "exactly_once_execution",
        "independent_failure_domain",
        "real_external_trust_operations",
        "network_operations_required",
    ):
        assert PHASE4_BOUNDARY_CLAIMS[name] is False


def test_phase4_evidence_register_is_machine_readable_and_complete() -> None:
    register = phase4_evidence_register()
    assert len(register) == 16
    assert tuple(item["milestone"] for item in register) == expected_phase4_milestones()
    assert all(item["threat_model"] for item in register)
    assert all(item["eval_command"] for item in register)
    assert all(item["evidence_paths"] for item in register)


def test_p4q_exit_gate_passes_and_is_deterministic() -> None:
    first = build_report()
    second = build_report()
    assert first["phase4_exit_gate_passed"] is True
    assert first["checks"] == second["checks"]
    assert first["registry_hash_sha256"] == second["registry_hash_sha256"]
    assert len(first["registry_hash_sha256"]) == 64
    assert first["phase4_control_count"] == 16
    assert first["next_phase"] == "Phase 5 model and AI supply-chain security"
