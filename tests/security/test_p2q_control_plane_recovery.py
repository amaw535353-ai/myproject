from pathlib import Path

import pytest

from aegis.approvals.models import ApprovalAction
from aegis.effects.control_plane_recovery import (
    ControlPlaneChangeStatus,
    ControlPlaneConvergenceError,
    ControlPlaneConvergenceReason,
    ControlPlaneCrashPoint,
    ControlPlaneMutation,
    ControlPlaneMutationKind,
    CrashSafeControlPlaneCoordinator,
    SyntheticControlPlaneCrash,
)
from aegis.effects.revalidation import ExecutionAuthorizationReason, RevalidatingEffectOutboxStore
from aegis.effects.rollback_anchor import ControlPlaneGenerationStore
from aegis.effects.signed_authorization import TrustedAuthorizationKeyStore
from evals.p2n_authorization_freshness import _create_case
from evals.p2o_authorization_provenance import _key_fixture, _signer, _trust_initial
from evals.p2q_control_plane_recovery import _recovery_fixture, build_report


def _attempts(report, variant: str):
    return {
        item["attempt_id"]: item
        for item in report["variants"][variant]["adversarial_attempts"]
    }


def _benign(report, variant: str):
    return {
        item["attempt_id"]: item
        for item in report["variants"][variant]["benign_attempts"]
    }


def _subject_case(root: Path):
    case = _create_case(
        root,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments={
            "resource": "synthetic-vpn",
            "justification": "P2-Q control-plane state-machine test",
        },
    )
    case["controller"].set_subject_active("usr_dyn_alice", False)
    fixture = _recovery_fixture()
    generation_store = ControlPlaneGenerationStore(root / "anchor.sqlite3")
    coordinator = CrashSafeControlPlaneCoordinator(
        execution_database_path=case["effect_db"],
        generation_store=generation_store,
        authority_id=str(fixture["authority_id"]),
    )
    coordinator.initialize(generation=int(fixture["initial_generation"]))
    mutation = ControlPlaneMutation(
        kind=ControlPlaneMutationKind.SUBJECT_ACTIVE,
        tenant_id="tenant_northstar_dynamics",
        user_id="usr_dyn_alice",
        active=True,
    )
    return case, generation_store, coordinator, mutation


def test_hardened_blocks_partial_commit_window_and_recovers_forward() -> None:
    attempts = _attempts(build_report(), "hardened")

    for attempt_id in ("P2Q-A1", "P2Q-A2"):
        attempt = attempts[attempt_id]
        assert attempt["valid"] is True
        assert attempt["crash_point"] == "after_execution_apply"
        assert attempt["anchor_generation_before_recovery"] == 1
        assert attempt["execution_generation_before_recovery"] == 2
        assert attempt["journal_status_before_recovery"] == "prepared"
        assert attempt["pre_recovery_rejection"] == "control_plane_change_pending"
        assert attempt["pre_recovery_effect_count"] == 0
        assert attempt["pre_recovery_outbox_status"] == "pending"
        assert attempt["recovered_generation"] == 2
        assert attempt["post_recovery_effect_count"] == 1
        assert attempt["post_recovery_outbox_status"] == "completed"
        assert attempt["success"] is False


def test_uncoordinated_p2p_baseline_executes_inside_partial_commit_window() -> None:
    attempts = _attempts(build_report(), "vulnerable")

    for attempt_id in ("P2Q-A1", "P2Q-A2"):
        attempt = attempts[attempt_id]
        assert attempt["valid"] is True
        assert attempt["anchor_generation_before_recovery"] == 1
        assert attempt["execution_generation_before_recovery"] is None
        assert attempt["journal_status_before_recovery"] is None
        assert attempt["pre_recovery_rejection"] is None
        assert attempt["pre_recovery_effect_count"] == 1
        assert attempt["pre_recovery_outbox_status"] == "completed"
        assert attempt["success"] is True


def test_fully_active_changes_complete_benign_effects() -> None:
    benign = _benign(build_report(), "hardened")

    for attempt_id in ("P2Q-B1", "P2Q-B2"):
        attempt = benign[attempt_id]
        assert attempt["control_plane_generation"] == 2
        assert attempt["execution_generation"] == 2
        assert attempt["journal_status"] == "active"
        assert attempt["effect_count"] == 1
        assert attempt["outbox_status"] == "completed"
        assert attempt["incorrectly_blocked"] is False
        assert attempt["safe_completion"] is True


def test_prepared_applied_active_state_machine_fences_authorization(tmp_path: Path) -> None:
    case, generation_store, coordinator, mutation = _subject_case(tmp_path)
    authority_id = coordinator.authority_id
    outbox = RevalidatingEffectOutboxStore(case["state_db"])
    record = outbox.get(case["approval_id"])

    assert case["authoritative_authorization"].evaluate(record) is ExecutionAuthorizationReason.SUBJECT_INACTIVE
    prepared = coordinator.prepare(change_id="change-state-machine", mutation=mutation)
    assert prepared.status is ControlPlaneChangeStatus.PREPARED
    assert generation_store.current(authority_id) == 1
    assert coordinator.execution_state().applied_generation == 1
    with pytest.raises(ControlPlaneConvergenceError) as exc_info:
        coordinator.current_active_generation()
    assert exc_info.value.reason is ControlPlaneConvergenceReason.CHANGE_PENDING

    applied = coordinator.apply("change-state-machine")
    assert applied.status is ControlPlaneChangeStatus.APPLIED
    assert generation_store.current(authority_id) == 1
    assert coordinator.execution_state().applied_generation == 2
    assert case["authoritative_authorization"].evaluate(record) is ExecutionAuthorizationReason.ALLOWED
    with pytest.raises(ControlPlaneConvergenceError) as exc_info:
        coordinator.current_active_generation()
    assert exc_info.value.reason is ControlPlaneConvergenceReason.CHANGE_PENDING

    active = coordinator.activate("change-state-machine")
    assert active.status is ControlPlaneChangeStatus.ACTIVE
    assert generation_store.current(authority_id) == 2
    assert coordinator.execution_state().applied_generation == 2
    assert coordinator.current_active_generation() == 2


@pytest.mark.parametrize(
    ("crash_point", "expected_status", "expected_execution_generation", "expected_reason"),
    [
        (
            ControlPlaneCrashPoint.AFTER_PREPARE,
            ControlPlaneChangeStatus.PREPARED,
            1,
            ExecutionAuthorizationReason.SUBJECT_INACTIVE,
        ),
        (
            ControlPlaneCrashPoint.AFTER_EXECUTION_APPLY,
            ControlPlaneChangeStatus.PREPARED,
            2,
            ExecutionAuthorizationReason.ALLOWED,
        ),
        (
            ControlPlaneCrashPoint.AFTER_MARK_APPLIED,
            ControlPlaneChangeStatus.APPLIED,
            2,
            ExecutionAuthorizationReason.ALLOWED,
        ),
    ],
)
def test_recovery_is_idempotent_across_all_committed_crash_points(
    tmp_path: Path,
    crash_point: ControlPlaneCrashPoint,
    expected_status: ControlPlaneChangeStatus,
    expected_execution_generation: int,
    expected_reason: ExecutionAuthorizationReason,
) -> None:
    root = tmp_path / crash_point.value
    root.mkdir()
    case, generation_store, coordinator, mutation = _subject_case(root)
    outbox = RevalidatingEffectOutboxStore(case["state_db"])
    record = outbox.get(case["approval_id"])

    with pytest.raises(SyntheticControlPlaneCrash) as exc_info:
        coordinator.commit(
            change_id=f"change-{crash_point.value}",
            mutation=mutation,
            crash_at=crash_point,
        )
    assert exc_info.value.point is crash_point
    pending = coordinator.pending_change()
    assert pending is not None
    assert pending.status is expected_status
    assert generation_store.current(coordinator.authority_id) == 1
    assert coordinator.execution_state().applied_generation == expected_execution_generation
    assert case["authoritative_authorization"].evaluate(record) is expected_reason

    recovered = coordinator.recover()
    assert recovered is not None
    assert recovered.status is ControlPlaneChangeStatus.ACTIVE
    assert recovered.target_generation == 2
    assert coordinator.pending_change() is None
    assert coordinator.execution_state().applied_generation == 2
    assert coordinator.current_active_generation() == 2
    assert case["authoritative_authorization"].evaluate(record) is ExecutionAuthorizationReason.ALLOWED

    assert coordinator.recover() is None
    assert coordinator.current_active_generation() == 2


def test_signing_key_rotation_is_applied_with_execution_generation_marker(tmp_path: Path) -> None:
    case = _create_case(
        tmp_path,
        action=ApprovalAction.REQUEST_PASSWORD_RESET,
        arguments={"reason": "P2-Q signing-key transaction test"},
    )
    key_fixture = _key_fixture()
    key1, key2 = key_fixture["keys"]
    registry = TrustedAuthorizationKeyStore(case["effect_db"])
    _trust_initial(registry, key_fixture, key1)
    fixture = _recovery_fixture()
    generation_store = ControlPlaneGenerationStore(tmp_path / "anchor.sqlite3")
    coordinator = CrashSafeControlPlaneCoordinator(
        execution_database_path=case["effect_db"],
        generation_store=generation_store,
        authority_id=str(fixture["authority_id"]),
    )
    coordinator.initialize(generation=1)
    key2_signer = _signer(key_fixture, key2)
    mutation = ControlPlaneMutation(
        kind=ControlPlaneMutationKind.SIGNING_KEY_ROTATION,
        issuer_id=str(key_fixture["issuer_id"]),
        audience=str(key_fixture["audience"]),
        key_id=str(key2["key_id"]),
        key_epoch=int(key2["key_epoch"]),
        public_key_hex=key2_signer.public_key_bytes().hex(),
    )

    with pytest.raises(SyntheticControlPlaneCrash):
        coordinator.commit(
            change_id="change-key-rotation",
            mutation=mutation,
            crash_at=ControlPlaneCrashPoint.AFTER_EXECUTION_APPLY,
        )
    assert coordinator.execution_state().applied_generation == 2
    assert generation_store.current(coordinator.authority_id) == 1
    assert registry.current_epoch(
        issuer_id=str(key_fixture["issuer_id"]),
        audience=str(key_fixture["audience"]),
    ) == 2

    coordinator.recover()
    assert coordinator.current_active_generation() == 2
