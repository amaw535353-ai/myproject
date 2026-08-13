from pathlib import Path

import pytest

from aegis.approvals.models import ApprovalAction
from aegis.effects.control_plane_recovery import (
    ControlPlaneMutation,
    ControlPlaneMutationKind,
    CrashSafeControlPlaneCoordinator,
)
from aegis.effects.protected_checkpoint import (
    ExternallyCheckpointedControlPlaneCoordinator,
    ProtectedCheckpointCrashPoint,
    ProtectedCheckpointError,
    ProtectedCheckpointReason,
    SyntheticProtectedCheckpointAuthority,
    SyntheticProtectedCheckpointCrash,
    genesis_journal_head,
)
from aegis.effects.rollback_anchor import ControlPlaneGenerationStore
from evals.p2n_authorization_freshness import _create_case
from evals.p2r_protected_checkpoint import _checkpoint_fixture


def _stack(root: Path):
    case = _create_case(
        root,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments={"resource": "synthetic-vpn", "justification": "P2-R checkpoint test"},
    )
    fixture = _checkpoint_fixture()
    generation_store = ControlPlaneGenerationStore(root / "anchor.sqlite3")
    local = CrashSafeControlPlaneCoordinator(
        execution_database_path=case["effect_db"],
        generation_store=generation_store,
        authority_id=str(fixture["authority_id"]),
    )
    checkpoint = SyntheticProtectedCheckpointAuthority(root / "protected.sqlite3")
    protected = ExternallyCheckpointedControlPlaneCoordinator(
        local_coordinator=local,
        checkpoint_authority=checkpoint,
    )
    protected.initialize(generation=1)
    mutation = ControlPlaneMutation(
        kind=ControlPlaneMutationKind.SUBJECT_ACTIVE,
        tenant_id="tenant_northstar_dynamics",
        user_id="usr_dyn_alice",
        active=False,
    )
    return case, generation_store, local, checkpoint, protected, mutation


def test_checkpoint_compare_and_swap_is_monotonic(tmp_path: Path) -> None:
    authority_id = "synthetic-p2r-authority"
    checkpoint = SyntheticProtectedCheckpointAuthority(tmp_path / "protected.sqlite3")
    genesis = genesis_journal_head(authority_id)
    assert checkpoint.initialize(
        authority_id=authority_id,
        generation=1,
        journal_head_sha256=genesis,
    ).generation == 1

    with pytest.raises(ValueError):
        checkpoint.advance(
            authority_id=authority_id,
            expected_generation=1,
            expected_journal_head_sha256=genesis,
            target_generation=3,
            target_journal_head_sha256="1" * 64,
        )

    with pytest.raises(ProtectedCheckpointError) as exc_info:
        checkpoint.advance(
            authority_id=authority_id,
            expected_generation=1,
            expected_journal_head_sha256="f" * 64,
            target_generation=2,
            target_journal_head_sha256="1" * 64,
        )
    assert exc_info.value.reason is ProtectedCheckpointReason.CHECKPOINT_CONFLICT
    assert checkpoint.current(authority_id).generation == 1


def test_local_activation_waits_for_checkpoint_before_becoming_usable(tmp_path: Path) -> None:
    _, _, local, checkpoint, protected, mutation = _stack(tmp_path)
    with pytest.raises(SyntheticProtectedCheckpointCrash) as exc_info:
        protected.commit(
            change_id="p2r-checkpoint-sync",
            mutation=mutation,
            crash_at=ProtectedCheckpointCrashPoint.AFTER_LOCAL_ACTIVATION,
        )
    assert exc_info.value.point is ProtectedCheckpointCrashPoint.AFTER_LOCAL_ACTIVATION
    assert local.current_active_generation() == 2
    assert checkpoint.current(local.authority_id).generation == 1

    with pytest.raises(ProtectedCheckpointError) as mismatch:
        protected.current_active_generation()
    assert mismatch.value.reason is ProtectedCheckpointReason.CHECKPOINT_BEHIND

    assert protected.recover() is None
    assert checkpoint.current(local.authority_id).generation == 2
    assert protected.current_active_generation() == 2


def test_journal_integrity_is_bound_to_checkpoint(tmp_path: Path) -> None:
    _, generation_store, local, checkpoint, protected, mutation = _stack(tmp_path)
    protected.commit(change_id="p2r-journal-integrity", mutation=mutation)
    assert protected.current_active_generation() == 2
    assert checkpoint.current(local.authority_id).generation == 2

    with generation_store._connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            UPDATE control_plane_changes
            SET mutation_sha256 = ?
            WHERE authority_id = ? AND change_id = ?
            """,
            ("0" * 64, local.authority_id, "p2r-journal-integrity"),
        )

    assert local.current_active_generation() == 2
    with pytest.raises(ProtectedCheckpointError) as exc_info:
        protected.current_active_generation()
    assert exc_info.value.reason is ProtectedCheckpointReason.JOURNAL_CHAIN_INVALID


def test_checkpoint_path_must_be_distinct_from_local_state(tmp_path: Path) -> None:
    case = _create_case(
        tmp_path,
        action=ApprovalAction.REQUEST_PASSWORD_RESET,
        arguments={"reason": "P2-R path isolation"},
    )
    fixture = _checkpoint_fixture()
    generation_store = ControlPlaneGenerationStore(tmp_path / "anchor.sqlite3")
    local = CrashSafeControlPlaneCoordinator(
        execution_database_path=case["effect_db"],
        generation_store=generation_store,
        authority_id=str(fixture["authority_id"]),
    )

    with pytest.raises(ValueError):
        ExternallyCheckpointedControlPlaneCoordinator(
            local_coordinator=local,
            checkpoint_authority=SyntheticProtectedCheckpointAuthority(case["effect_db"]),
        )
    with pytest.raises(ValueError):
        ExternallyCheckpointedControlPlaneCoordinator(
            local_coordinator=local,
            checkpoint_authority=SyntheticProtectedCheckpointAuthority(generation_store.database_path),
        )
