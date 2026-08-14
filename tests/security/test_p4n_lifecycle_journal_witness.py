from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from aegis.agent.checkpoint_external_contracts import (
    build_synthetic_external_checkpoint_contract_bundle,
)
from aegis.agent.checkpoint_external_lifecycle import (
    SyntheticExternalStyleCheckpointLifecycleProvider,
)
from aegis.agent.checkpoint_external_runtime_bridge import (
    SyntheticExternalCheckpointAnchorRuntimeBridge,
)
from aegis.agent.checkpoint_lifecycle_fencing import CheckpointLifecycleCommandOperation
from aegis.agent.checkpoint_lifecycle_journal import (
    CheckpointLifecycleJournalError,
    CheckpointLifecycleJournalFaultMode,
    CheckpointLifecycleJournalReason,
)
from aegis.agent.checkpoint_lifecycle_journal_witness import (
    P4N_LIFECYCLE_JOURNAL_WITNESS_POLICY_VERSION,
    CheckpointLifecycleJournalWitnessError,
    CheckpointLifecycleJournalWitnessFaultMode,
    CheckpointLifecycleJournalWitnessReason,
    WitnessedDurableSyntheticCheckpointLifecycleCoordinator,
)
from aegis.agent.checkpoint_operation_runtime import OperationProviderKeyLifecycleCheckpointer
from evals.p4e_backup_common import put
from evals.p4m_lifecycle_fixture import (
    build_p4m_legacy_fixture_key_provider,
    build_p4m_migration_fixture_key_provider,
)
from evals.p4n_lifecycle_journal_witness import build_report


EXPECTED_DATASET_HASH = "d9b50e2524950aa6e253df58600e2823960434a0a87e14543743457b5f655f6b"


def _make(root: Path, name: str, *, legacy_seed: bool = False):
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    bridge = SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor)
    lifecycle = SyntheticExternalStyleCheckpointLifecycleProvider(anchor_provider=bridge)
    runtime_root = root / name
    database_path = runtime_root / "checkpoints.sqlite3"
    compatibility_anchor = runtime_root / "compatibility-anchor.sqlite3"
    if legacy_seed:
        legacy_saver = OperationProviderKeyLifecycleCheckpointer(
            database_path=database_path,
            anchor_database_path=compatibility_anchor,
            key_provider=build_p4m_legacy_fixture_key_provider(),
            integrity_provider=bundle.integrity,
            anchor_provider=bridge,
            lifecycle_provider=lifecycle,
        )
        put(
            legacy_saver,
            thread_id=f"{name}-thread",
            checkpoint_id="00000001",
            marker=f"{name}-legacy-state",
        )
        key_provider = build_p4m_migration_fixture_key_provider()
    else:
        key_provider = bundle.encryption
    saver = OperationProviderKeyLifecycleCheckpointer(
        database_path=database_path,
        anchor_database_path=compatibility_anchor,
        key_provider=key_provider,
        integrity_provider=bundle.integrity,
        anchor_provider=bridge,
        lifecycle_provider=lifecycle,
    )
    if not legacy_seed:
        put(
            saver,
            thread_id=f"{name}-thread",
            checkpoint_id="00000001",
            marker=f"{name}-state",
        )
    journal_path = runtime_root / "lifecycle-journal.sqlite3"
    witness_path = runtime_root / "lifecycle-journal.witness.json"
    coordinator = WitnessedDurableSyntheticCheckpointLifecycleCoordinator(
        lifecycle_provider=lifecycle,
        journal_path=journal_path,
        witness_path=witness_path,
    )
    return saver, lifecycle, journal_path, witness_path, coordinator


def _reopen(lifecycle, journal_path: Path, witness_path: Path):
    return WitnessedDurableSyntheticCheckpointLifecycleCoordinator(
        lifecycle_provider=lifecycle,
        journal_path=journal_path,
        witness_path=witness_path,
    )


def _command(coordinator, saver, suffix: str):
    return coordinator.issue_command(
        command_id=f"p4n-test-{suffix}",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id=f"migration:{suffix}",
        saver=saver,
    )


def test_p4n_witness_is_separate_local_artifact_without_production_claim(tmp_path: Path) -> None:
    _, _, journal_path, witness_path, coordinator = _make(tmp_path, "posture")
    posture = coordinator.public_posture()
    assert journal_path.exists()
    assert witness_path.exists()
    assert journal_path != witness_path
    assert coordinator.witness_integrity_key_path != coordinator.journal.integrity_key_path
    assert posture["policy_version"] == P4N_LIFECYCLE_JOURNAL_WITNESS_POLICY_VERSION
    assert posture["durable_local_witness"] is True
    assert posture["independent_local_artifact"] is True
    assert posture["independent_failure_domain"] is False
    assert posture["rollback_resistant_journal"] is False
    assert posture["journal_and_witness_joint_rollback_detectable"] is False
    assert posture["network_operations"] == 0
    assert posture["production_checkpoint_lifecycle_claim"] is False


def test_p4n_committed_receipt_and_witness_survive_reopen(tmp_path: Path) -> None:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(tmp_path, "reopen")
    command = _command(coordinator, saver, "reopen")
    receipt = coordinator.execute(command, saver)
    generation = coordinator.witness_generation
    reopened = _reopen(lifecycle, journal_path, witness_path)
    replay = reopened.execute(command, saver)
    assert generation >= 2
    assert reopened.witness_generation == generation
    assert replay.replayed is True
    assert replay.command_digest == receipt.command_digest
    assert reopened.highest_committed_fence == command.fence_token
    assert lifecycle.migration_calls == 1


def test_p4n_authentic_journal_generation_rollback_rejected(tmp_path: Path) -> None:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(tmp_path, "rollback")
    old_journal = tmp_path / "old-journal.sqlite3"
    shutil.copy2(journal_path, old_journal)
    command = _command(coordinator, saver, "rollback")
    coordinator.execute(command, saver)
    shutil.copy2(old_journal, journal_path)
    with pytest.raises(CheckpointLifecycleJournalWitnessError) as raised:
        _reopen(lifecycle, journal_path, witness_path)
    assert raised.value.reason is CheckpointLifecycleJournalWitnessReason.JOURNAL_ROLLBACK_DETECTED


def test_p4n_same_fence_command_state_regression_rejected(tmp_path: Path) -> None:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(tmp_path, "state")
    command = _command(coordinator, saver, "state")
    prepared_journal = tmp_path / "prepared.sqlite3"
    shutil.copy2(journal_path, prepared_journal)
    coordinator.execute(command, saver)
    shutil.copy2(prepared_journal, journal_path)
    with pytest.raises(CheckpointLifecycleJournalWitnessError) as raised:
        _reopen(lifecycle, journal_path, witness_path)
    assert raised.value.reason is CheckpointLifecycleJournalWitnessReason.JOURNAL_ROLLBACK_DETECTED


def test_p4n_journal_and_p4m_integrity_key_pair_rollback_rejected(tmp_path: Path) -> None:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(tmp_path, "pair")
    journal_key = coordinator.journal.integrity_key_path
    old_journal = tmp_path / "old-pair-journal.sqlite3"
    old_key = tmp_path / "old-pair-key.bin"
    shutil.copy2(journal_path, old_journal)
    shutil.copy2(journal_key, old_key)
    command = _command(coordinator, saver, "pair")
    coordinator.execute(command, saver)
    shutil.copy2(old_journal, journal_path)
    shutil.copy2(old_key, journal_key)
    with pytest.raises(CheckpointLifecycleJournalWitnessError) as raised:
        _reopen(lifecycle, journal_path, witness_path)
    assert raised.value.reason is CheckpointLifecycleJournalWitnessReason.JOURNAL_ROLLBACK_DETECTED


def test_p4n_witness_tamper_and_missing_witness_fail_closed(tmp_path: Path) -> None:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(tmp_path, "tamper")
    command = _command(coordinator, saver, "tamper")
    coordinator.execute(command, saver)
    original = witness_path.read_bytes()
    payload = json.loads(original.decode("utf-8"))
    payload["witness_generation"] = int(payload["witness_generation"]) + 1
    witness_path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    with pytest.raises(CheckpointLifecycleJournalWitnessError) as tampered:
        _reopen(lifecycle, journal_path, witness_path)
    assert tampered.value.reason is CheckpointLifecycleJournalWitnessReason.WITNESS_INTEGRITY_FAILED

    witness_path.write_bytes(original)
    witness_path.unlink()
    with pytest.raises(CheckpointLifecycleJournalWitnessError) as missing:
        _reopen(lifecycle, journal_path, witness_path)
    assert (
        missing.value.reason
        is CheckpointLifecycleJournalWitnessReason.WITNESS_MISSING_FOR_EXISTING_JOURNAL
    )


def test_p4n_crash_after_journal_before_witness_auto_advances_only_forward(tmp_path: Path) -> None:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(tmp_path, "crash")
    command = _command(coordinator, saver, "crash")
    generation_before = coordinator.witness_generation
    coordinator.arm_fault(
        CheckpointLifecycleJournalWitnessFaultMode.AFTER_JOURNAL_BEFORE_WITNESS
    )
    with pytest.raises(CheckpointLifecycleJournalWitnessError) as crashed:
        coordinator.execute(command, saver)
    assert crashed.value.reason is CheckpointLifecycleJournalWitnessReason.SYNTHETIC_CRASH
    assert lifecycle.migration_calls == 1

    reopened = _reopen(lifecycle, journal_path, witness_path)
    assert reopened.witness_forward_advances == 1
    assert reopened.witness_generation > generation_before
    replay = reopened.execute(command, saver)
    assert replay.replayed is True
    assert lifecycle.migration_calls == 1


def test_p4n_preserves_p4m_ambiguous_migration_reconciliation(tmp_path: Path) -> None:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(
        tmp_path,
        "reconcile",
        legacy_seed=True,
    )
    command = _command(coordinator, saver, "reconcile")
    coordinator.journal.arm_fault(CheckpointLifecycleJournalFaultMode.AFTER_PROVIDER_BEFORE_COMMIT)
    with pytest.raises(CheckpointLifecycleJournalError) as crashed:
        coordinator.execute(command, saver)
    assert crashed.value.reason is CheckpointLifecycleJournalReason.SYNTHETIC_CRASH
    assert lifecycle.migration_calls == 1

    reopened = _reopen(lifecycle, journal_path, witness_path)
    with pytest.raises(CheckpointLifecycleJournalError) as blocked:
        reopened.execute(command, saver)
    assert blocked.value.reason is CheckpointLifecycleJournalReason.RECONCILIATION_REQUIRED
    receipt = reopened.reconcile(command, saver)
    assert receipt.replayed is True
    assert lifecycle.migration_calls == 1
    assert reopened.highest_committed_fence == 1


def test_p4n_eval_exact_hash_metrics_and_claims() -> None:
    report = build_report()
    hardened = report["variants"]["independently_witnessed_local_journal"]
    baseline = report["variants"]["journal_only_authenticated_baseline"]
    assert report["eval_dataset_hash_sha256"] == EXPECTED_DATASET_HASH
    assert baseline["metrics"]["asr"] == [5, 5]
    assert hardened["metrics"]["asr"] == [0, 5]
    assert hardened["metrics"]["fpr"] == [0, 3]
    assert hardened["metrics"]["safe_task_rate"] == [3, 3]
    assert report["journal_only_rollback_detected"] is True
    assert report["same_fence_state_regression_detected"] is True
    assert report["journal_and_p4m_key_pair_rollback_detected"] is True
    assert report["witness_integrity_tamper_rejected"] is True
    assert report["missing_witness_for_existing_history_rejected"] is True
    assert report["monotonic_forward_witness_recovery_after_crash"] is True
    assert report["p4m_fail_closed_reconciliation_preserved"] is True
    assert report["joint_journal_and_witness_rollback_detectable"] is False
    assert report["journal_rollback_resistance_claim"] is False
    assert report["distributed_fencing_claim"] is False
    assert report["exactly_once_claim"] is False
    assert report["network_operations"] == 0
    assert report["real_external_trust_operations"] is False
    assert report["production_checkpoint_lifecycle_claim"] is False
    assert report["passed"] is True
