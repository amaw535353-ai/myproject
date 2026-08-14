from __future__ import annotations

import sqlite3

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
from aegis.agent.checkpoint_keys import build_legacy_single_key_provider
from aegis.agent.checkpoint_lifecycle_fencing import (
    CheckpointLifecycleCommandOperation,
)
from aegis.agent.checkpoint_lifecycle_journal import (
    P4M_DURABLE_LIFECYCLE_JOURNAL_POLICY_VERSION,
    CheckpointLifecycleJournalError,
    CheckpointLifecycleJournalFaultMode,
    CheckpointLifecycleJournalReason,
    DurableSyntheticCheckpointLifecycleCoordinator,
)
from aegis.agent.checkpoint_operation_runtime import (
    OperationProviderKeyLifecycleCheckpointer,
)
from evals.p4e_backup_common import marker, put
from evals.p4m_durable_lifecycle_journal import build_report


def _runtime(tmp_path, name: str, *, legacy_seed: bool = False):
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    bridge = SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor)
    lifecycle = SyntheticExternalStyleCheckpointLifecycleProvider(anchor_provider=bridge)
    root = tmp_path / name
    database_path = root / "checkpoints.sqlite3"
    compatibility_anchor = root / "compatibility-anchor.sqlite3"

    if legacy_seed:
        legacy_saver = OperationProviderKeyLifecycleCheckpointer(
            database_path=database_path,
            anchor_database_path=compatibility_anchor,
            key_provider=build_legacy_single_key_provider(),
            integrity_provider=bundle.integrity,
            anchor_provider=bridge,
            lifecycle_provider=lifecycle,
        )
        put(
            legacy_saver,
            thread_id=f"{name}-thread",
            checkpoint_id="00000001",
            marker=f"{name}-state",
        )

    saver = OperationProviderKeyLifecycleCheckpointer(
        database_path=database_path,
        anchor_database_path=compatibility_anchor,
        key_provider=bundle.encryption,
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

    journal_path = root / "lifecycle-journal.sqlite3"
    coordinator = DurableSyntheticCheckpointLifecycleCoordinator(
        lifecycle_provider=lifecycle,
        journal_path=journal_path,
    )
    return saver, lifecycle, journal_path, coordinator


def _reopen(lifecycle, journal_path):
    return DurableSyntheticCheckpointLifecycleCoordinator(
        lifecycle_provider=lifecycle,
        journal_path=journal_path,
    )


def test_committed_receipt_and_fence_survive_reopen_without_provider_reinvocation(tmp_path) -> None:
    saver, lifecycle, journal_path, coordinator = _runtime(tmp_path, "receipt")
    command = coordinator.issue_command(
        command_id="p4m-receipt",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:receipt",
        saver=saver,
    )
    first = coordinator.execute(command, saver)
    assert first.replayed is False
    assert lifecycle.migration_calls == 1
    assert coordinator.highest_committed_fence == 1

    reopened = _reopen(lifecycle, journal_path)
    assert reopened.highest_issued_fence == 1
    assert reopened.highest_committed_fence == 1
    replay = reopened.execute(command, saver)
    assert replay.replayed is True
    assert replay.command_digest == first.command_digest
    assert lifecycle.migration_calls == 1
    assert reopened.receipt_count == 1


def test_pre_provider_crash_reopens_as_prepared_and_allows_safe_retry(tmp_path) -> None:
    saver, lifecycle, journal_path, coordinator = _runtime(tmp_path, "pre-crash")
    command = coordinator.issue_command(
        command_id="p4m-pre-crash",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:pre-crash",
        saver=saver,
    )
    coordinator.arm_fault(
        CheckpointLifecycleJournalFaultMode.AFTER_PREPARED_BEFORE_PROVIDER
    )
    with pytest.raises(CheckpointLifecycleJournalError) as raised:
        coordinator.execute(command, saver)
    assert raised.value.reason is CheckpointLifecycleJournalReason.SYNTHETIC_CRASH
    assert lifecycle.migration_calls == 0

    reopened = _reopen(lifecycle, journal_path)
    receipt = reopened.execute(command, saver)
    assert receipt.replayed is False
    assert lifecycle.migration_calls == 1
    assert reopened.highest_committed_fence == 1


def test_post_provider_crash_requires_reconciliation_and_proves_legacy_migration(tmp_path) -> None:
    saver, lifecycle, journal_path, coordinator = _runtime(
        tmp_path,
        "post-crash",
        legacy_seed=True,
    )
    command = coordinator.issue_command(
        command_id="p4m-post-crash",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:post-crash",
        saver=saver,
    )
    coordinator.arm_fault(
        CheckpointLifecycleJournalFaultMode.AFTER_PROVIDER_BEFORE_COMMIT
    )
    with pytest.raises(CheckpointLifecycleJournalError) as raised:
        coordinator.execute(command, saver)
    assert raised.value.reason is CheckpointLifecycleJournalReason.SYNTHETIC_CRASH
    assert lifecycle.migration_calls == 1
    assert marker(saver, "post-crash-thread") == "post-crash-state"

    reopened = _reopen(lifecycle, journal_path)
    with pytest.raises(CheckpointLifecycleJournalError) as blocked:
        reopened.execute(command, saver)
    assert blocked.value.reason is CheckpointLifecycleJournalReason.RECONCILIATION_REQUIRED
    assert lifecycle.migration_calls == 1

    receipt = reopened.reconcile(command, saver)
    assert receipt.replayed is True
    assert reopened.reconciliations == 1
    assert reopened.highest_committed_fence == 1
    assert lifecycle.migration_calls == 1

    reopened_again = _reopen(lifecycle, journal_path)
    replay = reopened_again.execute(command, saver)
    assert replay.replayed is True
    assert lifecycle.migration_calls == 1


def test_stale_fence_and_command_id_conflict_remain_rejected_after_reopen(tmp_path) -> None:
    saver, lifecycle, journal_path, coordinator = _runtime(tmp_path, "stale")
    stale = coordinator.issue_command(
        command_id="p4m-stale",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:stale",
        saver=saver,
    )
    winner = coordinator.issue_command(
        command_id="p4m-winner",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:winner",
        saver=saver,
    )
    coordinator.execute(winner, saver)
    assert winner.fence_token == 2

    reopened = _reopen(lifecycle, journal_path)
    with pytest.raises(CheckpointLifecycleJournalError) as stale_raised:
        reopened.execute(stale, saver)
    assert stale_raised.value.reason is CheckpointLifecycleJournalReason.JOURNAL_FENCE_STALE

    with pytest.raises(CheckpointLifecycleJournalError) as conflict_raised:
        reopened.issue_command(
            command_id=winner.command_id,
            operation=winner.operation,
            resource_id="migration:changed-resource",
            saver=saver,
        )
    assert conflict_raised.value.reason is CheckpointLifecycleJournalReason.JOURNAL_COMMAND_CONFLICT
    assert lifecycle.migration_calls == 1


def test_journal_row_tamper_fails_closed_on_reopen(tmp_path) -> None:
    saver, lifecycle, journal_path, coordinator = _runtime(tmp_path, "tamper")
    coordinator.issue_command(
        command_id="p4m-tamper",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:tamper",
        saver=saver,
    )

    connection = sqlite3.connect(journal_path)
    try:
        connection.execute(
            "UPDATE lifecycle_commands SET resource_id = ? WHERE command_id = ?",
            ("migration:tampered", "p4m-tamper"),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(CheckpointLifecycleJournalError) as raised:
        _reopen(lifecycle, journal_path)
    assert raised.value.reason is CheckpointLifecycleJournalReason.JOURNAL_INTEGRITY_FAILED


def test_unprovable_ambiguous_provider_outcome_stays_fail_closed(tmp_path) -> None:
    saver, lifecycle, journal_path, coordinator = _runtime(tmp_path, "unprovable")
    command = coordinator.issue_command(
        command_id="p4m-unprovable",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:unprovable",
        saver=saver,
    )
    coordinator.arm_fault(
        CheckpointLifecycleJournalFaultMode.AFTER_PROVIDER_BEFORE_COMMIT
    )
    with pytest.raises(CheckpointLifecycleJournalError):
        coordinator.execute(command, saver)
    assert lifecycle.migration_calls == 1

    reopened = _reopen(lifecycle, journal_path)
    with pytest.raises(CheckpointLifecycleJournalError) as raised:
        reopened.reconcile(command, saver)
    assert raised.value.reason is CheckpointLifecycleJournalReason.RECONCILIATION_UNPROVABLE
    with pytest.raises(CheckpointLifecycleJournalError) as retry_raised:
        reopened.execute(command, saver)
    assert retry_raised.value.reason is CheckpointLifecycleJournalReason.RECONCILIATION_REQUIRED
    assert lifecycle.migration_calls == 1


def test_missing_integrity_key_for_existing_journal_fails_closed(tmp_path) -> None:
    saver, lifecycle, journal_path, coordinator = _runtime(tmp_path, "missing-key")
    coordinator.issue_command(
        command_id="p4m-missing-key",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:missing-key",
        saver=saver,
    )
    coordinator.integrity_key_path.unlink()

    with pytest.raises(CheckpointLifecycleJournalError) as raised:
        _reopen(lifecycle, journal_path)
    assert raised.value.reason is CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID


def test_p4m_evaluation_exact_metrics_and_evidence_hygiene() -> None:
    report = build_report()
    baseline = report["variants"]["volatile_lifecycle_receipt_baseline"]["metrics"]
    hardened = report["variants"]["durable_restart_verifiable_lifecycle_journal"]["metrics"]

    assert report["passed"] is True
    assert baseline["asr"] == [5, 5]
    assert hardened["asr"] == [0, 5]
    assert hardened["fpr"] == [0, 3]
    assert hardened["safe_task_rate"] == [3, 3]
    assert report["policy_version"] == P4M_DURABLE_LIFECYCLE_JOURNAL_POLICY_VERSION
    assert report["durable_journal_enabled"] is True
    assert report["durable_fence_survives_reopen"] is True
    assert report["durable_receipt_replay_survives_reopen"] is True
    assert report["ambiguous_reopen_does_not_blindly_reexecute"] is True
    assert report["journal_integrity_tamper_rejected"] is True
    assert report["reconciliation_unprovable_fails_closed"] is True
    assert report["journal_rollback_resistance_claim"] is False
    assert report["distributed_fencing_claim"] is False
    assert report["exactly_once_claim"] is False
    assert report["production_checkpoint_lifecycle_claim"] is False
    assert report["real_external_trust_operations"] is False
    assert report["network_operations"] == 0
