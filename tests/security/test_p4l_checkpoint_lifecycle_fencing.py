from __future__ import annotations

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
from aegis.agent.checkpoint_lifecycle_fencing import (
    P4L_CHECKPOINT_LIFECYCLE_FENCING_POLICY_VERSION,
    CheckpointLifecycleCommand,
    CheckpointLifecycleCommandOperation,
    CheckpointLifecycleFaultMode,
    CheckpointLifecycleFencingError,
    CheckpointLifecycleFencingReason,
    SyntheticFencedCheckpointLifecycleCoordinator,
)
from aegis.agent.checkpoint_operation_runtime import (
    OperationProviderKeyLifecycleCheckpointer,
)
from aegis.agent.checkpoint_runtime_contracts import encode_checkpoint_scope
from evals.p4e_backup_common import marker, put
from evals.p4l_checkpoint_lifecycle_fencing import build_report


def _saver(tmp_path, name: str):
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    bridge = SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor)
    lifecycle = SyntheticExternalStyleCheckpointLifecycleProvider(anchor_provider=bridge)
    root = tmp_path / name
    saver = OperationProviderKeyLifecycleCheckpointer(
        database_path=root / "checkpoints.sqlite3",
        anchor_database_path=root / "compatibility-anchor.sqlite3",
        key_provider=bundle.encryption,
        integrity_provider=bundle.integrity,
        anchor_provider=bridge,
        lifecycle_provider=lifecycle,
    )
    coordinator = SyntheticFencedCheckpointLifecycleCoordinator(
        lifecycle_provider=lifecycle
    )
    return saver, bridge, lifecycle, coordinator


def test_ambiguous_commit_retry_returns_receipt_without_duplicate_snapshot(tmp_path) -> None:
    saver, _, lifecycle, coordinator = _saver(tmp_path, "ambiguous")
    put(
        saver,
        thread_id="p4l-ambiguous",
        checkpoint_id="00000001",
        marker="ambiguous-state",
    )
    command = coordinator.issue_command(
        command_id="p4l-command-ambiguous",
        operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
        resource_id="snapshot:ambiguous",
    )
    checkpoint_snapshot = tmp_path / "ambiguous-checkpoints.sqlite3"
    anchor_snapshot = tmp_path / "ambiguous-anchors.sqlite3"
    coordinator.arm_fault(CheckpointLifecycleFaultMode.AMBIGUOUS_AFTER_COMMIT)

    with pytest.raises(CheckpointLifecycleFencingError) as raised:
        coordinator.execute(
            command,
            saver,
            checkpoint_destination=checkpoint_snapshot,
            anchor_destination=anchor_snapshot,
        )
    assert raised.value.reason is CheckpointLifecycleFencingReason.AMBIGUOUS_COMMIT_OUTCOME
    assert lifecycle.snapshot_calls == 1
    assert checkpoint_snapshot.exists() and anchor_snapshot.exists()
    assert coordinator.receipt_count == 1
    assert coordinator.highest_committed_fence == 1

    replay = coordinator.execute(
        command,
        saver,
        checkpoint_destination=checkpoint_snapshot,
        anchor_destination=anchor_snapshot,
    )
    assert replay.replayed is True
    assert lifecycle.snapshot_calls == 1
    assert coordinator.provider_invocations == 1
    assert coordinator.replay_hits == 1


def test_provider_unavailability_fails_before_lifecycle_mutation(tmp_path) -> None:
    saver, _, lifecycle, coordinator = _saver(tmp_path, "unavailable")
    put(
        saver,
        thread_id="p4l-unavailable",
        checkpoint_id="00000001",
        marker="unavailable-state",
    )
    before = coordinator.anchor_fingerprint()
    command = coordinator.issue_command(
        command_id="p4l-command-unavailable",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:unavailable",
    )
    coordinator.arm_fault(CheckpointLifecycleFaultMode.PROVIDER_UNAVAILABLE)

    with pytest.raises(CheckpointLifecycleFencingError) as raised:
        coordinator.execute(command, saver)

    assert raised.value.reason is CheckpointLifecycleFencingReason.PROVIDER_UNAVAILABLE
    assert coordinator.anchor_fingerprint() == before
    assert lifecycle.migration_calls == 0
    assert coordinator.provider_invocations == 0
    assert coordinator.receipt_count == 0


def test_stale_fence_and_conflicting_command_replay_fail_closed(tmp_path) -> None:
    saver, _, lifecycle, coordinator = _saver(tmp_path, "stale")
    put(
        saver,
        thread_id="p4l-stale",
        checkpoint_id="00000001",
        marker="stale-state",
    )
    command = coordinator.issue_command(
        command_id="p4l-command-one",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:one",
    )
    receipt = coordinator.execute(command, saver)
    assert receipt.fence_token == 1
    assert lifecycle.migration_calls == 1

    stale = CheckpointLifecycleCommand(
        command_id="p4l-command-stale",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        fence_token=1,
        expected_anchor_fingerprint=coordinator.anchor_fingerprint(),
        resource_id="migration:stale",
    )
    with pytest.raises(CheckpointLifecycleFencingError) as stale_raised:
        coordinator.execute(stale, saver)
    assert stale_raised.value.reason is CheckpointLifecycleFencingReason.STALE_FENCE

    conflict = CheckpointLifecycleCommand(
        command_id=command.command_id,
        operation=command.operation,
        fence_token=command.fence_token,
        expected_anchor_fingerprint=command.expected_anchor_fingerprint,
        resource_id="migration:conflicting-resource",
    )
    with pytest.raises(CheckpointLifecycleFencingError) as replay_raised:
        coordinator.execute(conflict, saver)
    assert replay_raised.value.reason is CheckpointLifecycleFencingReason.COMMAND_REPLAY_CONFLICT
    assert lifecycle.migration_calls == 1


def test_concurrent_anchor_progress_invalidates_preissued_command(tmp_path) -> None:
    saver, bridge, lifecycle, coordinator = _saver(tmp_path, "concurrent")
    put(
        saver,
        thread_id="p4l-concurrent",
        checkpoint_id="00000001",
        marker="concurrent-state",
    )
    command = coordinator.issue_command(
        command_id="p4l-command-concurrent",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:concurrent",
    )
    scope = encode_checkpoint_scope("p4l-external-writer", "")
    bridge.advance(
        scope,
        generation=1,
        checkpoint_id="external-0001",
        checkpoint_digest="a" * 64,
        expected_generation=None,
    )

    with pytest.raises(CheckpointLifecycleFencingError) as raised:
        coordinator.execute(command, saver)

    assert raised.value.reason is CheckpointLifecycleFencingReason.ANCHOR_FENCE_MISMATCH
    assert lifecycle.migration_calls == 0
    assert coordinator.provider_invocations == 0


def test_partial_anchor_progress_is_reconciled_and_same_command_can_retry(tmp_path) -> None:
    saver, _, lifecycle, coordinator = _saver(tmp_path, "partial")
    put(
        saver,
        thread_id="p4l-partial",
        checkpoint_id="00000001",
        marker="partial-state",
    )
    before = coordinator.anchor_fingerprint()
    command = coordinator.issue_command(
        command_id="p4l-command-partial",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:partial",
    )
    coordinator.arm_fault(CheckpointLifecycleFaultMode.PARTIAL_ANCHOR_PROGRESS)

    with pytest.raises(CheckpointLifecycleFencingError) as raised:
        coordinator.execute(command, saver)

    assert raised.value.reason is CheckpointLifecycleFencingReason.PARTIAL_PROGRESS_RECONCILED
    assert coordinator.anchor_fingerprint() == before
    assert coordinator.reconciliations == 1
    assert lifecycle.migration_calls == 0
    assert coordinator.receipt_count == 0

    receipt = coordinator.execute(command, saver)
    assert receipt.replayed is False
    assert lifecycle.migration_calls == 1
    assert coordinator.highest_committed_fence == 1
    assert marker(saver, "p4l-partial") == "partial-state"


def test_p4l_evaluation_exact_metrics_and_evidence_hygiene() -> None:
    report = build_report()
    baseline = report["variants"]["implicit_unfenced_lifecycle_baseline"]["metrics"]
    hardened = report["variants"]["fenced_failure_aware_lifecycle_harness"]["metrics"]

    assert report["passed"] is True
    assert baseline["asr"] == [5, 5]
    assert hardened["asr"] == [0, 5]
    assert hardened["fpr"] == [0, 3]
    assert hardened["safe_task_rate"] == [3, 3]
    assert report["policy_version"] == P4L_CHECKPOINT_LIFECYCLE_FENCING_POLICY_VERSION
    assert report["p4j_lifecycle_provider_exercised"] is True
    assert report["ambiguous_commit_replay_idempotent"] is True
    assert report["provider_unavailability_fails_before_mutation"] is True
    assert report["stale_and_conflicting_replays_rejected"] is True
    assert report["concurrent_anchor_fence_mismatch_rejected"] is True
    assert report["partial_anchor_progress_reconciled"] is True
    assert report["durable_distributed_fencing"] is False
    assert report["production_checkpoint_lifecycle_claim"] is False
    assert report["real_external_trust_operations"] is False
    assert report["network_operations"] == 0
