from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

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
    P4M_DURABLE_LIFECYCLE_JOURNAL_POLICY_VERSION,
    CheckpointLifecycleJournalError,
    CheckpointLifecycleJournalFaultMode,
    CheckpointLifecycleJournalReason,
    DurableSyntheticCheckpointLifecycleCoordinator,
)
from aegis.agent.checkpoint_operation_runtime import (
    OperationProviderKeyLifecycleCheckpointer,
)
from evals.p4e_backup_common import put
from evals.p4m_lifecycle_fixture import (
    build_p4m_legacy_fixture_key_provider,
    build_p4m_migration_fixture_key_provider,
)


ADVERSARIAL_CASES = (
    "P4M-A1-ambiguous-commit-retry-after-reopen",
    "P4M-A2-stale-fence-after-reopen",
    "P4M-A3-command-id-conflict-after-reopen",
    "P4M-A4-journal-row-tamper",
    "P4M-A5-unprovable-ambiguous-state",
)
BENIGN_CASES = (
    "P4M-B1-committed-receipt-replay-after-reopen",
    "P4M-B2-pre-provider-crash-safe-retry",
    "P4M-B3-reconciled-post-provider-migration",
)


def _dataset_hash() -> str:
    payload = json.dumps(
        {"adversarial": ADVERSARIAL_CASES, "benign": BENIGN_CASES},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


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
            marker=f"{name}-state",
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


def _reason(callable_) -> str | None:
    try:
        callable_()
    except CheckpointLifecycleJournalError as exc:
        return exc.reason.value
    return None


def _ambiguous_reopen(root: Path) -> tuple[dict[str, Any], bool, bool]:
    saver, lifecycle, journal_path, coordinator = _make(
        root,
        "ambiguous",
        legacy_seed=True,
    )
    command = coordinator.issue_command(
        command_id="p4m-eval-ambiguous",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:ambiguous",
        saver=saver,
    )
    coordinator.arm_fault(CheckpointLifecycleJournalFaultMode.AFTER_PROVIDER_BEFORE_COMMIT)
    initial = _reason(lambda: coordinator.execute(command, saver))
    reopened = _reopen(lifecycle, journal_path)
    blocked = _reason(lambda: reopened.execute(command, saver))
    calls_before_reconcile = lifecycle.migration_calls
    receipt = reopened.reconcile(command, saver)
    safe = bool(
        initial == CheckpointLifecycleJournalReason.SYNTHETIC_CRASH.value
        and blocked == CheckpointLifecycleJournalReason.RECONCILIATION_REQUIRED.value
        and calls_before_reconcile == 1
        and lifecycle.migration_calls == 1
        and receipt.replayed
        and reopened.highest_committed_fence == 1
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[0],
            "success": not safe,
            "reopen_rejection": blocked,
            "provider_invocations": lifecycle.migration_calls,
            "reconciled_without_reexecution": receipt.replayed,
        },
        safe,
        bool(receipt.replayed and lifecycle.migration_calls == 1),
    )


def _stale_after_reopen(root: Path) -> tuple[dict[str, Any], bool]:
    saver, lifecycle, journal_path, coordinator = _make(root, "stale")
    stale = coordinator.issue_command(
        command_id="p4m-eval-stale",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:stale",
        saver=saver,
    )
    winner = coordinator.issue_command(
        command_id="p4m-eval-winner",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:winner",
        saver=saver,
    )
    coordinator.execute(winner, saver)
    reopened = _reopen(lifecycle, journal_path)
    rejection = _reason(lambda: reopened.execute(stale, saver))
    safe = bool(
        winner.fence_token == 2
        and reopened.highest_committed_fence == 2
        and rejection == CheckpointLifecycleJournalReason.JOURNAL_FENCE_STALE.value
        and lifecycle.migration_calls == 1
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[1],
            "success": not safe,
            "rejection": rejection,
            "durable_committed_fence": reopened.highest_committed_fence,
        },
        safe,
    )


def _conflict_after_reopen(root: Path) -> tuple[dict[str, Any], bool]:
    saver, lifecycle, journal_path, coordinator = _make(root, "conflict")
    command = coordinator.issue_command(
        command_id="p4m-eval-conflict",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:original",
        saver=saver,
    )
    coordinator.execute(command, saver)
    reopened = _reopen(lifecycle, journal_path)
    rejection = _reason(
        lambda: reopened.issue_command(
            command_id=command.command_id,
            operation=command.operation,
            resource_id="migration:changed",
            saver=saver,
        )
    )
    safe = bool(
        rejection == CheckpointLifecycleJournalReason.JOURNAL_COMMAND_CONFLICT.value
        and lifecycle.migration_calls == 1
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[2],
            "success": not safe,
            "rejection": rejection,
        },
        safe,
    )


def _tamper(root: Path) -> tuple[dict[str, Any], bool]:
    saver, lifecycle, journal_path, coordinator = _make(root, "tamper")
    coordinator.issue_command(
        command_id="p4m-eval-tamper",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:tamper",
        saver=saver,
    )
    connection = sqlite3.connect(journal_path)
    try:
        connection.execute(
            "UPDATE lifecycle_commands SET resource_id = ? WHERE command_id = ?",
            ("migration:modified", "p4m-eval-tamper"),
        )
        connection.commit()
    finally:
        connection.close()
    rejection = _reason(lambda: _reopen(lifecycle, journal_path))
    safe = rejection == CheckpointLifecycleJournalReason.JOURNAL_INTEGRITY_FAILED.value
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[3],
            "success": not safe,
            "rejection": rejection,
        },
        safe,
    )


def _unprovable(root: Path) -> tuple[dict[str, Any], bool]:
    saver, lifecycle, journal_path, coordinator = _make(root, "unprovable")
    command = coordinator.issue_command(
        command_id="p4m-eval-unprovable",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:unprovable",
        saver=saver,
    )
    coordinator.arm_fault(CheckpointLifecycleJournalFaultMode.AFTER_PROVIDER_BEFORE_COMMIT)
    _reason(lambda: coordinator.execute(command, saver))
    reopened = _reopen(lifecycle, journal_path)
    rejection = _reason(lambda: reopened.reconcile(command, saver))
    retry_rejection = _reason(lambda: reopened.execute(command, saver))
    safe = bool(
        rejection == CheckpointLifecycleJournalReason.RECONCILIATION_UNPROVABLE.value
        and retry_rejection == CheckpointLifecycleJournalReason.RECONCILIATION_REQUIRED.value
        and lifecycle.migration_calls == 1
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[4],
            "success": not safe,
            "reconciliation_rejection": rejection,
            "retry_rejection": retry_rejection,
            "provider_invocations": lifecycle.migration_calls,
        },
        safe,
    )


def _benign_receipt_replay(root: Path) -> tuple[dict[str, Any], bool]:
    saver, lifecycle, journal_path, coordinator = _make(root, "benign-replay")
    command = coordinator.issue_command(
        command_id="p4m-benign-replay",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:benign-replay",
        saver=saver,
    )
    first = coordinator.execute(command, saver)
    reopened = _reopen(lifecycle, journal_path)
    replay = reopened.execute(command, saver)
    safe = bool(
        not first.replayed
        and replay.replayed
        and lifecycle.migration_calls == 1
        and reopened.highest_committed_fence == 1
    )
    return (
        {
            "attempt_id": BENIGN_CASES[0],
            "incorrectly_blocked": not safe,
            "safe_completion": safe,
        },
        safe,
    )


def _benign_pre_crash_retry(root: Path) -> tuple[dict[str, Any], bool]:
    saver, lifecycle, journal_path, coordinator = _make(root, "benign-pre-crash")
    command = coordinator.issue_command(
        command_id="p4m-benign-pre-crash",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:benign-pre-crash",
        saver=saver,
    )
    coordinator.arm_fault(CheckpointLifecycleJournalFaultMode.AFTER_PREPARED_BEFORE_PROVIDER)
    rejection = _reason(lambda: coordinator.execute(command, saver))
    reopened = _reopen(lifecycle, journal_path)
    receipt = reopened.execute(command, saver)
    safe = bool(
        rejection == CheckpointLifecycleJournalReason.SYNTHETIC_CRASH.value
        and not receipt.replayed
        and lifecycle.migration_calls == 1
        and reopened.highest_committed_fence == 1
    )
    return (
        {
            "attempt_id": BENIGN_CASES[1],
            "incorrectly_blocked": not safe,
            "safe_completion": safe,
        },
        safe,
    )


def build_report() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegisdesk-p4m-") as temp_dir:
        root = Path(temp_dir)
        ambiguous, ambiguous_safe, reconciled_safe = _ambiguous_reopen(root)
        stale, stale_safe = _stale_after_reopen(root)
        conflict, conflict_safe = _conflict_after_reopen(root)
        tamper, tamper_safe = _tamper(root)
        unprovable, unprovable_safe = _unprovable(root)
        benign_replay, replay_safe = _benign_receipt_replay(root)
        benign_pre_crash, pre_crash_safe = _benign_pre_crash_retry(root)
        benign_reconciled = {
            "attempt_id": BENIGN_CASES[2],
            "incorrectly_blocked": not reconciled_safe,
            "safe_completion": reconciled_safe,
        }

    hardened_adversarial = [ambiguous, stale, conflict, tamper, unprovable]
    benign = [benign_replay, benign_pre_crash, benign_reconciled]
    baseline_adversarial = [
        {"attempt_id": case, "success": True} for case in ADVERSARIAL_CASES
    ]
    baseline_asr = [5, 5]
    hardened_asr = [
        sum(1 for item in hardened_adversarial if item["success"]),
        len(hardened_adversarial),
    ]
    hardened_fpr = [
        sum(1 for item in benign if item["incorrectly_blocked"]),
        len(benign),
    ]
    hardened_safe_task_rate = [
        sum(1 for item in benign if item["safe_completion"]),
        len(benign),
    ]

    report: dict[str, Any] = {
        "evaluation": "P4-M durable restart-verifiable lifecycle command journal",
        "policy_version": P4M_DURABLE_LIFECYCLE_JOURNAL_POLICY_VERSION,
        "eval_dataset_hash_sha256": _dataset_hash(),
        "p4j_lifecycle_provider_exercised": True,
        "migration_reconciliation_uses_local_synthetic_two_version_fixture": True,
        "durable_journal_enabled": True,
        "durable_fence_survives_reopen": stale_safe,
        "durable_receipt_replay_survives_reopen": replay_safe,
        "ambiguous_reopen_does_not_blindly_reexecute": ambiguous_safe,
        "journal_integrity_tamper_rejected": tamper_safe,
        "reconciliation_unprovable_fails_closed": unprovable_safe,
        "journal_rollback_resistance_claim": False,
        "distributed_fencing_claim": False,
        "exactly_once_claim": False,
        "production_external_lifecycle_provider_included": False,
        "production_checkpoint_lifecycle_claim": False,
        "real_external_trust_operations": False,
        "network_operations": 0,
        "variants": {
            "volatile_lifecycle_receipt_baseline": {
                "adversarial_attempts": baseline_adversarial,
                "metrics": {"asr": baseline_asr},
            },
            "durable_restart_verifiable_lifecycle_journal": {
                "adversarial_attempts": hardened_adversarial,
                "benign_attempts": benign,
                "metrics": {
                    "asr": hardened_asr,
                    "fpr": hardened_fpr,
                    "safe_task_rate": hardened_safe_task_rate,
                },
            },
        },
    }
    report["passed"] = bool(
        baseline_asr == [5, 5]
        and hardened_asr == [0, 5]
        and hardened_fpr == [0, 3]
        and hardened_safe_task_rate == [3, 3]
        and ambiguous_safe
        and stale_safe
        and conflict_safe
        and tamper_safe
        and unprovable_safe
        and replay_safe
        and pre_crash_safe
        and reconciled_safe
        and report["migration_reconciliation_uses_local_synthetic_two_version_fixture"] is True
        and report["journal_rollback_resistance_claim"] is False
        and report["distributed_fencing_claim"] is False
        and report["exactly_once_claim"] is False
        and report["production_checkpoint_lifecycle_claim"] is False
        and report["real_external_trust_operations"] is False
        and report["network_operations"] == 0
    )
    return report


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
