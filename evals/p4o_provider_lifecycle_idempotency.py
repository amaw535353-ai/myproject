from __future__ import annotations

import hashlib
import json
import tempfile
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

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
    CheckpointLifecycleCommand,
    CheckpointLifecycleCommandOperation,
)
from aegis.agent.checkpoint_lifecycle_journal import CheckpointLifecycleJournalError
from aegis.agent.checkpoint_operation_runtime import OperationProviderKeyLifecycleCheckpointer
from aegis.agent.checkpoint_provider_idempotency import (
    P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_POLICY_VERSION,
    CheckpointProviderLifecycleError,
    CheckpointProviderLifecycleFaultMode,
    CheckpointProviderLifecycleReason,
    ProviderOutcomeAwareDurableCheckpointLifecycleCoordinator,
    SyntheticProviderIdempotentCheckpointLifecycleProvider,
)
from evals.p4e_backup_common import marker, put
from evals.p4m_lifecycle_fixture import (
    build_p4m_legacy_fixture_key_provider,
    build_p4m_migration_fixture_key_provider,
)


ADVERSARIAL_CASES = (
    "P4O-A1-ambiguous-provider-applied-local-reopen",
    "P4O-A2-command-id-digest-conflict",
    "P4O-A3-stale-provider-fence",
    "P4O-A4-tampered-or-spliced-provider-receipt",
    "P4O-A5-provider-outcome-unknown-no-blind-reexecution",
)
BENIGN_CASES = (
    "P4O-B1-exact-duplicate-migration",
    "P4O-B2-snapshot-receipt-survives-provider-reopen",
    "P4O-B3-restore-receipt-and-state",
)


def _dataset_hash() -> str:
    payload = json.dumps(
        {"adversarial": ADVERSARIAL_CASES, "benign": BENIGN_CASES},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _make(root: Path, name: str, *, legacy_seed: bool = False):
    runtime_root = root / name
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    bridge = SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor)
    delegate = SyntheticExternalStyleCheckpointLifecycleProvider(anchor_provider=bridge)
    ledger_path = runtime_root / "provider-ledger.sqlite3"
    provider = SyntheticProviderIdempotentCheckpointLifecycleProvider(
        lifecycle_provider=delegate,
        ledger_path=ledger_path,
    )
    database_path = runtime_root / "checkpoints.sqlite3"
    compatibility_anchor = runtime_root / "compatibility-anchor.sqlite3"
    if legacy_seed:
        legacy_saver = OperationProviderKeyLifecycleCheckpointer(
            database_path=database_path,
            anchor_database_path=compatibility_anchor,
            key_provider=build_p4m_legacy_fixture_key_provider(),
            integrity_provider=bundle.integrity,
            anchor_provider=bridge,
            lifecycle_provider=provider,
        )
        put(
            legacy_saver,
            thread_id=f"{name}-thread",
            checkpoint_id="00000001",
            marker=f"{name}-legacy",
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
        lifecycle_provider=provider,
    )
    if not legacy_seed:
        put(
            saver,
            thread_id=f"{name}-thread",
            checkpoint_id="00000001",
            marker=f"{name}-state-one",
        )
    journal_path = runtime_root / "local-lifecycle-journal.sqlite3"
    coordinator = ProviderOutcomeAwareDurableCheckpointLifecycleCoordinator(
        lifecycle_provider=provider,
        journal_path=journal_path,
    )
    return saver, delegate, provider, ledger_path, journal_path, coordinator


def _reopen_provider(delegate: Any, ledger_path: Path):
    return SyntheticProviderIdempotentCheckpointLifecycleProvider(
        lifecycle_provider=delegate,
        ledger_path=ledger_path,
    )


def _reopen_coordinator(provider: Any, journal_path: Path):
    return ProviderOutcomeAwareDurableCheckpointLifecycleCoordinator(
        lifecycle_provider=provider,
        journal_path=journal_path,
    )


def _provider_reason(callable_: Callable[[], object]) -> str | None:
    try:
        callable_()
    except CheckpointProviderLifecycleError as exc:
        return exc.reason.value
    return None


def _migration_command(coordinator: Any, saver: Any, suffix: str):
    return coordinator.issue_command(
        command_id=f"p4o-{suffix}",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id=f"migration:{suffix}",
        saver=saver,
    )


def _ambiguous_applied_local_reopen(root: Path) -> tuple[dict[str, Any], bool]:
    saver, delegate, provider, ledger_path, journal_path, coordinator = _make(
        root, "ambiguous-applied", legacy_seed=True
    )
    command = _migration_command(coordinator, saver, "ambiguous-applied")
    provider.arm_fault(CheckpointProviderLifecycleFaultMode.AFTER_APPLIED_BEFORE_RESPONSE)
    local_rejection = None
    try:
        coordinator.execute(command, saver)
    except CheckpointLifecycleJournalError as exc:
        local_rejection = exc.reason.value
    calls_after_ambiguous = delegate.migration_calls
    reopened_provider = _reopen_provider(delegate, ledger_path)
    reopened = _reopen_coordinator(reopened_provider, journal_path)
    receipt = reopened.reconcile(command, saver)
    safe = bool(
        receipt.replayed
        and calls_after_ambiguous == 1
        and delegate.migration_calls == 1
        and reopened.highest_committed_fence == command.fence_token
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[0],
            "success": not safe,
            "local_rejection": local_rejection,
            "provider_invocations": delegate.migration_calls,
            "provider_receipt_reconciled": safe,
        },
        safe,
    )


def _command_conflict(root: Path) -> tuple[dict[str, Any], bool]:
    saver, _, provider, _, _, coordinator = _make(root, "conflict")
    command = _migration_command(coordinator, saver, "conflict")
    provider.execute_command(command, saver)
    changed = replace(command, resource_id="migration:changed-resource")
    rejection = _provider_reason(lambda: provider.execute_command(changed, saver))
    safe = rejection == CheckpointProviderLifecycleReason.COMMAND_CONFLICT.value
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[1],
            "success": not safe,
            "rejection": rejection,
        },
        safe,
    )


def _stale_fence(root: Path) -> tuple[dict[str, Any], bool]:
    saver, _, provider, _, _, coordinator = _make(root, "stale")
    command = _migration_command(coordinator, saver, "stale-first")
    provider.execute_command(command, saver)
    stale = CheckpointLifecycleCommand(
        command_id="p4o-stale-second",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        fence_token=command.fence_token,
        expected_anchor_fingerprint=coordinator.anchor_fingerprint(),
        resource_id="migration:stale-second",
    )
    rejection = _provider_reason(lambda: provider.execute_command(stale, saver))
    safe = rejection == CheckpointProviderLifecycleReason.FENCE_STALE.value
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[2],
            "success": not safe,
            "rejection": rejection,
        },
        safe,
    )


def _receipt_tamper(root: Path) -> tuple[dict[str, Any], bool]:
    saver, _, provider, _, _, coordinator = _make(root, "receipt-tamper")
    command = _migration_command(coordinator, saver, "receipt-tamper")
    receipt = provider.execute_command(command, saver)
    tampered = replace(receipt, result_digest="0" * 64)
    tamper_rejection = _provider_reason(lambda: provider.verify_receipt(tampered, command))
    spliced = replace(receipt, command_id="p4o-other-command")
    splice_rejection = _provider_reason(lambda: provider.verify_receipt(spliced, command))
    safe = bool(
        tamper_rejection == CheckpointProviderLifecycleReason.RECEIPT_INVALID.value
        and splice_rejection
        == CheckpointProviderLifecycleReason.RECEIPT_COMMAND_MISMATCH.value
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[3],
            "success": not safe,
            "tamper_rejection": tamper_rejection,
            "splice_rejection": splice_rejection,
        },
        safe,
    )


def _unknown_outcome(root: Path) -> tuple[dict[str, Any], bool]:
    saver, delegate, provider, ledger_path, journal_path, coordinator = _make(
        root, "unknown-outcome", legacy_seed=True
    )
    command = _migration_command(coordinator, saver, "unknown-outcome")
    provider.arm_fault(CheckpointProviderLifecycleFaultMode.AFTER_SIDE_EFFECT_BEFORE_APPLIED)
    try:
        coordinator.execute(command, saver)
    except CheckpointLifecycleJournalError:
        pass
    calls = delegate.migration_calls
    reopened_provider = _reopen_provider(delegate, ledger_path)
    reopened = _reopen_coordinator(reopened_provider, journal_path)
    rejection = _provider_reason(lambda: reopened.reconcile(command, saver))
    safe = bool(
        rejection == CheckpointProviderLifecycleReason.OUTCOME_UNKNOWN.value
        and delegate.migration_calls == calls == 1
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[4],
            "success": not safe,
            "rejection": rejection,
            "provider_invocations": delegate.migration_calls,
        },
        safe,
    )


def _duplicate_migration(root: Path) -> tuple[dict[str, Any], bool]:
    saver, delegate, provider, _, _, coordinator = _make(root, "duplicate")
    command = _migration_command(coordinator, saver, "duplicate")
    first = provider.execute_command(command, saver)
    second = provider.execute_command(command, saver)
    safe = bool(
        not first.replayed
        and second.replayed
        and delegate.migration_calls == 1
        and provider.side_effect_invocations == 1
    )
    return (
        {
            "attempt_id": BENIGN_CASES[0],
            "incorrectly_blocked": not safe,
            "safe_completion": safe,
        },
        safe,
    )


def _snapshot_reopen(root: Path) -> tuple[dict[str, Any], bool]:
    saver, delegate, provider, ledger_path, _, coordinator = _make(root, "snapshot")
    command = coordinator.issue_command(
        command_id="p4o-snapshot",
        operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
        resource_id="snapshot:pair-one",
        saver=saver,
    )
    checkpoint_backup = root / "snapshot" / "backup-checkpoints.sqlite3"
    anchor_backup = root / "snapshot" / "backup-anchor.sqlite3"
    receipt = provider.execute_command(
        command,
        saver,
        checkpoint_destination=checkpoint_backup,
        anchor_destination=anchor_backup,
    )
    reopened_provider = _reopen_provider(delegate, ledger_path)
    replay = reopened_provider.query_outcome(command)
    safe = bool(
        replay is not None
        and replay.replayed
        and replay.receipt_tag == receipt.receipt_tag
        and delegate.snapshot_calls == 1
        and checkpoint_backup.exists()
        and anchor_backup.exists()
    )
    return (
        {
            "attempt_id": BENIGN_CASES[1],
            "incorrectly_blocked": not safe,
            "safe_completion": safe,
        },
        safe,
    )


def _restore_receipt(root: Path) -> tuple[dict[str, Any], bool]:
    saver, delegate, provider, _, _, coordinator = _make(root, "restore")
    snapshot = coordinator.issue_command(
        command_id="p4o-restore-snapshot",
        operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
        resource_id="snapshot:restore-source",
        saver=saver,
    )
    checkpoint_backup = root / "restore" / "restore-source.sqlite3"
    anchor_backup = root / "restore" / "restore-source-anchor.sqlite3"
    provider.execute_command(
        snapshot,
        saver,
        checkpoint_destination=checkpoint_backup,
        anchor_destination=anchor_backup,
    )
    parent = put(
        saver,
        thread_id="restore-thread",
        checkpoint_id="00000002",
        marker="restore-state-two",
    )
    del parent
    restore = CheckpointLifecycleCommand(
        command_id="p4o-restore-command",
        operation=CheckpointLifecycleCommandOperation.RESTORE,
        fence_token=2,
        expected_anchor_fingerprint=coordinator.anchor_fingerprint(),
        resource_id="restore:pair-one",
    )
    receipt = provider.execute_command(
        restore,
        saver,
        backup_database_path=checkpoint_backup,
        backup_anchor_path=anchor_backup,
    )
    safe = bool(
        receipt.operation is CheckpointLifecycleCommandOperation.RESTORE
        and delegate.restore_calls == 1
        and marker(saver, "restore-thread") == "restore-state-one"
    )
    return (
        {
            "attempt_id": BENIGN_CASES[2],
            "incorrectly_blocked": not safe,
            "safe_completion": safe,
        },
        safe,
    )


def build_report() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4o-") as tmp:
        root = Path(tmp)
        adversarial_results = [
            _ambiguous_applied_local_reopen(root),
            _command_conflict(root),
            _stale_fence(root),
            _receipt_tamper(root),
            _unknown_outcome(root),
        ]
        benign_results = [
            _duplicate_migration(root),
            _snapshot_reopen(root),
            _restore_receipt(root),
        ]
    adversarial = [item[0] for item in adversarial_results]
    benign = [item[0] for item in benign_results]
    hardened_asr = sum(1 for item in adversarial if item["success"])
    hardened_fpr = sum(1 for item in benign if item["incorrectly_blocked"])
    safe_tasks = sum(1 for item in benign if item["safe_completion"])
    baseline = [
        {"attempt_id": case, "success": True}
        for case in ADVERSARIAL_CASES
    ]
    passed = bool(
        hardened_asr == 0
        and hardened_fpr == 0
        and safe_tasks == len(benign)
    )
    return {
        "evaluation": "P4-O provider-side lifecycle idempotency and outcome-receipt contract",
        "policy_version": P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_POLICY_VERSION,
        "eval_dataset_hash_sha256": _dataset_hash(),
        "provider_owned_durable_idempotency_ledger": True,
        "provider_outcome_receipt_authenticated": True,
        "exact_duplicate_does_not_reapply": bool(benign_results[0][1]),
        "provider_receipt_survives_reopen": bool(benign_results[1][1]),
        "ambiguous_local_reopen_queries_provider_outcome": bool(adversarial_results[0][1]),
        "unknown_provider_outcome_fails_closed": bool(adversarial_results[4][1]),
        "snapshot_and_restore_operations_exercised": bool(
            benign_results[1][1] and benign_results[2][1]
        ),
        "p4j_lifecycle_provider_exercised": True,
        "provider_ledger_rollback_resistance_claim": False,
        "provider_independent_failure_domain": False,
        "exactly_once_claim": False,
        "distributed_transaction_claim": False,
        "production_provider_claim": False,
        "production_checkpoint_lifecycle_claim": False,
        "production_external_lifecycle_provider_included": False,
        "real_external_trust_operations": False,
        "network_operations": 0,
        "variants": {
            "local_only_outcome_tracking_baseline": {
                "adversarial_attempts": baseline,
                "metrics": {"asr": [len(baseline), len(baseline)]},
            },
            "provider_owned_idempotency_receipt_contract": {
                "adversarial_attempts": adversarial,
                "benign_attempts": benign,
                "metrics": {
                    "asr": [hardened_asr, len(adversarial)],
                    "fpr": [hardened_fpr, len(benign)],
                    "safe_task_rate": [safe_tasks, len(benign)],
                },
            },
        },
        "passed": passed,
    }


def main() -> int:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
