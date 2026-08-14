from __future__ import annotations

import hashlib
import json
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
from aegis.agent.checkpoint_lifecycle_fencing import (
    CheckpointLifecycleCommand,
    CheckpointLifecycleCommandOperation,
)
from aegis.agent.checkpoint_lifecycle_journal import (
    CheckpointLifecycleJournalError,
    CheckpointLifecycleJournalReason,
)
from aegis.agent.checkpoint_lifecycle_provider_state_machine import (
    P4P_PROVIDER_COMMAND_STATE_POLICY_VERSION,
    ProviderCommandFaultMode,
    ProviderCommandStateError,
    ProviderCommandStateReason,
    ProviderStateMachineRecoveringLifecycleCoordinator,
    SyntheticCrashSafeOutcomeReceiptLifecycleProvider,
)
from aegis.agent.checkpoint_lifecycle_trust import (
    describe_checkpoint_lifecycle_provider,
    production_lifecycle_descriptor_allowed,
)
from aegis.agent.checkpoint_operation_runtime import (
    OperationProviderKeyLifecycleCheckpointer,
)
from aegis.effects.trust_providers import TrustProviderKind
from aegis.vulnerable.p4p_provider_internal_ambiguity import (
    VulnerableProviderInternalAmbiguityLifecycleProvider,
)
from evals.p4e_backup_common import put
from evals.p4m_lifecycle_fixture import (
    build_p4m_legacy_fixture_key_provider,
    build_p4m_migration_fixture_key_provider,
)


ADVERSARIAL_CASES = (
    "P4P-A1-mutation-receipt-gap-exact-retry",
    "P4P-A2-snapshot-argument-substitution-after-gap",
    "P4P-A3-restore-backup-substitution-after-gap",
)
BENIGN_CASES = (
    "P4P-B1-prepare-crash-safe-retry",
    "P4P-B2-migration-gap-reconciliation",
    "P4P-B3-snapshot-gap-reconciliation",
    "P4P-B4-restore-gap-reconciliation",
    "P4P-B5-receipt-commit-response-crash-replay",
)


def _dataset_hash() -> str:
    return hashlib.sha256(
        json.dumps(
            {"adversarial": ADVERSARIAL_CASES, "benign": BENIGN_CASES},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _anchor_fingerprint(bridge: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "checkpoint_heads": tuple(dict(item) for item in bridge.export_heads()),
                "write_heads": tuple(dict(item) for item in bridge.export_write_heads()),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _plain_runtime(root: Path, name: str):
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    bridge = SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor)
    inner = SyntheticExternalStyleCheckpointLifecycleProvider(anchor_provider=bridge)
    runtime_root = root / name
    saver = OperationProviderKeyLifecycleCheckpointer(
        database_path=runtime_root / "checkpoints.sqlite3",
        anchor_database_path=runtime_root / "compatibility-anchor.sqlite3",
        key_provider=bundle.encryption,
        integrity_provider=bundle.integrity,
        anchor_provider=bridge,
        lifecycle_provider=inner,
    )
    put(
        saver,
        thread_id=f"{name}-thread",
        checkpoint_id="00000001",
        marker=f"{name}-state",
    )
    return bundle, bridge, inner, saver


def _crash_safe_runtime(root: Path, name: str, *, legacy_seed: bool = False):
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    bridge = SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor)
    inner = SyntheticExternalStyleCheckpointLifecycleProvider(anchor_provider=bridge)
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
            lifecycle_provider=inner,
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

    provider = SyntheticCrashSafeOutcomeReceiptLifecycleProvider(
        lifecycle_provider=inner,
        command_database_path=runtime_root / "provider-commands.sqlite3",
        outcome_database_path=runtime_root / "provider-outcomes.sqlite3",
    )
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
            marker=f"{name}-state",
        )
    journal_path = runtime_root / "caller-journal.sqlite3"
    coordinator = ProviderStateMachineRecoveringLifecycleCoordinator(
        lifecycle_provider=provider,
        journal_path=journal_path,
    )
    return (
        bundle,
        bridge,
        inner,
        provider,
        saver,
        runtime_root / "provider-commands.sqlite3",
        runtime_root / "provider-outcomes.sqlite3",
        journal_path,
        coordinator,
    )


def _reopen_provider(
    *,
    inner: Any,
    command_path: Path,
    outcome_path: Path,
) -> SyntheticCrashSafeOutcomeReceiptLifecycleProvider:
    return SyntheticCrashSafeOutcomeReceiptLifecycleProvider(
        lifecycle_provider=inner,
        command_database_path=command_path,
        outcome_database_path=outcome_path,
    )


def _snapshot_command(command_id: str, bridge: Any, *, resource_id: str) -> CheckpointLifecycleCommand:
    return CheckpointLifecycleCommand(
        command_id=command_id,
        operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
        fence_token=1,
        expected_anchor_fingerprint=_anchor_fingerprint(bridge),
        resource_id=resource_id,
    )


def _adversarial_exact_retry(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    _, bridge_b, inner_b, saver_b = _plain_runtime(root, "a1-baseline")
    baseline = VulnerableProviderInternalAmbiguityLifecycleProvider(lifecycle_provider=inner_b)
    command_b = _snapshot_command("p4p-a1", bridge_b, resource_id="snapshot:a1")
    dest_b = root / "a1-baseline.sqlite3"
    anchor_b = root / "a1-baseline-anchor.sqlite3"
    baseline.arm_crash_after_mutation()
    try:
        baseline.execute_lifecycle_command(
            command_b,
            saver_b,
            checkpoint_destination=dest_b,
            anchor_destination=anchor_b,
        )
    except RuntimeError:
        pass
    baseline.execute_lifecycle_command(
        command_b,
        saver_b,
        checkpoint_destination=dest_b,
        anchor_destination=anchor_b,
    )
    baseline_success = inner_b.snapshot_calls == 2

    (
        _,
        bridge_h,
        inner_h,
        provider_h,
        saver_h,
        command_path,
        outcome_path,
        _,
        _,
    ) = _crash_safe_runtime(root, "a1-hardened")
    command_h = _snapshot_command("p4p-a1", bridge_h, resource_id="snapshot:a1")
    dest_h = root / "a1-hardened.sqlite3"
    anchor_h = root / "a1-hardened-anchor.sqlite3"
    provider_h.arm_fault(ProviderCommandFaultMode.AFTER_MUTATION_BEFORE_RECEIPT)
    try:
        provider_h.execute_lifecycle_command(
            command_h,
            saver_h,
            checkpoint_destination=dest_h,
            anchor_destination=anchor_h,
        )
    except ProviderCommandStateError:
        pass
    reopened = _reopen_provider(
        inner=inner_h,
        command_path=command_path,
        outcome_path=outcome_path,
    )
    receipt = reopened.recover_lifecycle_command(
        command_h,
        saver_h,
        checkpoint_destination=dest_h,
        anchor_destination=anchor_h,
    )
    hardened_success = inner_h.snapshot_calls != 1 or not receipt.replayed
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[0],
            "success": baseline_success,
            "provider_invocations": inner_b.snapshot_calls,
        },
        {
            "attempt_id": ADVERSARIAL_CASES[0],
            "success": hardened_success,
            "provider_invocations": inner_h.snapshot_calls,
            "provider_reconciled": receipt.replayed,
        },
    )


def _adversarial_snapshot_argument_substitution(
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _, bridge_b, inner_b, saver_b = _plain_runtime(root, "a2-baseline")
    baseline = VulnerableProviderInternalAmbiguityLifecycleProvider(lifecycle_provider=inner_b)
    command_b = _snapshot_command("p4p-a2", bridge_b, resource_id="snapshot:a2")
    baseline.arm_crash_after_mutation()
    try:
        baseline.execute_lifecycle_command(
            command_b,
            saver_b,
            checkpoint_destination=root / "a2-base-one.sqlite3",
            anchor_destination=root / "a2-base-one-anchor.sqlite3",
        )
    except RuntimeError:
        pass
    second_db = root / "a2-base-two.sqlite3"
    second_anchor = root / "a2-base-two-anchor.sqlite3"
    baseline.execute_lifecycle_command(
        command_b,
        saver_b,
        checkpoint_destination=second_db,
        anchor_destination=second_anchor,
    )
    baseline_success = inner_b.snapshot_calls == 2 and second_db.exists() and second_anchor.exists()

    (
        _,
        bridge_h,
        inner_h,
        provider_h,
        saver_h,
        command_path,
        outcome_path,
        _,
        _,
    ) = _crash_safe_runtime(root, "a2-hardened")
    command_h = _snapshot_command("p4p-a2", bridge_h, resource_id="snapshot:a2")
    provider_h.arm_fault(ProviderCommandFaultMode.AFTER_MUTATION_BEFORE_RECEIPT)
    try:
        provider_h.execute_lifecycle_command(
            command_h,
            saver_h,
            checkpoint_destination=root / "a2-hard-one.sqlite3",
            anchor_destination=root / "a2-hard-one-anchor.sqlite3",
        )
    except ProviderCommandStateError:
        pass
    reopened = _reopen_provider(
        inner=inner_h,
        command_path=command_path,
        outcome_path=outcome_path,
    )
    rejection = None
    try:
        reopened.recover_lifecycle_command(
            command_h,
            saver_h,
            checkpoint_destination=root / "a2-hard-two.sqlite3",
            anchor_destination=root / "a2-hard-two-anchor.sqlite3",
        )
    except ProviderCommandStateError as exc:
        rejection = exc.reason.value
    hardened_success = (
        rejection != ProviderCommandStateReason.ARGUMENT_CONFLICT.value
        or inner_h.snapshot_calls != 1
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[1],
            "success": baseline_success,
            "provider_invocations": inner_b.snapshot_calls,
        },
        {
            "attempt_id": ADVERSARIAL_CASES[1],
            "success": hardened_success,
            "provider_invocations": inner_h.snapshot_calls,
            "rejection": rejection,
        },
    )


def _prepare_restore_backups(inner: Any, saver: Any, root: Path, prefix: str):
    backup_one_db = root / f"{prefix}-backup-one.sqlite3"
    backup_one_anchor = root / f"{prefix}-backup-one-anchor.sqlite3"
    inner.snapshot_pair(
        saver,
        checkpoint_destination=backup_one_db,
        anchor_destination=backup_one_anchor,
    )
    put(
        saver,
        thread_id=f"{prefix}-later-thread",
        checkpoint_id="00000002",
        marker=f"{prefix}-later-state",
    )
    backup_two_db = root / f"{prefix}-backup-two.sqlite3"
    backup_two_anchor = root / f"{prefix}-backup-two-anchor.sqlite3"
    inner.snapshot_pair(
        saver,
        checkpoint_destination=backup_two_db,
        anchor_destination=backup_two_anchor,
    )
    put(
        saver,
        thread_id=f"{prefix}-current-thread",
        checkpoint_id="00000003",
        marker=f"{prefix}-current-state",
    )
    return backup_one_db, backup_one_anchor, backup_two_db, backup_two_anchor


def _adversarial_restore_backup_substitution(
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _, bridge_b, inner_b, saver_b = _plain_runtime(root, "a3-baseline")
    b1_db, b1_anchor, b2_db, b2_anchor = _prepare_restore_backups(
        inner_b, saver_b, root, "a3-base"
    )
    baseline = VulnerableProviderInternalAmbiguityLifecycleProvider(lifecycle_provider=inner_b)
    command_b = CheckpointLifecycleCommand(
        command_id="p4p-a3",
        operation=CheckpointLifecycleCommandOperation.RESTORE,
        fence_token=1,
        expected_anchor_fingerprint=_anchor_fingerprint(bridge_b),
        resource_id="restore:a3",
    )
    baseline.arm_crash_after_mutation()
    try:
        baseline.execute_lifecycle_command(
            command_b,
            saver_b,
            backup_database_path=b1_db,
            backup_anchor_path=b1_anchor,
        )
    except RuntimeError:
        pass
    baseline.execute_lifecycle_command(
        command_b,
        saver_b,
        backup_database_path=b2_db,
        backup_anchor_path=b2_anchor,
    )
    baseline_success = inner_b.restore_calls == 2

    (
        _,
        bridge_h,
        inner_h,
        provider_h,
        saver_h,
        command_path,
        outcome_path,
        _,
        _,
    ) = _crash_safe_runtime(root, "a3-hardened")
    h1_db, h1_anchor, h2_db, h2_anchor = _prepare_restore_backups(
        inner_h, saver_h, root, "a3-hard"
    )
    command_h = CheckpointLifecycleCommand(
        command_id="p4p-a3",
        operation=CheckpointLifecycleCommandOperation.RESTORE,
        fence_token=1,
        expected_anchor_fingerprint=_anchor_fingerprint(bridge_h),
        resource_id="restore:a3",
    )
    provider_h.arm_fault(ProviderCommandFaultMode.AFTER_MUTATION_BEFORE_RECEIPT)
    try:
        provider_h.execute_lifecycle_command(
            command_h,
            saver_h,
            backup_database_path=h1_db,
            backup_anchor_path=h1_anchor,
        )
    except ProviderCommandStateError:
        pass
    reopened = _reopen_provider(
        inner=inner_h,
        command_path=command_path,
        outcome_path=outcome_path,
    )
    rejection = None
    try:
        reopened.recover_lifecycle_command(
            command_h,
            saver_h,
            backup_database_path=h2_db,
            backup_anchor_path=h2_anchor,
        )
    except ProviderCommandStateError as exc:
        rejection = exc.reason.value
    hardened_success = (
        rejection != ProviderCommandStateReason.ARGUMENT_CONFLICT.value
        or inner_h.restore_calls != 1
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[2],
            "success": baseline_success,
            "provider_invocations": inner_b.restore_calls,
        },
        {
            "attempt_id": ADVERSARIAL_CASES[2],
            "success": hardened_success,
            "provider_invocations": inner_h.restore_calls,
            "rejection": rejection,
        },
    )


def _operation_call_count(inner: Any, operation: CheckpointLifecycleCommandOperation) -> int:
    return {
        CheckpointLifecycleCommandOperation.MIGRATION: inner.migration_calls,
        CheckpointLifecycleCommandOperation.SNAPSHOT: inner.snapshot_calls,
        CheckpointLifecycleCommandOperation.RESTORE: inner.restore_calls,
    }[operation]


def _benign_crash_recovery(
    root: Path,
    *,
    name: str,
    operation: CheckpointLifecycleCommandOperation,
    fault: ProviderCommandFaultMode,
) -> tuple[dict[str, Any], bool]:
    legacy = operation is CheckpointLifecycleCommandOperation.MIGRATION
    (
        _,
        _,
        inner,
        provider,
        saver,
        command_path,
        outcome_path,
        journal_path,
        coordinator,
    ) = _crash_safe_runtime(root, name, legacy_seed=legacy)

    kwargs: dict[str, Path] = {}
    if operation is CheckpointLifecycleCommandOperation.SNAPSHOT:
        kwargs = {
            "checkpoint_destination": root / f"{name}-snapshot.sqlite3",
            "anchor_destination": root / f"{name}-anchor.sqlite3",
        }
    elif operation is CheckpointLifecycleCommandOperation.RESTORE:
        backup_db = root / f"{name}-backup.sqlite3"
        backup_anchor = root / f"{name}-backup-anchor.sqlite3"
        inner.snapshot_pair(
            saver,
            checkpoint_destination=backup_db,
            anchor_destination=backup_anchor,
        )
        put(
            saver,
            thread_id=f"{name}-later-thread",
            checkpoint_id="00000002",
            marker=f"{name}-later-state",
        )
        kwargs = {
            "backup_database_path": backup_db,
            "backup_anchor_path": backup_anchor,
        }

    command = coordinator.issue_command(
        command_id=f"p4p-{name}",
        operation=operation,
        resource_id=f"{operation.value}:{name}",
        saver=saver,
    )
    provider.arm_fault(fault)
    failure_reason = None
    try:
        coordinator.execute(command, saver, **kwargs)
    except CheckpointLifecycleJournalError as exc:
        failure_reason = exc.reason.value

    calls_after_failure = _operation_call_count(inner, operation)
    reopened_provider = _reopen_provider(
        inner=inner,
        command_path=command_path,
        outcome_path=outcome_path,
    )
    reopened = ProviderStateMachineRecoveringLifecycleCoordinator(
        lifecycle_provider=reopened_provider,
        journal_path=journal_path,
    )
    receipt = reopened.reconcile(command, saver, **kwargs)
    calls_after_recovery = _operation_call_count(inner, operation)

    safe = bool(
        failure_reason == CheckpointLifecycleJournalReason.RECONCILIATION_REQUIRED.value
        and calls_after_recovery == 1
        and receipt.replayed
        and reopened.highest_committed_fence == command.fence_token
        and reopened_provider.outcome_store.receipt_count == 1
        and reopened_provider.command_store.command_count == 1
    )
    return (
        {
            "attempt_id": name,
            "incorrectly_blocked": not safe,
            "safe_completion": safe,
            "provider_invocations_after_failure": calls_after_failure,
            "provider_invocations_after_recovery": calls_after_recovery,
            "provider_receipt_replayed": receipt.replayed,
        },
        safe,
    )


def _production_rejection(root: Path) -> bool:
    (
        bundle,
        _,
        _,
        provider,
        _,
        _,
        _,
        _,
        _,
    ) = _crash_safe_runtime(root, "trust")
    descriptor = describe_checkpoint_lifecycle_provider(
        provider,
        kind=TrustProviderKind.EXTERNAL,
        independent_failure_domain=True,
    )
    return not production_lifecycle_descriptor_allowed(
        checkpoint_manifest=bundle.manifest,
        lifecycle_descriptor=descriptor,
    )


def build_report() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegisdesk-p4p-") as temp_dir:
        root = Path(temp_dir)
        baseline_a1, hardened_a1 = _adversarial_exact_retry(root)
        baseline_a2, hardened_a2 = _adversarial_snapshot_argument_substitution(root)
        baseline_a3, hardened_a3 = _adversarial_restore_backup_substitution(root)

        benign_prepare, prepare_safe = _benign_crash_recovery(
            root,
            name=BENIGN_CASES[0],
            operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
            fault=ProviderCommandFaultMode.AFTER_PREPARE_BEFORE_MUTATION,
        )
        benign_migration, migration_safe = _benign_crash_recovery(
            root,
            name=BENIGN_CASES[1],
            operation=CheckpointLifecycleCommandOperation.MIGRATION,
            fault=ProviderCommandFaultMode.AFTER_MUTATION_BEFORE_RECEIPT,
        )
        benign_snapshot, snapshot_safe = _benign_crash_recovery(
            root,
            name=BENIGN_CASES[2],
            operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
            fault=ProviderCommandFaultMode.AFTER_MUTATION_BEFORE_RECEIPT,
        )
        benign_restore, restore_safe = _benign_crash_recovery(
            root,
            name=BENIGN_CASES[3],
            operation=CheckpointLifecycleCommandOperation.RESTORE,
            fault=ProviderCommandFaultMode.AFTER_MUTATION_BEFORE_RECEIPT,
        )
        benign_receipt, receipt_safe = _benign_crash_recovery(
            root,
            name=BENIGN_CASES[4],
            operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
            fault=ProviderCommandFaultMode.AFTER_RECEIPT_BEFORE_RESPONSE,
        )
        production_rejected = _production_rejection(root)

    baseline_adversarial = [baseline_a1, baseline_a2, baseline_a3]
    hardened_adversarial = [hardened_a1, hardened_a2, hardened_a3]
    benign = [
        benign_prepare,
        benign_migration,
        benign_snapshot,
        benign_restore,
        benign_receipt,
    ]
    baseline_asr = [
        sum(1 for item in baseline_adversarial if item["success"]),
        len(baseline_adversarial),
    ]
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
        "evaluation": "P4-P provider-internal crash-safe command state machine",
        "policy_version": P4P_PROVIDER_COMMAND_STATE_POLICY_VERSION,
        "eval_dataset_hash_sha256": _dataset_hash(),
        "provider_owned_command_state": True,
        "authenticated_provider_command_state": True,
        "provider_argument_binding": True,
        "provider_internal_mutation_receipt_gap_recoverable": bool(
            migration_safe and snapshot_safe and restore_safe
        ),
        "provider_prepare_crash_safe_retry": prepare_safe,
        "provider_receipt_commit_response_crash_replay": receipt_safe,
        "provider_reexecution_during_mutation_gap_reconciliation": False,
        "provider_command_store_operationally_external": False,
        "provider_command_store_independent_failure_domain": False,
        "distributed_transaction_claim": False,
        "exactly_once_claim": False,
        "production_external_lifecycle_provider_included": False,
        "production_checkpoint_lifecycle_claim": False,
        "p4k_production_rejection_preserved": production_rejected,
        "real_external_trust_operations": False,
        "network_operations": 0,
        "variants": {
            "provider_internal_ambiguity_baseline": {
                "adversarial_attempts": baseline_adversarial,
                "metrics": {"asr": baseline_asr},
            },
            "crash_safe_provider_command_state": {
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
        baseline_asr == [3, 3]
        and hardened_asr == [0, 3]
        and hardened_fpr == [0, 5]
        and hardened_safe_task_rate == [5, 5]
        and report["provider_internal_mutation_receipt_gap_recoverable"] is True
        and report["provider_prepare_crash_safe_retry"] is True
        and report["provider_receipt_commit_response_crash_replay"] is True
        and production_rejected
        and report["distributed_transaction_claim"] is False
        and report["exactly_once_claim"] is False
        and report["production_checkpoint_lifecycle_claim"] is False
        and report["network_operations"] == 0
    )
    return report


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
