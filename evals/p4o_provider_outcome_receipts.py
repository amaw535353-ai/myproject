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
from aegis.agent.checkpoint_lifecycle_fencing import (
    CheckpointLifecycleCommand,
    CheckpointLifecycleCommandOperation,
)
from aegis.agent.checkpoint_lifecycle_journal import (
    CheckpointLifecycleJournalError,
    CheckpointLifecycleJournalFaultMode,
    CheckpointLifecycleJournalReason,
)
from aegis.agent.checkpoint_lifecycle_outcome_receipts import (
    P4O_PROVIDER_OUTCOME_RECEIPT_POLICY_VERSION,
    ProviderLifecycleOutcomeError,
    ProviderLifecycleOutcomeReason,
    ProviderOutcomeRecoveringLifecycleCoordinator,
    SyntheticIdempotentOutcomeReceiptLifecycleProvider,
)
from aegis.agent.checkpoint_lifecycle_trust import (
    describe_checkpoint_lifecycle_provider,
    production_lifecycle_descriptor_allowed,
)
from aegis.agent.checkpoint_operation_runtime import (
    OperationProviderKeyLifecycleCheckpointer,
)
from aegis.effects.trust_providers import TrustProviderKind
from aegis.vulnerable.p4o_outcome_blind import VulnerableOutcomeBlindLifecycleProvider
from evals.p4e_backup_common import put
from evals.p4m_lifecycle_fixture import (
    build_p4m_legacy_fixture_key_provider,
    build_p4m_migration_fixture_key_provider,
)


ADVERSARIAL_CASES = (
    "P4O-A1-exact-command-provider-replay",
    "P4O-A2-command-id-conflicting-replay",
)
BENIGN_CASES = (
    "P4O-B1-migration-ambiguous-local-result-recovery",
    "P4O-B2-snapshot-ambiguous-local-result-recovery",
    "P4O-B3-restore-ambiguous-local-result-recovery",
)


def _dataset_hash() -> str:
    payload = json.dumps(
        {"adversarial": ADVERSARIAL_CASES, "benign": BENIGN_CASES},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _anchor_fingerprint(bridge: Any) -> str:
    payload = json.dumps(
        {
            "checkpoint_heads": tuple(dict(item) for item in bridge.export_heads()),
            "write_heads": tuple(dict(item) for item in bridge.export_write_heads()),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


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


def _receipt_runtime(root: Path, name: str, *, legacy_seed: bool = False):
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
            marker=f"{name}-state",
        )
        key_provider = build_p4m_migration_fixture_key_provider()
    else:
        key_provider = bundle.encryption

    outcome_path = runtime_root / "provider-outcomes.sqlite3"
    provider = SyntheticIdempotentOutcomeReceiptLifecycleProvider(
        lifecycle_provider=inner,
        outcome_database_path=outcome_path,
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
    journal_path = runtime_root / "lifecycle-journal.sqlite3"
    coordinator = ProviderOutcomeRecoveringLifecycleCoordinator(
        lifecycle_provider=provider,
        journal_path=journal_path,
    )
    return bundle, bridge, inner, provider, saver, outcome_path, journal_path, coordinator


def _snapshot_command(command_id: str, bridge: Any, *, resource_id: str) -> CheckpointLifecycleCommand:
    return CheckpointLifecycleCommand(
        command_id=command_id,
        operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
        fence_token=1,
        expected_anchor_fingerprint=_anchor_fingerprint(bridge),
        resource_id=resource_id,
    )


def _adversarial_exact_replay(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    _, bridge_b, inner_b, saver_b = _plain_runtime(root, "a1-baseline")
    blind = VulnerableOutcomeBlindLifecycleProvider(lifecycle_provider=inner_b)
    command_b = _snapshot_command("p4o-a1", bridge_b, resource_id="snapshot:a1")
    blind.execute_lifecycle_command(
        command_b,
        saver_b,
        checkpoint_destination=root / "a1-baseline-checkpoints.sqlite3",
        anchor_destination=root / "a1-baseline-anchor.json",
    )
    blind.execute_lifecycle_command(
        command_b,
        saver_b,
        checkpoint_destination=root / "a1-baseline-checkpoints.sqlite3",
        anchor_destination=root / "a1-baseline-anchor.json",
    )
    baseline_success = inner_b.snapshot_calls == 2

    _, bridge_h, inner_h, _, saver_h, _, _, _ = _receipt_runtime(root, "a1-hardened")
    hardened = saver_h.lifecycle_provider
    command_h = _snapshot_command("p4o-a1", bridge_h, resource_id="snapshot:a1")
    first = hardened.execute_lifecycle_command(
        command_h,
        saver_h,
        checkpoint_destination=root / "a1-hard-checkpoints.sqlite3",
        anchor_destination=root / "a1-hard-anchor.json",
    )
    replay = hardened.execute_lifecycle_command(
        command_h,
        saver_h,
        checkpoint_destination=root / "a1-hard-checkpoints.sqlite3",
        anchor_destination=root / "a1-hard-anchor.json",
    )
    hardened_success = inner_h.snapshot_calls != 1 or not replay.replayed
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
            "provider_replay": replay.replayed,
            "receipt_digest_stable": first.digest() == replay.digest(),
        },
    )


def _adversarial_conflict(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    _, bridge_b, inner_b, saver_b = _plain_runtime(root, "a2-baseline")
    blind = VulnerableOutcomeBlindLifecycleProvider(lifecycle_provider=inner_b)
    first_b = _snapshot_command("p4o-a2", bridge_b, resource_id="snapshot:a2-original")
    conflict_b = _snapshot_command("p4o-a2", bridge_b, resource_id="snapshot:a2-conflict")
    blind.execute_lifecycle_command(
        first_b,
        saver_b,
        checkpoint_destination=root / "a2-base-one.sqlite3",
        anchor_destination=root / "a2-base-one.json",
    )
    blind.execute_lifecycle_command(
        conflict_b,
        saver_b,
        checkpoint_destination=root / "a2-base-two.sqlite3",
        anchor_destination=root / "a2-base-two.json",
    )
    baseline_success = inner_b.snapshot_calls == 2

    _, bridge_h, inner_h, provider_h, saver_h, _, _, _ = _receipt_runtime(
        root, "a2-hardened"
    )
    first_h = _snapshot_command("p4o-a2", bridge_h, resource_id="snapshot:a2-original")
    conflict_h = _snapshot_command("p4o-a2", bridge_h, resource_id="snapshot:a2-conflict")
    provider_h.execute_lifecycle_command(
        first_h,
        saver_h,
        checkpoint_destination=root / "a2-hard-one.sqlite3",
        anchor_destination=root / "a2-hard-one.json",
    )
    rejection = None
    try:
        provider_h.execute_lifecycle_command(
            conflict_h,
            saver_h,
            checkpoint_destination=root / "a2-hard-two.sqlite3",
            anchor_destination=root / "a2-hard-two.json",
        )
    except ProviderLifecycleOutcomeError as exc:
        rejection = exc.reason.value
    hardened_success = (
        rejection != ProviderLifecycleOutcomeReason.COMMAND_CONFLICT.value
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


def _provider_call_count(inner: Any, operation: CheckpointLifecycleCommandOperation) -> int:
    return {
        CheckpointLifecycleCommandOperation.MIGRATION: inner.migration_calls,
        CheckpointLifecycleCommandOperation.SNAPSHOT: inner.snapshot_calls,
        CheckpointLifecycleCommandOperation.RESTORE: inner.restore_calls,
    }[operation]


def _benign_ambiguous_recovery(
    root: Path,
    *,
    name: str,
    operation: CheckpointLifecycleCommandOperation,
) -> tuple[dict[str, Any], bool]:
    legacy = operation is CheckpointLifecycleCommandOperation.MIGRATION
    (
        _,
        _,
        inner,
        provider,
        saver,
        outcome_path,
        journal_path,
        coordinator,
    ) = _receipt_runtime(root, name, legacy_seed=legacy)

    kwargs: dict[str, Path] = {}
    if operation is CheckpointLifecycleCommandOperation.SNAPSHOT:
        kwargs = {
            "checkpoint_destination": root / f"{name}-snapshot.sqlite3",
            "anchor_destination": root / f"{name}-anchor.json",
        }
    elif operation is CheckpointLifecycleCommandOperation.RESTORE:
        backup_db = root / f"{name}-backup.sqlite3"
        backup_anchor = root / f"{name}-backup-anchor.json"
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
        command_id=f"p4o-{name}",
        operation=operation,
        resource_id=f"{operation.value}:{name}",
        saver=saver,
    )
    coordinator.arm_fault(CheckpointLifecycleJournalFaultMode.AFTER_PROVIDER_BEFORE_COMMIT)
    crash_reason = None
    try:
        coordinator.execute(command, saver, **kwargs)
    except CheckpointLifecycleJournalError as exc:
        crash_reason = exc.reason.value

    calls_after_provider = _provider_call_count(inner, operation)
    reopened_provider = SyntheticIdempotentOutcomeReceiptLifecycleProvider(
        lifecycle_provider=inner,
        outcome_database_path=outcome_path,
    )
    reopened = ProviderOutcomeRecoveringLifecycleCoordinator(
        lifecycle_provider=reopened_provider,
        journal_path=journal_path,
    )
    receipt = reopened.reconcile(command, saver)
    calls_after_reconcile = _provider_call_count(inner, operation)
    safe = bool(
        crash_reason == CheckpointLifecycleJournalReason.SYNTHETIC_CRASH.value
        and calls_after_provider == 1
        and calls_after_reconcile == 1
        and receipt.replayed
        and reopened.highest_committed_fence == command.fence_token
        and reopened_provider.outcome_store.receipt_count == 1
    )
    return (
        {
            "attempt_id": {
                CheckpointLifecycleCommandOperation.MIGRATION: BENIGN_CASES[0],
                CheckpointLifecycleCommandOperation.SNAPSHOT: BENIGN_CASES[1],
                CheckpointLifecycleCommandOperation.RESTORE: BENIGN_CASES[2],
            }[operation],
            "incorrectly_blocked": not safe,
            "safe_completion": safe,
            "provider_invocations_after_ambiguity": calls_after_provider,
            "provider_invocations_after_reconciliation": calls_after_reconcile,
            "provider_receipt_replayed": receipt.replayed,
        },
        safe,
    )


def _tamper_rejected(root: Path) -> bool:
    _, bridge, _, provider, saver, outcome_path, _, _ = _receipt_runtime(
        root, "tamper"
    )
    command = _snapshot_command("p4o-tamper", bridge, resource_id="snapshot:tamper")
    provider.execute_lifecycle_command(
        command,
        saver,
        checkpoint_destination=root / "tamper.sqlite3",
        anchor_destination=root / "tamper.json",
    )
    connection = sqlite3.connect(outcome_path)
    try:
        connection.execute(
            "UPDATE provider_outcome_receipts SET resource_id = ? WHERE command_id = ?",
            ("snapshot:tampered", command.command_id),
        )
        connection.commit()
    finally:
        connection.close()
    try:
        SyntheticIdempotentOutcomeReceiptLifecycleProvider(
            lifecycle_provider=provider.inner_provider,
            outcome_database_path=outcome_path,
        )
    except ProviderLifecycleOutcomeError as exc:
        return exc.reason is ProviderLifecycleOutcomeReason.RECEIPT_INTEGRITY_FAILED
    return False


def _production_rejection(root: Path) -> bool:
    bundle, _, _, provider, _, _, _, _ = _receipt_runtime(root, "trust")
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
    with tempfile.TemporaryDirectory(prefix="aegisdesk-p4o-") as temp_dir:
        root = Path(temp_dir)
        baseline_a1, hardened_a1 = _adversarial_exact_replay(root)
        baseline_a2, hardened_a2 = _adversarial_conflict(root)
        benign_migration, migration_safe = _benign_ambiguous_recovery(
            root,
            name="benign-migration",
            operation=CheckpointLifecycleCommandOperation.MIGRATION,
        )
        benign_snapshot, snapshot_safe = _benign_ambiguous_recovery(
            root,
            name="benign-snapshot",
            operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
        )
        benign_restore, restore_safe = _benign_ambiguous_recovery(
            root,
            name="benign-restore",
            operation=CheckpointLifecycleCommandOperation.RESTORE,
        )
        tamper_safe = _tamper_rejected(root)
        production_rejected = _production_rejection(root)

    baseline_adversarial = [baseline_a1, baseline_a2]
    hardened_adversarial = [hardened_a1, hardened_a2]
    benign = [benign_migration, benign_snapshot, benign_restore]
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
        "evaluation": "P4-O provider-side idempotency and lifecycle outcome receipts",
        "policy_version": P4O_PROVIDER_OUTCOME_RECEIPT_POLICY_VERSION,
        "eval_dataset_hash_sha256": _dataset_hash(),
        "provider_owned_outcome_receipts": True,
        "authenticated_provider_receipts": True,
        "provider_receipt_binds_exact_command_and_post_anchor": True,
        "all_lifecycle_operations_ambiguous_local_results_recovered": bool(
            migration_safe and snapshot_safe and restore_safe
        ),
        "provider_reexecution_during_reconciliation": False,
        "provider_receipt_integrity_tamper_rejected": tamper_safe,
        "provider_outcome_store_operationally_external": False,
        "provider_outcome_store_independent_failure_domain": False,
        "provider_internal_operation_receipt_atomicity_claim": False,
        "exactly_once_claim": False,
        "production_external_lifecycle_provider_included": False,
        "production_checkpoint_lifecycle_claim": False,
        "p4k_production_rejection_preserved": production_rejected,
        "real_external_trust_operations": False,
        "network_operations": 0,
        "variants": {
            "outcome_blind_retry_baseline": {
                "adversarial_attempts": baseline_adversarial,
                "metrics": {"asr": baseline_asr},
            },
            "provider_owned_authenticated_outcome_receipts": {
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
        baseline_asr == [2, 2]
        and hardened_asr == [0, 2]
        and hardened_fpr == [0, 3]
        and hardened_safe_task_rate == [3, 3]
        and report["all_lifecycle_operations_ambiguous_local_results_recovered"] is True
        and tamper_safe
        and production_rejected
        and report["provider_internal_operation_receipt_atomicity_claim"] is False
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
