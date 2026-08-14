from __future__ import annotations

import hashlib
import json
import shutil
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


ADVERSARIAL_CASES = (
    "P4N-A1-authentic-journal-generation-rollback",
    "P4N-A2-command-state-regression-same-fence",
    "P4N-A3-journal-and-p4m-key-pair-rollback",
    "P4N-A4-witness-payload-tamper",
    "P4N-A5-witness-deletion-with-existing-history",
)
BENIGN_CASES = (
    "P4N-B1-normal-witnessed-commit-reopen",
    "P4N-B2-forward-recovery-after-journal-before-witness-crash",
    "P4N-B3-p4m-ambiguous-migration-reconciliation-preserved",
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


def _witness_reason(callable_) -> str | None:
    try:
        callable_()
    except CheckpointLifecycleJournalWitnessError as exc:
        return exc.reason.value
    return None


def _journal_reason(callable_) -> str | None:
    try:
        callable_()
    except CheckpointLifecycleJournalError as exc:
        return exc.reason.value
    return None


def _command(coordinator, saver, suffix: str):
    return coordinator.issue_command(
        command_id=f"p4n-eval-{suffix}",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id=f"migration:{suffix}",
        saver=saver,
    )


def _authentic_journal_rollback(root: Path) -> tuple[dict[str, Any], bool]:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(root, "rollback")
    old_journal = root / "rollback-old.sqlite3"
    shutil.copy2(journal_path, old_journal)
    command = _command(coordinator, saver, "rollback")
    coordinator.execute(command, saver)
    shutil.copy2(old_journal, journal_path)
    rejection = _witness_reason(lambda: _reopen(lifecycle, journal_path, witness_path))
    safe = rejection == CheckpointLifecycleJournalWitnessReason.JOURNAL_ROLLBACK_DETECTED.value
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[0],
            "success": not safe,
            "rejection": rejection,
        },
        safe,
    )


def _state_regression(root: Path) -> tuple[dict[str, Any], bool]:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(root, "state-regression")
    command = _command(coordinator, saver, "state-regression")
    prepared_journal = root / "prepared-journal.sqlite3"
    shutil.copy2(journal_path, prepared_journal)
    coordinator.execute(command, saver)
    shutil.copy2(prepared_journal, journal_path)
    rejection = _witness_reason(lambda: _reopen(lifecycle, journal_path, witness_path))
    safe = rejection == CheckpointLifecycleJournalWitnessReason.JOURNAL_ROLLBACK_DETECTED.value
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[1],
            "success": not safe,
            "rejection": rejection,
            "same_issued_fence": True,
        },
        safe,
    )


def _journal_key_pair_rollback(root: Path) -> tuple[dict[str, Any], bool]:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(root, "pair-rollback")
    journal_key = journal_path.with_suffix(journal_path.suffix + ".hmac-key")
    old_journal = root / "pair-old-journal.sqlite3"
    old_key = root / "pair-old-key.bin"
    shutil.copy2(journal_path, old_journal)
    shutil.copy2(journal_key, old_key)
    command = _command(coordinator, saver, "pair-rollback")
    coordinator.execute(command, saver)
    shutil.copy2(old_journal, journal_path)
    shutil.copy2(old_key, journal_key)
    rejection = _witness_reason(lambda: _reopen(lifecycle, journal_path, witness_path))
    safe = rejection == CheckpointLifecycleJournalWitnessReason.JOURNAL_ROLLBACK_DETECTED.value
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[2],
            "success": not safe,
            "rejection": rejection,
            "p4m_key_rolled_back_with_journal": True,
        },
        safe,
    )


def _witness_tamper(root: Path) -> tuple[dict[str, Any], bool]:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(root, "witness-tamper")
    command = _command(coordinator, saver, "witness-tamper")
    coordinator.execute(command, saver)
    payload = json.loads(witness_path.read_text(encoding="utf-8"))
    payload["witness_generation"] = int(payload["witness_generation"]) + 100
    witness_path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    rejection = _witness_reason(lambda: _reopen(lifecycle, journal_path, witness_path))
    safe = rejection == CheckpointLifecycleJournalWitnessReason.WITNESS_INTEGRITY_FAILED.value
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[3],
            "success": not safe,
            "rejection": rejection,
        },
        safe,
    )


def _witness_deletion(root: Path) -> tuple[dict[str, Any], bool]:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(root, "witness-delete")
    command = _command(coordinator, saver, "witness-delete")
    coordinator.execute(command, saver)
    witness_path.unlink()
    rejection = _witness_reason(lambda: _reopen(lifecycle, journal_path, witness_path))
    safe = (
        rejection
        == CheckpointLifecycleJournalWitnessReason.WITNESS_MISSING_FOR_EXISTING_JOURNAL.value
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[4],
            "success": not safe,
            "rejection": rejection,
        },
        safe,
    )


def _normal_reopen(root: Path) -> tuple[dict[str, Any], bool]:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(root, "normal")
    command = _command(coordinator, saver, "normal")
    receipt = coordinator.execute(command, saver)
    reopened = _reopen(lifecycle, journal_path, witness_path)
    replay = reopened.execute(command, saver)
    safe = bool(
        receipt.command_digest == replay.command_digest
        and replay.replayed
        and lifecycle.migration_calls == 1
        and reopened.highest_committed_fence == 1
    )
    return (
        {
            "attempt_id": BENIGN_CASES[0],
            "safe_completion": safe,
            "incorrectly_blocked": not safe,
        },
        safe,
    )


def _forward_crash_recovery(root: Path) -> tuple[dict[str, Any], bool, bool]:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(root, "forward-crash")
    command = _command(coordinator, saver, "forward-crash")
    before_generation = coordinator.witness_generation
    coordinator.arm_fault(
        CheckpointLifecycleJournalWitnessFaultMode.AFTER_JOURNAL_BEFORE_WITNESS
    )
    crash = _witness_reason(lambda: coordinator.execute(command, saver))
    reopened = _reopen(lifecycle, journal_path, witness_path)
    replay = reopened.execute(command, saver)
    advanced = reopened.witness_generation > before_generation
    safe = bool(
        crash == CheckpointLifecycleJournalWitnessReason.SYNTHETIC_CRASH.value
        and advanced
        and replay.replayed
        and lifecycle.migration_calls == 1
    )
    return (
        {
            "attempt_id": BENIGN_CASES[1],
            "safe_completion": safe,
            "incorrectly_blocked": not safe,
            "witness_forward_advanced": advanced,
            "provider_invocations": lifecycle.migration_calls,
        },
        safe,
        bool(advanced and lifecycle.migration_calls == 1),
    )


def _p4m_reconciliation_preserved(root: Path) -> tuple[dict[str, Any], bool, bool]:
    saver, lifecycle, journal_path, witness_path, coordinator = _make(
        root,
        "reconcile",
        legacy_seed=True,
    )
    command = _command(coordinator, saver, "reconcile")
    coordinator.journal.arm_fault(CheckpointLifecycleJournalFaultMode.AFTER_PROVIDER_BEFORE_COMMIT)
    initial = _journal_reason(lambda: coordinator.execute(command, saver))
    reopened = _reopen(lifecycle, journal_path, witness_path)
    blocked = _journal_reason(lambda: reopened.execute(command, saver))
    calls_before = lifecycle.migration_calls
    receipt = reopened.reconcile(command, saver)
    safe = bool(
        initial == CheckpointLifecycleJournalReason.SYNTHETIC_CRASH.value
        and blocked == CheckpointLifecycleJournalReason.RECONCILIATION_REQUIRED.value
        and calls_before == 1
        and lifecycle.migration_calls == 1
        and receipt.replayed
        and reopened.highest_committed_fence == 1
    )
    return (
        {
            "attempt_id": BENIGN_CASES[2],
            "safe_completion": safe,
            "incorrectly_blocked": not safe,
            "reconciled_without_provider_reexecution": lifecycle.migration_calls == 1,
        },
        safe,
        bool(receipt.replayed and lifecycle.migration_calls == 1),
    )


def build_report() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegis-p4n-") as temporary:
        root = Path(temporary)
        a1, safe1 = _authentic_journal_rollback(root)
        a2, safe2 = _state_regression(root)
        a3, safe3 = _journal_key_pair_rollback(root)
        a4, safe4 = _witness_tamper(root)
        a5, safe5 = _witness_deletion(root)
        b1, benign1 = _normal_reopen(root)
        b2, benign2, forward_recovery = _forward_crash_recovery(root)
        b3, benign3, p4m_reconciliation = _p4m_reconciliation_preserved(root)

    adversarial = [a1, a2, a3, a4, a5]
    benign = [b1, b2, b3]
    hardened_asr = sum(1 for item in adversarial if item["success"])
    fpr = sum(1 for item in benign if item["incorrectly_blocked"])
    safe_tasks = sum(1 for item in benign if item["safe_completion"])
    all_security = all((safe1, safe2, safe3, safe4, safe5))
    all_benign = all((benign1, benign2, benign3))

    report = {
        "evaluation": "P4-N independent local lifecycle-journal witness boundary",
        "policy_version": P4N_LIFECYCLE_JOURNAL_WITNESS_POLICY_VERSION,
        "eval_dataset_hash_sha256": _dataset_hash(),
        "variants": {
            "journal_only_authenticated_baseline": {
                "adversarial_attempts": [
                    {"attempt_id": attempt_id, "success": True}
                    for attempt_id in ADVERSARIAL_CASES
                ],
                "metrics": {"asr": [5, 5]},
            },
            "independently_witnessed_local_journal": {
                "adversarial_attempts": adversarial,
                "benign_attempts": benign,
                "metrics": {
                    "asr": [hardened_asr, len(adversarial)],
                    "fpr": [fpr, len(benign)],
                    "safe_task_rate": [safe_tasks, len(benign)],
                },
            },
        },
        "journal_only_rollback_detected": safe1,
        "same_fence_state_regression_detected": safe2,
        "journal_and_p4m_key_pair_rollback_detected": safe3,
        "witness_integrity_tamper_rejected": safe4,
        "missing_witness_for_existing_history_rejected": safe5,
        "monotonic_forward_witness_recovery_after_crash": forward_recovery,
        "p4m_fail_closed_reconciliation_preserved": p4m_reconciliation,
        "joint_journal_and_witness_rollback_detectable": False,
        "independent_failure_domain": False,
        "journal_rollback_resistance_claim": False,
        "distributed_fencing_claim": False,
        "exactly_once_claim": False,
        "network_operations": 0,
        "real_external_trust_operations": False,
        "production_external_lifecycle_provider_included": False,
        "production_checkpoint_lifecycle_claim": False,
    }
    report["passed"] = bool(
        all_security
        and all_benign
        and hardened_asr == 0
        and fpr == 0
        and safe_tasks == len(benign)
        and forward_recovery
        and p4m_reconciliation
    )
    return report


def main() -> int:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
