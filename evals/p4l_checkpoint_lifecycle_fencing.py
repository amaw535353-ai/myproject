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


ADVERSARIAL_CASES = (
    "P4L-A1-ambiguous-commit-retry",
    "P4L-A2-provider-unavailability",
    "P4L-A3-stale-or-conflicting-command-replay",
    "P4L-A4-concurrent-writer-fence-mismatch",
    "P4L-A5-partial-anchor-progression",
)
BENIGN_CASES = (
    "P4L-B1-fenced-migration",
    "P4L-B2-fenced-snapshot",
    "P4L-B3-retry-after-reconciled-partial-progress",
)


def _dataset_hash() -> str:
    payload = json.dumps(
        {"adversarial": ADVERSARIAL_CASES, "benign": BENIGN_CASES},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _make(root: Path, name: str):
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    bridge = SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor)
    lifecycle = SyntheticExternalStyleCheckpointLifecycleProvider(anchor_provider=bridge)
    saver_root = root / name
    saver = OperationProviderKeyLifecycleCheckpointer(
        database_path=saver_root / "checkpoints.sqlite3",
        anchor_database_path=saver_root / "compatibility-anchor.sqlite3",
        key_provider=bundle.encryption,
        integrity_provider=bundle.integrity,
        anchor_provider=bridge,
        lifecycle_provider=lifecycle,
    )
    coordinator = SyntheticFencedCheckpointLifecycleCoordinator(
        lifecycle_provider=lifecycle
    )
    put(
        saver,
        thread_id=f"{name}-thread",
        checkpoint_id="00000001",
        marker=f"{name}-state",
    )
    return saver, bridge, lifecycle, coordinator


def _reason(callable_) -> str | None:
    try:
        callable_()
    except CheckpointLifecycleFencingError as exc:
        return exc.reason.value
    return None


def _ambiguous_case(root: Path) -> tuple[dict[str, Any], bool]:
    saver, _, lifecycle, coordinator = _make(root, "ambiguous")
    command = coordinator.issue_command(
        command_id="p4l-eval-ambiguous",
        operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
        resource_id="snapshot:ambiguous",
    )
    checkpoint_snapshot = root / "ambiguous-checkpoints.sqlite3"
    anchor_snapshot = root / "ambiguous-anchors.sqlite3"
    coordinator.arm_fault(CheckpointLifecycleFaultMode.AMBIGUOUS_AFTER_COMMIT)
    rejection = _reason(
        lambda: coordinator.execute(
            command,
            saver,
            checkpoint_destination=checkpoint_snapshot,
            anchor_destination=anchor_snapshot,
        )
    )
    replay = coordinator.execute(
        command,
        saver,
        checkpoint_destination=checkpoint_snapshot,
        anchor_destination=anchor_snapshot,
    )
    safe = bool(
        rejection == CheckpointLifecycleFencingReason.AMBIGUOUS_COMMIT_OUTCOME.value
        and replay.replayed
        and lifecycle.snapshot_calls == 1
        and coordinator.provider_invocations == 1
        and coordinator.receipt_count == 1
        and checkpoint_snapshot.exists()
        and anchor_snapshot.exists()
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[0],
            "success": not safe,
            "rejection": rejection,
            "provider_invocations": coordinator.provider_invocations,
            "replay_returned_committed_receipt": replay.replayed,
        },
        safe,
    )


def _unavailable_case(root: Path) -> tuple[dict[str, Any], bool]:
    saver, _, lifecycle, coordinator = _make(root, "unavailable")
    before = coordinator.anchor_fingerprint()
    command = coordinator.issue_command(
        command_id="p4l-eval-unavailable",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:unavailable",
    )
    coordinator.arm_fault(CheckpointLifecycleFaultMode.PROVIDER_UNAVAILABLE)
    rejection = _reason(lambda: coordinator.execute(command, saver))
    safe = bool(
        rejection == CheckpointLifecycleFencingReason.PROVIDER_UNAVAILABLE.value
        and coordinator.anchor_fingerprint() == before
        and lifecycle.migration_calls == 0
        and coordinator.provider_invocations == 0
        and coordinator.receipt_count == 0
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[1],
            "success": not safe,
            "rejection": rejection,
            "state_preserved": coordinator.anchor_fingerprint() == before,
        },
        safe,
    )


def _stale_replay_case(root: Path) -> tuple[dict[str, Any], bool]:
    saver, _, lifecycle, coordinator = _make(root, "stale")
    seed = coordinator.issue_command(
        command_id="p4l-eval-seed",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:seed",
    )
    coordinator.execute(seed, saver)
    stale = CheckpointLifecycleCommand(
        command_id="p4l-eval-stale",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        fence_token=1,
        expected_anchor_fingerprint=coordinator.anchor_fingerprint(),
        resource_id="migration:stale",
    )
    stale_rejection = _reason(lambda: coordinator.execute(stale, saver))
    conflict = CheckpointLifecycleCommand(
        command_id=seed.command_id,
        operation=seed.operation,
        fence_token=seed.fence_token,
        expected_anchor_fingerprint=seed.expected_anchor_fingerprint,
        resource_id="migration:conflict",
    )
    conflict_rejection = _reason(lambda: coordinator.execute(conflict, saver))
    safe = bool(
        stale_rejection == CheckpointLifecycleFencingReason.STALE_FENCE.value
        and conflict_rejection
        == CheckpointLifecycleFencingReason.COMMAND_REPLAY_CONFLICT.value
        and lifecycle.migration_calls == 1
        and coordinator.provider_invocations == 1
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[2],
            "success": not safe,
            "stale_rejection": stale_rejection,
            "conflict_rejection": conflict_rejection,
        },
        safe,
    )


def _concurrent_case(root: Path) -> tuple[dict[str, Any], bool]:
    saver, bridge, lifecycle, coordinator = _make(root, "concurrent")
    command = coordinator.issue_command(
        command_id="p4l-eval-concurrent",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:concurrent",
    )
    bridge.advance(
        encode_checkpoint_scope("p4l-other-writer", ""),
        generation=1,
        checkpoint_id="external-0001",
        checkpoint_digest="a" * 64,
        expected_generation=None,
    )
    rejection = _reason(lambda: coordinator.execute(command, saver))
    safe = bool(
        rejection == CheckpointLifecycleFencingReason.ANCHOR_FENCE_MISMATCH.value
        and lifecycle.migration_calls == 0
        and coordinator.provider_invocations == 0
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[3],
            "success": not safe,
            "rejection": rejection,
            "provider_invocations": coordinator.provider_invocations,
        },
        safe,
    )


def _partial_case(root: Path) -> tuple[dict[str, Any], bool, bool]:
    saver, _, lifecycle, coordinator = _make(root, "partial")
    before = coordinator.anchor_fingerprint()
    command = coordinator.issue_command(
        command_id="p4l-eval-partial",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:partial",
    )
    coordinator.arm_fault(CheckpointLifecycleFaultMode.PARTIAL_ANCHOR_PROGRESS)
    rejection = _reason(lambda: coordinator.execute(command, saver))
    reconciled = bool(
        rejection == CheckpointLifecycleFencingReason.PARTIAL_PROGRESS_RECONCILED.value
        and coordinator.anchor_fingerprint() == before
        and coordinator.reconciliations == 1
        and lifecycle.migration_calls == 0
        and coordinator.receipt_count == 0
    )
    retry = coordinator.execute(command, saver)
    retry_safe = bool(
        not retry.replayed
        and lifecycle.migration_calls == 1
        and coordinator.highest_committed_fence == 1
        and marker(saver, "partial-thread") == "partial-state"
    )
    return (
        {
            "attempt_id": ADVERSARIAL_CASES[4],
            "success": not reconciled,
            "rejection": rejection,
            "anchor_state_restored": coordinator.anchor_fingerprint()
            == retry.anchor_fingerprint_after,
        },
        reconciled,
        retry_safe,
    )


def _benign_migration(root: Path) -> dict[str, Any]:
    saver, _, lifecycle, coordinator = _make(root, "benign-migration")
    command = coordinator.issue_command(
        command_id="p4l-benign-migration",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:benign",
    )
    receipt = coordinator.execute(command, saver)
    safe = bool(
        receipt.fence_token == 1
        and lifecycle.migration_calls == 1
        and marker(saver, "benign-migration-thread") == "benign-migration-state"
    )
    return {
        "attempt_id": BENIGN_CASES[0],
        "incorrectly_blocked": not safe,
        "safe_completion": safe,
    }


def _benign_snapshot(root: Path) -> dict[str, Any]:
    saver, _, lifecycle, coordinator = _make(root, "benign-snapshot")
    checkpoint_snapshot = root / "benign-snapshot-checkpoints.sqlite3"
    anchor_snapshot = root / "benign-snapshot-anchors.sqlite3"
    command = coordinator.issue_command(
        command_id="p4l-benign-snapshot",
        operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
        resource_id="snapshot:benign",
    )
    coordinator.execute(
        command,
        saver,
        checkpoint_destination=checkpoint_snapshot,
        anchor_destination=anchor_snapshot,
    )
    safe = bool(
        lifecycle.snapshot_calls == 1
        and checkpoint_snapshot.exists()
        and anchor_snapshot.exists()
    )
    return {
        "attempt_id": BENIGN_CASES[1],
        "incorrectly_blocked": not safe,
        "safe_completion": safe,
    }


def build_report() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="aegisdesk-p4l-") as temp_dir:
        root = Path(temp_dir)
        ambiguous, ambiguous_safe = _ambiguous_case(root)
        unavailable, unavailable_safe = _unavailable_case(root)
        stale, stale_safe = _stale_replay_case(root)
        concurrent, concurrent_safe = _concurrent_case(root)
        partial, partial_safe, partial_retry_safe = _partial_case(root)
        benign = [
            _benign_migration(root),
            _benign_snapshot(root),
            {
                "attempt_id": BENIGN_CASES[2],
                "incorrectly_blocked": not partial_retry_safe,
                "safe_completion": partial_retry_safe,
            },
        ]

    hardened_adversarial = [ambiguous, unavailable, stale, concurrent, partial]
    baseline_adversarial = [
        {"attempt_id": case, "success": True} for case in ADVERSARIAL_CASES
    ]
    baseline_asr = [len(baseline_adversarial), len(baseline_adversarial)]
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
        "evaluation": "P4-L checkpoint lifecycle failure and fencing semantics harness",
        "policy_version": P4L_CHECKPOINT_LIFECYCLE_FENCING_POLICY_VERSION,
        "eval_dataset_hash_sha256": _dataset_hash(),
        "p4j_lifecycle_provider_exercised": True,
        "ambiguous_commit_replay_idempotent": ambiguous_safe,
        "provider_unavailability_fails_before_mutation": unavailable_safe,
        "stale_and_conflicting_replays_rejected": stale_safe,
        "concurrent_anchor_fence_mismatch_rejected": concurrent_safe,
        "partial_anchor_progress_reconciled": partial_safe,
        "durable_distributed_fencing": False,
        "production_external_lifecycle_provider_included": False,
        "production_checkpoint_lifecycle_claim": False,
        "real_external_trust_operations": False,
        "network_operations": 0,
        "variants": {
            "implicit_unfenced_lifecycle_baseline": {
                "adversarial_attempts": baseline_adversarial,
                "metrics": {"asr": baseline_asr},
            },
            "fenced_failure_aware_lifecycle_harness": {
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
    report["passed"] = (
        baseline_asr == [5, 5]
        and hardened_asr == [0, 5]
        and hardened_fpr == [0, 3]
        and hardened_safe_task_rate == [3, 3]
        and ambiguous_safe
        and unavailable_safe
        and stale_safe
        and concurrent_safe
        and partial_safe
        and partial_retry_safe
        and report["durable_distributed_fencing"] is False
        and report["production_external_lifecycle_provider_included"] is False
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
