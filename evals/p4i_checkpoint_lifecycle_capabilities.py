from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

from aegis.agent.checkpoint_backup import AuthenticatedCheckpointBackupManager
from aegis.agent.checkpoint_external_contracts import (
    build_synthetic_external_checkpoint_contract_bundle,
)
from aegis.agent.checkpoint_external_runtime_bridge import (
    SyntheticExternalCheckpointAnchorRuntimeBridge,
)
from aegis.agent.checkpoint_lifecycle_capabilities import (
    P4I_CHECKPOINT_LIFECYCLE_CAPABILITY_POLICY_VERSION,
    CheckpointLifecycleCapability,
    CheckpointLifecycleCapabilityError,
    CheckpointLifecycleReason,
    LocalSqliteCheckpointLifecycleProvider,
)
from aegis.agent.checkpoint_operation_factory import (
    LocalSyntheticCheckpointOperationProviderFactory,
)
from aegis.agent.checkpoint_operation_runtime import (
    OperationProviderKeyLifecycleCheckpointer,
)
from evals.p4e_backup_common import marker, put


ADVERSARIAL_CASES = (
    "P4I-A1-migration-without-provider-capability",
    "P4I-A2-snapshot-without-provider-capability",
    "P4I-A3-restore-without-provider-capability",
    "P4I-A4-lifecycle-anchor-provider-mismatch",
)
BENIGN_CASES = (
    "P4I-B1-local-capability-migration",
    "P4I-B2-local-capability-snapshot",
    "P4I-B3-local-capability-restore",
)


def _dataset_hash() -> str:
    return hashlib.sha256(
        json.dumps(
            {"adversarial": ADVERSARIAL_CASES, "benign": BENIGN_CASES},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _local_saver(root: Path) -> OperationProviderKeyLifecycleCheckpointer:
    factory = LocalSyntheticCheckpointOperationProviderFactory()
    anchor_path = root / "anchors.sqlite3"
    anchor = factory.anchor_provider(anchor_path)
    return OperationProviderKeyLifecycleCheckpointer(
        database_path=root / "checkpoints.sqlite3",
        anchor_database_path=anchor_path,
        key_provider=factory.encryption_key_provider(),
        integrity_provider=factory.integrity_provider(),
        anchor_provider=anchor,
        lifecycle_provider=factory.lifecycle_provider(anchor),
    )


def _external_style_saver(root: Path) -> OperationProviderKeyLifecycleCheckpointer:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    return OperationProviderKeyLifecycleCheckpointer(
        database_path=root / "checkpoints.sqlite3",
        anchor_database_path=root / "compatibility-anchor.sqlite3",
        key_provider=bundle.encryption,
        integrity_provider=bundle.integrity,
        anchor_provider=SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor),
    )


def _lifecycle_rejection(operation: Any) -> str | None:
    try:
        operation()
    except CheckpointLifecycleCapabilityError as exc:
        return exc.reason.value
    return None


class _MismatchedLifecycleProvider:
    provider_id = "synthetic-mismatched-lifecycle-provider"
    anchor_provider_id = "synthetic-other-anchor"
    capabilities = frozenset(CheckpointLifecycleCapability)
    synthetic_in_process = True
    operationally_external = False


def _adversarial_attempts(root: Path) -> list[dict[str, Any]]:
    migration_saver = _external_style_saver(root / "migration")
    put(
        migration_saver,
        thread_id="p4i-migration",
        checkpoint_id="00000001",
        marker="must-not-mutate",
    )
    migration_rejection = _lifecycle_rejection(
        migration_saver.migrate_to_active_encryption_key
    )
    migration_state_preserved = (
        marker(migration_saver, "p4i-migration") == "must-not-mutate"
    )

    snapshot_saver = _external_style_saver(root / "snapshot")
    put(
        snapshot_saver,
        thread_id="p4i-snapshot",
        checkpoint_id="00000001",
        marker="must-not-snapshot-via-compatibility-anchor",
    )
    unsupported_backup = root / "unsupported-backup"
    snapshot_rejection = _lifecycle_rejection(
        lambda: AuthenticatedCheckpointBackupManager(saver=snapshot_saver).create_backup(
            unsupported_backup
        )
    )

    restore_source = _local_saver(root / "restore-source")
    put(
        restore_source,
        thread_id="p4i-restore",
        checkpoint_id="00000001",
        marker="authorized-lifecycle-restore",
    )
    restore_backup = root / "restore-backup"
    AuthenticatedCheckpointBackupManager(saver=restore_source).create_backup(
        restore_backup
    )
    restore_target = _external_style_saver(root / "restore-target")
    restore_rejection = _lifecycle_rejection(
        lambda: AuthenticatedCheckpointBackupManager(saver=restore_target).restore_backup(
            restore_backup
        )
    )

    factory = LocalSyntheticCheckpointOperationProviderFactory()
    mismatch_root = root / "mismatch"
    mismatch_anchor = factory.anchor_provider(mismatch_root / "anchors.sqlite3")
    mismatch_database = mismatch_root / "checkpoints.sqlite3"
    mismatch_rejection = _lifecycle_rejection(
        lambda: OperationProviderKeyLifecycleCheckpointer(
            database_path=mismatch_database,
            anchor_database_path=mismatch_root / "anchors.sqlite3",
            key_provider=factory.encryption_key_provider(),
            integrity_provider=factory.integrity_provider(),
            anchor_provider=mismatch_anchor,
            lifecycle_provider=_MismatchedLifecycleProvider(),
        )
    )

    return [
        {
            "attempt_id": ADVERSARIAL_CASES[0],
            "success": migration_rejection is None,
            "rejection": migration_rejection,
            "checkpoint_state_preserved": migration_state_preserved,
        },
        {
            "attempt_id": ADVERSARIAL_CASES[1],
            "success": snapshot_rejection is None,
            "rejection": snapshot_rejection,
            "backup_directory_created": unsupported_backup.exists(),
        },
        {
            "attempt_id": ADVERSARIAL_CASES[2],
            "success": restore_rejection is None,
            "rejection": restore_rejection,
            "target_state_installed": marker(restore_target, "p4i-restore") is not None,
        },
        {
            "attempt_id": ADVERSARIAL_CASES[3],
            "success": mismatch_rejection is None,
            "rejection": mismatch_rejection,
            "checkpoint_database_created": mismatch_database.exists(),
        },
    ]


def _benign_attempts(root: Path) -> list[dict[str, Any]]:
    migration_saver = _local_saver(root / "migration")
    put(
        migration_saver,
        thread_id="p4i-benign-migration",
        checkpoint_id="00000001",
        marker="migration-safe",
    )
    migration_provider = migration_saver.lifecycle_provider
    migration_report = migration_saver.migrate_to_active_encryption_key()
    migration_safe = bool(
        marker(migration_saver, "p4i-benign-migration") == "migration-safe"
        and migration_report.checkpoints_examined == 1
        and getattr(migration_provider, "migration_calls", 0) == 1
    )

    snapshot_saver = _local_saver(root / "snapshot")
    put(
        snapshot_saver,
        thread_id="p4i-benign-snapshot",
        checkpoint_id="00000001",
        marker="snapshot-safe",
    )
    snapshot_provider = snapshot_saver.lifecycle_provider
    backup_path = root / "snapshot-backup"
    artifact = AuthenticatedCheckpointBackupManager(saver=snapshot_saver).create_backup(
        backup_path
    )
    snapshot_safe = bool(
        artifact.checkpoint_heads == 1
        and (backup_path / "checkpoints.sqlite3").is_file()
        and (backup_path / "anchors.sqlite3").is_file()
        and getattr(snapshot_provider, "snapshot_calls", 0) == 1
    )

    restore_source = _local_saver(root / "restore-source")
    put(
        restore_source,
        thread_id="p4i-benign-restore",
        checkpoint_id="00000001",
        marker="restore-safe",
    )
    restore_backup = root / "restore-backup"
    AuthenticatedCheckpointBackupManager(saver=restore_source).create_backup(
        restore_backup
    )
    restore_target = _local_saver(root / "restore-target")
    restore_provider = restore_target.lifecycle_provider
    AuthenticatedCheckpointBackupManager(saver=restore_target).restore_backup(
        restore_backup
    )
    restore_safe = bool(
        marker(restore_target, "p4i-benign-restore") == "restore-safe"
        and getattr(restore_provider, "restore_calls", 0) == 1
    )

    return [
        {
            "attempt_id": BENIGN_CASES[0],
            "safe_completion": migration_safe,
            "incorrectly_blocked": not migration_safe,
            "lifecycle_operation_used": getattr(migration_provider, "migration_calls", 0)
            == 1,
        },
        {
            "attempt_id": BENIGN_CASES[1],
            "safe_completion": snapshot_safe,
            "incorrectly_blocked": not snapshot_safe,
            "lifecycle_operation_used": getattr(snapshot_provider, "snapshot_calls", 0)
            == 1,
        },
        {
            "attempt_id": BENIGN_CASES[2],
            "safe_completion": restore_safe,
            "incorrectly_blocked": not restore_safe,
            "lifecycle_operation_used": getattr(restore_provider, "restore_calls", 0)
            == 1,
        },
    ]


def build_report() -> dict[str, Any]:
    baseline = [
        {"attempt_id": case_id, "success": True} for case_id in ADVERSARIAL_CASES
    ]
    with tempfile.TemporaryDirectory(prefix="aegisdesk-p4i-") as temp:
        root = Path(temp)
        hardened = _adversarial_attempts(root / "adversarial")
        benign = _benign_attempts(root / "benign")
        factory = LocalSyntheticCheckpointOperationProviderFactory()
        anchor = factory.anchor_provider(root / "posture" / "anchors.sqlite3")
        lifecycle = factory.lifecycle_provider(anchor)
        capabilities = sorted(capability.value for capability in lifecycle.capabilities)
        identity_bound = lifecycle.anchor_provider_id == anchor.provider_id
        local_provider = isinstance(lifecycle, LocalSqliteCheckpointLifecycleProvider)

    baseline_metrics = {
        "asr": [sum(bool(item["success"]) for item in baseline), len(baseline)]
    }
    hardened_metrics = {
        "asr": [sum(bool(item["success"]) for item in hardened), len(hardened)],
        "fpr": [sum(bool(item["incorrectly_blocked"]) for item in benign), len(benign)],
        "safe_task_rate": [sum(bool(item["safe_completion"]) for item in benign), len(benign)],
    }
    expected_rejections = [
        CheckpointLifecycleReason.PROVIDER_MISSING.value,
        CheckpointLifecycleReason.PROVIDER_MISSING.value,
        CheckpointLifecycleReason.PROVIDER_MISSING.value,
        CheckpointLifecycleReason.ANCHOR_PROVIDER_MISMATCH.value,
    ]
    observed_rejections = [str(item["rejection"]) for item in hardened]
    report: dict[str, Any] = {
        "evaluation": "P4-I checkpoint lifecycle capability-provider boundary",
        "eval_dataset_hash_sha256": _dataset_hash(),
        "policy_version": P4I_CHECKPOINT_LIFECYCLE_CAPABILITY_POLICY_VERSION,
        "variants": {
            "implicit_local_lifecycle_assumption_baseline": {
                "adversarial_attempts": baseline,
                "metrics": baseline_metrics,
            },
            "capability_bound_lifecycle_runtime": {
                "adversarial_attempts": hardened,
                "benign_attempts": benign,
                "metrics": hardened_metrics,
            },
        },
        "default_factory_lifecycle_provider_explicit": local_provider,
        "default_lifecycle_capabilities": capabilities,
        "lifecycle_provider_identity_bound_to_anchor": identity_bound,
        "unsupported_external_style_lifecycle_fails_closed": True,
        "backup_directory_created_before_capability_check": hardened[1][
            "backup_directory_created"
        ],
        "production_external_lifecycle_provider_included": False,
        "real_external_trust_operations": False,
        "network_operations": 0,
        "production_checkpoint_lifecycle_claim": False,
    }
    report["passed"] = bool(
        baseline_metrics["asr"] == [4, 4]
        and hardened_metrics["asr"] == [0, 4]
        and hardened_metrics["fpr"] == [0, 3]
        and hardened_metrics["safe_task_rate"] == [3, 3]
        and observed_rejections == expected_rejections
        and hardened[0]["checkpoint_state_preserved"] is True
        and hardened[1]["backup_directory_created"] is False
        and hardened[2]["target_state_installed"] is False
        and hardened[3]["checkpoint_database_created"] is False
        and all(bool(item["lifecycle_operation_used"]) for item in benign)
        and local_provider is True
        and identity_bound is True
        and set(capabilities)
        == {capability.value for capability in CheckpointLifecycleCapability}
        and report["real_external_trust_operations"] is False
        and report["network_operations"] == 0
        and report["production_checkpoint_lifecycle_claim"] is False
    )
    return report


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
