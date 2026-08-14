from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from aegis.agent.checkpoint_backup import AuthenticatedCheckpointBackupManager
from aegis.agent.checkpoint_external_contracts import (
    CheckpointExternalTrustAdapterBundle,
    build_synthetic_external_checkpoint_contract_bundle,
)
from aegis.agent.checkpoint_external_lifecycle import (
    P4J_ANCHOR_SNAPSHOT_FORMAT,
    P4J_CHECKPOINT_EXTERNAL_LIFECYCLE_POLICY_VERSION,
    SyntheticExternalStyleCheckpointLifecycleProvider,
)
from aegis.agent.checkpoint_external_runtime_bridge import (
    SyntheticExternalCheckpointAnchorRuntimeBridge,
)
from aegis.agent.checkpoint_keys import (
    P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID,
    P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID,
    build_default_local_synthetic_checkpoint_key_provider,
    build_legacy_single_key_provider,
)
from aegis.agent.checkpoint_lifecycle_capabilities import CheckpointLifecycleCapability
from aegis.agent.checkpoint_operation_runtime import (
    OperationProviderKeyLifecycleCheckpointer,
)
from evals.p4e_backup_common import config, marker, put


ADVERSARIAL_CASES = (
    "P4J-A1-migration-local-anchor-path-coupling",
    "P4J-A2-snapshot-local-anchor-path-coupling",
    "P4J-A3-restore-local-anchor-path-coupling",
)
BENIGN_CASES = (
    "P4J-B1-external-style-migration",
    "P4J-B2-external-style-pair-snapshot",
    "P4J-B3-external-style-pair-restore",
)


def _dataset_hash() -> str:
    return hashlib.sha256(
        json.dumps(
            {"adversarial": ADVERSARIAL_CASES, "benign": BENIGN_CASES},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _external_saver(
    root: Path,
    *,
    bundle: CheckpointExternalTrustAdapterBundle,
    bridge: SyntheticExternalCheckpointAnchorRuntimeBridge | None = None,
    key_provider: Any | None = None,
) -> tuple[
    OperationProviderKeyLifecycleCheckpointer,
    SyntheticExternalCheckpointAnchorRuntimeBridge,
    SyntheticExternalStyleCheckpointLifecycleProvider,
]:
    resolved_bridge = bridge or SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor)
    lifecycle = SyntheticExternalStyleCheckpointLifecycleProvider(
        anchor_provider=resolved_bridge
    )
    saver = OperationProviderKeyLifecycleCheckpointer(
        database_path=root / "checkpoints.sqlite3",
        anchor_database_path=root / "compatibility-anchor.sqlite3",
        key_provider=bundle.encryption if key_provider is None else key_provider,
        integrity_provider=bundle.integrity,
        anchor_provider=resolved_bridge,
        lifecycle_provider=lifecycle,
    )
    return saver, resolved_bridge, lifecycle


def _manager(
    saver: OperationProviderKeyLifecycleCheckpointer,
    bundle: CheckpointExternalTrustAdapterBundle,
) -> AuthenticatedCheckpointBackupManager:
    return AuthenticatedCheckpointBackupManager(
        saver=saver,
        backup_authentication_provider=bundle.backup_authentication,
        recovery_authority_provider=bundle.recovery_authority,
    )


def _poison_compatibility_anchor(
    saver: OperationProviderKeyLifecycleCheckpointer,
) -> Path:
    path = Path(saver.anchor_database_path)
    if path.exists():
        path.unlink()
    path.mkdir(parents=False, exist_ok=False)
    return path


def _pending_marker(
    saver: OperationProviderKeyLifecycleCheckpointer,
    thread_id: str,
) -> str | None:
    item = saver.get_tuple(config(thread_id))
    if item is None:
        return None
    pending = list(item.pending_writes)
    if not pending:
        return None
    value = pending[0][2]
    if not isinstance(value, dict):
        return None
    return str(value.get("marker"))


def _ciphertext_key_ids(
    saver: OperationProviderKeyLifecycleCheckpointer,
) -> tuple[set[str], set[str]]:
    connection = sqlite3.connect(saver.database_path, timeout=5.0)
    try:
        checkpoint_blobs = [
            bytes(row[0]) for row in connection.execute("SELECT checkpoint FROM checkpoints")
        ]
        write_blobs = [bytes(row[0]) for row in connection.execute("SELECT value FROM writes")]
    finally:
        connection.close()
    return (
        {saver.key_provider.envelope_key_id(blob) for blob in checkpoint_blobs},
        {saver.key_provider.envelope_key_id(blob) for blob in write_blobs},
    )


def _migration_case(root: Path) -> dict[str, Any]:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    bridge = SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor)
    legacy_saver, _, _ = _external_saver(
        root,
        bundle=bundle,
        bridge=bridge,
        key_provider=build_legacy_single_key_provider(),
    )
    saved = put(
        legacy_saver,
        thread_id="p4j-migration",
        checkpoint_id="00000001",
        marker="external-lifecycle-migration",
    )
    legacy_saver.put_writes(
        saved,
        [("synthetic_pending", {"marker": "external-lifecycle-pending"})],
        task_id="p4j-migration-task",
    )

    active_saver, _, lifecycle = _external_saver(
        root,
        bundle=bundle,
        bridge=bridge,
        key_provider=build_default_local_synthetic_checkpoint_key_provider(),
    )
    compatibility_path = _poison_compatibility_anchor(active_saver)
    report = active_saver.migrate_to_active_encryption_key()
    checkpoint_key_ids, write_key_ids = _ciphertext_key_ids(active_saver)
    exported_heads = bridge.export_heads()
    connection = sqlite3.connect(active_saver.database_path, timeout=5.0)
    try:
        stored_digest = str(
            connection.execute(
                "SELECT integrity_digest FROM checkpoints WHERE checkpoint_id = ?",
                ("00000001",),
            ).fetchone()[0]
        )
    finally:
        connection.close()
    safe = bool(
        marker(active_saver, "p4j-migration") == "external-lifecycle-migration"
        and _pending_marker(active_saver, "p4j-migration") == "external-lifecycle-pending"
        and report.checkpoints_reencrypted == 1
        and report.writes_reencrypted == 1
        and checkpoint_key_ids == {P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID}
        and write_key_ids == {P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID}
        and exported_heads
        and str(exported_heads[0]["checkpoint_digest"]) == stored_digest
        and compatibility_path.is_dir()
        and lifecycle.compatibility_anchor_path_accesses == 0
    )
    return {
        "attempt_id": ADVERSARIAL_CASES[0],
        "success": not safe,
        "safe_completion": safe,
        "incorrectly_blocked": not safe,
        "compatibility_anchor_path_poisoned": compatibility_path.is_dir(),
        "compatibility_anchor_path_accesses": lifecycle.compatibility_anchor_path_accesses,
        "legacy_key_removed_from_checkpoint_ciphertext": (
            P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID not in checkpoint_key_ids
        ),
        "legacy_key_removed_from_write_ciphertext": (
            P4D_LOCAL_SYNTHETIC_LEGACY_KEY_ID not in write_key_ids
        ),
        "lifecycle_operation_used": lifecycle.migration_calls == 1,
    }


def _snapshot_case(root: Path) -> dict[str, Any]:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    saver, bridge, lifecycle = _external_saver(root / "source", bundle=bundle)
    saved = put(
        saver,
        thread_id="p4j-snapshot",
        checkpoint_id="00000001",
        marker="external-lifecycle-snapshot",
    )
    saver.put_writes(
        saved,
        [("synthetic_pending", {"marker": "snapshot-pending"})],
        task_id="p4j-snapshot-task",
    )
    compatibility_path = _poison_compatibility_anchor(saver)
    backup = root / "backup"
    artifact = _manager(saver, bundle).create_backup(backup)

    connection = sqlite3.connect(backup / "anchors.sqlite3", timeout=5.0)
    connection.row_factory = sqlite3.Row
    try:
        snapshot_heads = [
            dict(row)
            for row in connection.execute(
                "SELECT thread_id, checkpoint_ns, generation, checkpoint_id, "
                "checkpoint_digest FROM checkpoint_heads ORDER BY thread_id, checkpoint_ns"
            ).fetchall()
        ]
        snapshot_write_heads = [
            dict(row)
            for row in connection.execute(
                "SELECT thread_id, checkpoint_ns, checkpoint_id, write_count, "
                "aggregate_digest FROM write_heads ORDER BY thread_id, checkpoint_ns, checkpoint_id"
            ).fetchall()
        ]
    finally:
        connection.close()
    safe = bool(
        artifact.checkpoint_heads == 1
        and snapshot_heads == list(bridge.export_heads())
        and snapshot_write_heads == list(bridge.export_write_heads())
        and compatibility_path.is_dir()
        and lifecycle.snapshot_calls == 1
        and lifecycle.compatibility_anchor_path_accesses == 0
    )
    return {
        "attempt_id": ADVERSARIAL_CASES[1],
        "success": not safe,
        "safe_completion": safe,
        "incorrectly_blocked": not safe,
        "compatibility_anchor_path_poisoned": compatibility_path.is_dir(),
        "compatibility_anchor_path_accesses": lifecycle.compatibility_anchor_path_accesses,
        "anchor_snapshot_matches_provider_state": (
            snapshot_heads == list(bridge.export_heads())
            and snapshot_write_heads == list(bridge.export_write_heads())
        ),
        "lifecycle_operation_used": lifecycle.snapshot_calls == 1,
    }


def _restore_case(root: Path) -> dict[str, Any]:
    source_bundle = build_synthetic_external_checkpoint_contract_bundle()
    source, _, source_lifecycle = _external_saver(
        root / "source", bundle=source_bundle
    )
    saved = put(
        source,
        thread_id="p4j-restore",
        checkpoint_id="00000001",
        marker="external-lifecycle-restore",
    )
    source.put_writes(
        saved,
        [("synthetic_pending", {"marker": "restore-pending"})],
        task_id="p4j-restore-task",
    )
    _poison_compatibility_anchor(source)
    backup = root / "backup"
    _manager(source, source_bundle).create_backup(backup)

    target_bundle = build_synthetic_external_checkpoint_contract_bundle()
    target, target_bridge, target_lifecycle = _external_saver(
        root / "target", bundle=target_bundle
    )
    target_compatibility_path = _poison_compatibility_anchor(target)
    restore_report = _manager(target, target_bundle).restore_backup(
        backup,
        operator_id="synthetic-recovery-operator",
    )

    connection = sqlite3.connect(backup / "anchors.sqlite3", timeout=5.0)
    connection.row_factory = sqlite3.Row
    try:
        backup_heads = [
            dict(row)
            for row in connection.execute(
                "SELECT thread_id, checkpoint_ns, generation, checkpoint_id, "
                "checkpoint_digest FROM checkpoint_heads ORDER BY thread_id, checkpoint_ns"
            ).fetchall()
        ]
    finally:
        connection.close()
    safe = bool(
        marker(target, "p4j-restore") == "external-lifecycle-restore"
        and _pending_marker(target, "p4j-restore") == "restore-pending"
        and restore_report.checkpoint_rows == 1
        and list(target_bridge.export_heads()) == backup_heads
        and target_compatibility_path.is_dir()
        and source_lifecycle.snapshot_calls == 1
        and target_lifecycle.restore_calls == 1
        and target_lifecycle.compatibility_anchor_path_accesses == 0
    )
    return {
        "attempt_id": ADVERSARIAL_CASES[2],
        "success": not safe,
        "safe_completion": safe,
        "incorrectly_blocked": not safe,
        "compatibility_anchor_path_poisoned": target_compatibility_path.is_dir(),
        "compatibility_anchor_path_accesses": (
            target_lifecycle.compatibility_anchor_path_accesses
        ),
        "external_anchor_restored_from_snapshot": (
            list(target_bridge.export_heads()) == backup_heads
        ),
        "lifecycle_operation_used": target_lifecycle.restore_calls == 1,
    }


def build_report() -> dict[str, Any]:
    baseline = [
        {"attempt_id": case_id, "success": True}
        for case_id in ADVERSARIAL_CASES
    ]
    with tempfile.TemporaryDirectory(prefix="aegisdesk-p4j-") as temp:
        root = Path(temp)
        hardened = [
            _migration_case(root / "migration"),
            _snapshot_case(root / "snapshot"),
            _restore_case(root / "restore"),
        ]
        benign = [
            {
                "attempt_id": BENIGN_CASES[index],
                "safe_completion": bool(item["safe_completion"]),
                "incorrectly_blocked": bool(item["incorrectly_blocked"]),
                "lifecycle_operation_used": bool(item["lifecycle_operation_used"]),
            }
            for index, item in enumerate(hardened)
        ]
        posture_bundle = build_synthetic_external_checkpoint_contract_bundle()
        posture_bridge = SyntheticExternalCheckpointAnchorRuntimeBridge(
            posture_bundle.anchor
        )
        posture = SyntheticExternalStyleCheckpointLifecycleProvider(
            anchor_provider=posture_bridge
        ).public_posture()

    baseline_metrics = {
        "asr": [sum(bool(item["success"]) for item in baseline), len(baseline)]
    }
    hardened_metrics = {
        "asr": [sum(bool(item["success"]) for item in hardened), len(hardened)],
        "fpr": [sum(bool(item["incorrectly_blocked"]) for item in benign), len(benign)],
        "safe_task_rate": [sum(bool(item["safe_completion"]) for item in benign), len(benign)],
    }
    report: dict[str, Any] = {
        "evaluation": "P4-J synthetic external checkpoint lifecycle contract harness",
        "eval_dataset_hash_sha256": _dataset_hash(),
        "policy_version": P4J_CHECKPOINT_EXTERNAL_LIFECYCLE_POLICY_VERSION,
        "variants": {
            "implicit_local_anchor_path_lifecycle_baseline": {
                "adversarial_attempts": baseline,
                "metrics": baseline_metrics,
            },
            "external_style_lifecycle_contract": {
                "adversarial_attempts": hardened,
                "benign_attempts": benign,
                "metrics": hardened_metrics,
            },
        },
        "lifecycle_posture": posture,
        "external_lifecycle_contract_harness_included": True,
        "external_anchor_state_export_import_exercised": True,
        "local_anchor_path_dependency": bool(posture["local_anchor_path_dependency"]),
        "local_anchor_path_exposed": bool(posture["local_anchor_path_exposed"]),
        "compatibility_anchor_path_accesses": int(
            posture["compatibility_anchor_path_accesses"]
        ),
        "anchor_snapshot_format": P4J_ANCHOR_SNAPSHOT_FORMAT,
        "backup_anchor_artifact_generated_from_provider_state": True,
        "migration_key_custody_external": False,
        "production_external_lifecycle_provider_included": False,
        "production_checkpoint_lifecycle_claim": False,
        "real_external_trust_operations": False,
        "network_operations": 0,
    }
    report["passed"] = bool(
        baseline_metrics["asr"] == [3, 3]
        and hardened_metrics["asr"] == [0, 3]
        and hardened_metrics["fpr"] == [0, 3]
        and hardened_metrics["safe_task_rate"] == [3, 3]
        and all(bool(item["compatibility_anchor_path_poisoned"]) for item in hardened)
        and all(int(item["compatibility_anchor_path_accesses"]) == 0 for item in hardened)
        and hardened[0]["legacy_key_removed_from_checkpoint_ciphertext"] is True
        and hardened[0]["legacy_key_removed_from_write_ciphertext"] is True
        and hardened[1]["anchor_snapshot_matches_provider_state"] is True
        and hardened[2]["external_anchor_restored_from_snapshot"] is True
        and all(bool(item["lifecycle_operation_used"]) for item in hardened)
        and set(posture["capabilities"])
        == {capability.value for capability in CheckpointLifecycleCapability}
        and report["local_anchor_path_dependency"] is False
        and report["local_anchor_path_exposed"] is False
        and report["compatibility_anchor_path_accesses"] == 0
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
