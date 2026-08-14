from __future__ import annotations

import sqlite3

from aegis.agent.checkpoint_backup import AuthenticatedCheckpointBackupManager
from aegis.agent.checkpoint_external_contracts import (
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
    build_default_local_synthetic_checkpoint_key_provider,
    build_legacy_single_key_provider,
)
from aegis.agent.checkpoint_lifecycle_capabilities import (
    CheckpointLifecycleCapability,
    LocalSqliteCheckpointLifecycleProvider,
)
from aegis.agent.checkpoint_operation_runtime import (
    OperationProviderKeyLifecycleCheckpointer,
)
from apps.api.dependencies import get_agent_checkpointer
from evals.p4e_backup_common import config, marker, put
from evals.p4j_external_lifecycle_contract import build_report


def _external_saver(tmp_path, name: str, *, bundle, bridge=None, key_provider=None):
    root = tmp_path / name
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


def _poison(saver: OperationProviderKeyLifecycleCheckpointer) -> None:
    path = saver.anchor_database_path
    if path.exists():
        path.unlink()
    path.mkdir()


def test_external_lifecycle_provider_is_bound_without_local_anchor_path(tmp_path) -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    bridge = SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor)
    lifecycle = SyntheticExternalStyleCheckpointLifecycleProvider(anchor_provider=bridge)
    posture = lifecycle.public_posture()

    assert lifecycle.bound_anchor_provider is bridge
    assert lifecycle.anchor_provider_id == bridge.provider_id
    assert lifecycle.capabilities == frozenset(CheckpointLifecycleCapability)
    assert lifecycle.operationally_external is False
    assert lifecycle.synthetic_in_process is True
    assert lifecycle.production_runtime_eligible is False
    assert posture["local_anchor_path_dependency"] is False
    assert posture["local_anchor_path_exposed"] is False
    assert posture["compatibility_anchor_path_accesses"] == 0
    assert posture["anchor_snapshot_format"] == P4J_ANCHOR_SNAPSHOT_FORMAT


def test_external_lifecycle_migration_reencrypts_without_compatibility_anchor(tmp_path) -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    bridge = SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor)
    legacy, _, _ = _external_saver(
        tmp_path,
        "migration",
        bundle=bundle,
        bridge=bridge,
        key_provider=build_legacy_single_key_provider(),
    )
    saved = put(
        legacy,
        thread_id="p4j-migration-test",
        checkpoint_id="00000001",
        marker="migration-state",
    )
    legacy.put_writes(
        saved,
        [("synthetic_pending", {"marker": "migration-pending"})],
        task_id="p4j-task",
    )

    active, _, lifecycle = _external_saver(
        tmp_path,
        "migration",
        bundle=bundle,
        bridge=bridge,
        key_provider=build_default_local_synthetic_checkpoint_key_provider(),
    )
    _poison(active)
    report = active.migrate_to_active_encryption_key()

    connection = sqlite3.connect(active.database_path, timeout=5.0)
    try:
        checkpoint_blob = bytes(connection.execute("SELECT checkpoint FROM checkpoints").fetchone()[0])
        write_blob = bytes(connection.execute("SELECT value FROM writes").fetchone()[0])
    finally:
        connection.close()
    reopened = active.get_tuple(config("p4j-migration-test"))

    assert report.checkpoints_reencrypted == 1
    assert report.writes_reencrypted == 1
    assert active.key_provider.envelope_key_id(checkpoint_blob) == P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID
    assert active.key_provider.envelope_key_id(write_blob) == P4D_LOCAL_SYNTHETIC_ACTIVE_KEY_ID
    assert marker(active, "p4j-migration-test") == "migration-state"
    assert reopened is not None and list(reopened.pending_writes)[0][2]["marker"] == "migration-pending"
    assert lifecycle.migration_calls == 1
    assert lifecycle.compatibility_anchor_path_accesses == 0
    assert active.anchor_database_path.is_dir()


def test_external_lifecycle_backup_restore_uses_provider_state_not_local_anchor(tmp_path) -> None:
    source_bundle = build_synthetic_external_checkpoint_contract_bundle()
    source, source_bridge, source_lifecycle = _external_saver(
        tmp_path, "source", bundle=source_bundle
    )
    saved = put(
        source,
        thread_id="p4j-backup-test",
        checkpoint_id="00000001",
        marker="external-provider-backup",
    )
    source.put_writes(
        saved,
        [("synthetic_pending", {"marker": "backup-pending"})],
        task_id="p4j-backup-task",
    )
    _poison(source)
    backup = tmp_path / "backup"
    AuthenticatedCheckpointBackupManager(
        saver=source,
        backup_authentication_provider=source_bundle.backup_authentication,
        recovery_authority_provider=source_bundle.recovery_authority,
    ).create_backup(backup)

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
    assert backup_heads == list(source_bridge.export_heads())
    assert source_lifecycle.snapshot_calls == 1
    assert source_lifecycle.compatibility_anchor_path_accesses == 0

    target_bundle = build_synthetic_external_checkpoint_contract_bundle()
    target, target_bridge, target_lifecycle = _external_saver(
        tmp_path, "target", bundle=target_bundle
    )
    _poison(target)
    AuthenticatedCheckpointBackupManager(
        saver=target,
        backup_authentication_provider=target_bundle.backup_authentication,
        recovery_authority_provider=target_bundle.recovery_authority,
    ).restore_backup(backup, operator_id="synthetic-recovery-operator")

    reopened = target.get_tuple(config("p4j-backup-test"))
    assert marker(target, "p4j-backup-test") == "external-provider-backup"
    assert reopened is not None and list(reopened.pending_writes)[0][2]["marker"] == "backup-pending"
    assert list(target_bridge.export_heads()) == backup_heads
    assert target_lifecycle.restore_calls == 1
    assert target_lifecycle.compatibility_anchor_path_accesses == 0
    assert target.anchor_database_path.is_dir()


def test_default_api_remains_local_lifecycle_profile(client) -> None:
    saver = get_agent_checkpointer()

    assert isinstance(saver.lifecycle_provider, LocalSqliteCheckpointLifecycleProvider)
    assert not isinstance(
        saver.lifecycle_provider, SyntheticExternalStyleCheckpointLifecycleProvider
    )


def test_p4j_evaluation_exact_metrics_and_evidence_hygiene() -> None:
    report = build_report()
    baseline = report["variants"]["implicit_local_anchor_path_lifecycle_baseline"][
        "metrics"
    ]
    hardened = report["variants"]["external_style_lifecycle_contract"]["metrics"]

    assert report["passed"] is True
    assert baseline["asr"] == [3, 3]
    assert hardened["asr"] == [0, 3]
    assert hardened["fpr"] == [0, 3]
    assert hardened["safe_task_rate"] == [3, 3]
    assert report["policy_version"] == P4J_CHECKPOINT_EXTERNAL_LIFECYCLE_POLICY_VERSION
    assert report["external_lifecycle_contract_harness_included"] is True
    assert report["external_anchor_state_export_import_exercised"] is True
    assert report["local_anchor_path_dependency"] is False
    assert report["local_anchor_path_exposed"] is False
    assert report["compatibility_anchor_path_accesses"] == 0
    assert report["backup_anchor_artifact_generated_from_provider_state"] is True
    assert report["migration_key_custody_external"] is False
    assert report["production_external_lifecycle_provider_included"] is False
    assert report["production_checkpoint_lifecycle_claim"] is False
    assert report["real_external_trust_operations"] is False
    assert report["network_operations"] == 0
