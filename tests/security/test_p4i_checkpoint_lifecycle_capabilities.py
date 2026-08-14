from __future__ import annotations

import pytest

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
from apps.api.dependencies import get_agent_checkpointer
from evals.p4e_backup_common import marker, put
from evals.p4i_checkpoint_lifecycle_capabilities import build_report


def _local_saver(tmp_path, name: str) -> OperationProviderKeyLifecycleCheckpointer:
    factory = LocalSyntheticCheckpointOperationProviderFactory()
    root = tmp_path / name
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


def _external_saver(tmp_path, name: str) -> OperationProviderKeyLifecycleCheckpointer:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    root = tmp_path / name
    return OperationProviderKeyLifecycleCheckpointer(
        database_path=root / "checkpoints.sqlite3",
        anchor_database_path=root / "compatibility-anchor.sqlite3",
        key_provider=bundle.encryption,
        integrity_provider=bundle.integrity,
        anchor_provider=SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor),
    )


def test_default_api_injects_bound_lifecycle_provider(client) -> None:
    saver = get_agent_checkpointer()
    provider = saver.lifecycle_provider

    assert saver.lifecycle_capability_policy_version == (
        P4I_CHECKPOINT_LIFECYCLE_CAPABILITY_POLICY_VERSION
    )
    assert isinstance(provider, LocalSqliteCheckpointLifecycleProvider)
    assert provider.bound_anchor_provider is saver.anchor_provider
    assert provider.anchor_provider_id == saver.anchor_provider.provider_id
    assert provider.capabilities == frozenset(CheckpointLifecycleCapability)
    assert provider.operationally_external is False


def test_lifecycle_anchor_mismatch_rejected_before_checkpoint_database_creation(
    tmp_path,
) -> None:
    factory = LocalSyntheticCheckpointOperationProviderFactory()
    first_anchor = factory.anchor_provider(tmp_path / "first-anchor.sqlite3")
    lifecycle = factory.lifecycle_provider(first_anchor)
    second_anchor = factory.anchor_provider(tmp_path / "second-anchor.sqlite3")
    checkpoint_path = tmp_path / "checkpoints.sqlite3"

    with pytest.raises(CheckpointLifecycleCapabilityError) as raised:
        OperationProviderKeyLifecycleCheckpointer(
            database_path=checkpoint_path,
            anchor_database_path=tmp_path / "second-anchor.sqlite3",
            key_provider=factory.encryption_key_provider(),
            integrity_provider=factory.integrity_provider(),
            anchor_provider=second_anchor,
            lifecycle_provider=lifecycle,
        )

    assert raised.value.reason is CheckpointLifecycleReason.ANCHOR_PROVIDER_MISMATCH
    assert checkpoint_path.exists() is False


def test_external_style_runtime_without_lifecycle_provider_fails_before_lifecycle_state_change(
    tmp_path,
) -> None:
    saver = _external_saver(tmp_path, "external")
    put(
        saver,
        thread_id="p4i-external",
        checkpoint_id="00000001",
        marker="core-runtime-still-supported",
    )

    with pytest.raises(CheckpointLifecycleCapabilityError) as migration_raised:
        saver.migrate_to_active_encryption_key()
    assert migration_raised.value.reason is CheckpointLifecycleReason.PROVIDER_MISSING
    assert migration_raised.value.capability is CheckpointLifecycleCapability.MIGRATION
    assert marker(saver, "p4i-external") == "core-runtime-still-supported"

    backup_path = tmp_path / "unsupported-backup"
    with pytest.raises(CheckpointLifecycleCapabilityError) as backup_raised:
        AuthenticatedCheckpointBackupManager(saver=saver).create_backup(backup_path)
    assert backup_raised.value.reason is CheckpointLifecycleReason.PROVIDER_MISSING
    assert backup_raised.value.capability is CheckpointLifecycleCapability.SNAPSHOT
    assert backup_path.exists() is False


def test_local_backup_restore_routes_through_lifecycle_provider(tmp_path) -> None:
    source = _local_saver(tmp_path, "source")
    put(
        source,
        thread_id="p4i-local",
        checkpoint_id="00000001",
        marker="provider-routed-state",
    )
    source_provider = source.lifecycle_provider
    backup = tmp_path / "backup"
    AuthenticatedCheckpointBackupManager(saver=source).create_backup(backup)

    assert getattr(source_provider, "snapshot_calls", 0) == 1

    target = _local_saver(tmp_path, "target")
    target_provider = target.lifecycle_provider
    AuthenticatedCheckpointBackupManager(saver=target).restore_backup(backup)

    assert getattr(target_provider, "restore_calls", 0) == 1
    assert marker(target, "p4i-local") == "provider-routed-state"


def test_p4i_evaluation_exact_metrics_and_evidence_hygiene() -> None:
    report = build_report()
    baseline = report["variants"]["implicit_local_lifecycle_assumption_baseline"][
        "metrics"
    ]
    hardened = report["variants"]["capability_bound_lifecycle_runtime"]["metrics"]

    assert report["passed"] is True
    assert baseline["asr"] == [4, 4]
    assert hardened["asr"] == [0, 4]
    assert hardened["fpr"] == [0, 3]
    assert hardened["safe_task_rate"] == [3, 3]
    assert report["default_factory_lifecycle_provider_explicit"] is True
    assert report["lifecycle_provider_identity_bound_to_anchor"] is True
    assert report["backup_directory_created_before_capability_check"] is False
    assert report["production_external_lifecycle_provider_included"] is False
    assert report["real_external_trust_operations"] is False
    assert report["network_operations"] == 0
    assert report["production_checkpoint_lifecycle_claim"] is False
