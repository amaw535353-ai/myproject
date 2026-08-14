from __future__ import annotations

import pytest

from aegis.agent.checkpoint_backup import (
    AuthenticatedCheckpointBackupManager,
    CheckpointBackupError,
    CheckpointBackupReason,
)
from aegis.agent.checkpoint_external_contracts import (
    build_synthetic_external_checkpoint_contract_bundle,
)
from aegis.agent.checkpoint_external_runtime_bridge import (
    SyntheticExternalCheckpointAnchorRuntimeBridge,
)
from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_operation_runtime import (
    OperationProviderKeyLifecycleCheckpointer,
)
from aegis.agent.checkpoint_runtime_contracts import (
    P4H_CHECKPOINT_RUNTIME_PROVIDER_POLICY_VERSION,
)
from apps.api.dependencies import (
    get_agent_checkpointer,
    get_checkpoint_backup_manager,
    get_checkpoint_trust_provider_factory,
)
from evals.p4e_backup_common import config, marker, put
from evals.p4h_checkpoint_runtime_provider_seam import build_report


def test_default_api_checkpoint_runtime_uses_operation_providers(client) -> None:
    saver = get_agent_checkpointer()
    factory = get_checkpoint_trust_provider_factory()

    assert isinstance(saver, OperationProviderKeyLifecycleCheckpointer)
    assert isinstance(saver, KeyLifecycleConfidentialCheckpointer)
    assert saver.runtime_provider_policy_version == P4H_CHECKPOINT_RUNTIME_PROVIDER_POLICY_VERSION
    assert saver._hmac_key is None
    assert saver.integrity_provider.provider_id == saver.key_id
    assert saver.anchor_provider.provider_id == "local-sqlite-agent-checkpoint-anchor"
    assert saver.anchor_provider.database_path.resolve() == saver.anchor_database_path.resolve()
    assert factory.manifest is not None


def test_default_backup_manager_uses_operations_without_retaining_raw_backup_key(client) -> None:
    manager = get_checkpoint_backup_manager()

    assert isinstance(manager, AuthenticatedCheckpointBackupManager)
    assert hasattr(manager, "backup_key") is False
    assert manager.backup_authentication_provider.provider_id == manager.backup_key_id
    assert manager.recovery_authority_provider.provider_id == (
        "local-process-checkpoint-recovery-authority"
    )


def test_p4g_integrity_and_anchor_contracts_can_drive_actual_checkpoint_runtime(tmp_path) -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    saver = OperationProviderKeyLifecycleCheckpointer(
        database_path=tmp_path / "checkpoints.sqlite3",
        anchor_database_path=tmp_path / "compatibility-anchor.sqlite3",
        key_provider=bundle.encryption,
        integrity_provider=bundle.integrity,
        anchor_provider=SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor),
    )
    saved = put(
        saver,
        thread_id="p4h-p4g-runtime",
        checkpoint_id="00000001",
        marker="operation-provider-state",
    )
    saver.put_writes(
        saved,
        [("synthetic-result", {"status": "ok"})],
        task_id="p4h-p4g-task",
    )

    item = saver.get_tuple(config("p4h-p4g-runtime"))
    assert item is not None
    assert marker(saver, "p4h-p4g-runtime") == "operation-provider-state"
    assert item.pending_writes
    assert saver._hmac_key is None


def test_recovery_authority_rejection_happens_before_target_install(tmp_path) -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    factory = get_checkpoint_trust_provider_factory()

    source_anchor = tmp_path / "source" / "anchors.sqlite3"
    source = OperationProviderKeyLifecycleCheckpointer(
        database_path=tmp_path / "source" / "checkpoints.sqlite3",
        anchor_database_path=source_anchor,
        key_provider=factory.encryption_key_provider(),
        integrity_provider=factory.integrity_provider(),
        anchor_provider=factory.anchor_provider(source_anchor),
    )
    put(
        source,
        thread_id="p4h-recovery",
        checkpoint_id="00000001",
        marker="must-require-authority",
    )
    backup = tmp_path / "backup"
    AuthenticatedCheckpointBackupManager(
        saver=source,
        backup_authentication_provider=bundle.backup_authentication,
        recovery_authority_provider=bundle.recovery_authority,
    ).create_backup(backup)

    target_anchor = tmp_path / "target" / "anchors.sqlite3"
    target = OperationProviderKeyLifecycleCheckpointer(
        database_path=tmp_path / "target" / "checkpoints.sqlite3",
        anchor_database_path=target_anchor,
        key_provider=factory.encryption_key_provider(),
        integrity_provider=factory.integrity_provider(),
        anchor_provider=factory.anchor_provider(target_anchor),
    )
    manager = AuthenticatedCheckpointBackupManager(
        saver=target,
        backup_authentication_provider=bundle.backup_authentication,
        recovery_authority_provider=bundle.recovery_authority,
    )

    with pytest.raises(CheckpointBackupError) as raised:
        manager.restore_backup(
            backup,
            operator_id="synthetic-unauthorized-recovery-operator",
        )

    assert raised.value.reason is CheckpointBackupReason.RECOVERY_AUTHORIZATION_DENIED
    assert marker(target, "p4h-recovery") is None


def test_p4h_evaluation_exact_metrics_and_evidence_hygiene() -> None:
    report = build_report()
    assert report["passed"] is True
    baseline = report["variants"]["raw_material_direct_anchor_baseline"]["metrics"]
    hardened = report["variants"]["operation_provider_runtime"]["metrics"]
    assert baseline["asr"] == [4, 4]
    assert hardened["asr"] == [0, 4]
    assert hardened["fpr"] == [0, 3]
    assert hardened["safe_task_rate"] == [3, 3]
    assert report["default_runtime_operation_provider_seam"] is True
    assert report["default_runtime_raw_integrity_key_retained"] is False
    assert report["external_anchor_backup_restore_supported"] is False
    assert report["production_external_adapter_implementation_included"] is False
    assert report["real_external_trust_operations"] is False
    assert report["network_operations"] == 0
    assert report["production_checkpoint_runtime_claim"] is False
