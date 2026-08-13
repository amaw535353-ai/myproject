from __future__ import annotations

import hashlib
import shutil

import pytest

from aegis.agent.checkpoint_backup import (
    AuthenticatedCheckpointBackupManager,
    CheckpointBackupError,
    CheckpointBackupReason,
    P4E_CHECKPOINT_BACKUP_POLICY_VERSION,
)
from aegis.agent.checkpoint_backup_format import P4E_LOCAL_BACKUP_KEY, open_package
from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from apps.api.dependencies import get_agent_checkpointer
from evals.p4e_backup_common import marker, put, saver
from evals.p4e_checkpoint_backup_restore import build_report


def test_default_checkpointer_can_be_wrapped_by_p4e_manager(client, tmp_path) -> None:
    checkpointer = get_agent_checkpointer()
    manager = AuthenticatedCheckpointBackupManager(saver=checkpointer)
    assert isinstance(checkpointer, KeyLifecycleConfidentialCheckpointer)
    assert manager.saver is checkpointer
    assert manager.policy_version == P4E_CHECKPOINT_BACKUP_POLICY_VERSION


def test_backup_keeps_dynamic_checkpoint_content_encrypted(client, tmp_path) -> None:
    checkpointer = get_agent_checkpointer()
    marker_value = "P4E-BACKUP-SECRET-MARKER-4821"
    response = client.post(
        "/v1/agent/run",
        json={"message": f"search: {marker_value}"},
        headers={"X-Aegis-User": "alice@northstar-dynamics.test"},
    )
    assert response.status_code == 200
    backup = tmp_path / "backup"
    artifact = AuthenticatedCheckpointBackupManager(saver=checkpointer).create_backup(backup)
    manifest = open_package((backup / "manifest.json").read_bytes(), key=P4E_LOCAL_BACKUP_KEY)
    assert artifact.backup_id == manifest["backup_id"]
    assert marker_value.encode() not in (backup / "checkpoints.sqlite3").read_bytes()
    assert manifest["active_encryption_key_id"] == checkpointer.key_provider.active_key_id
    assert manifest["production_backup_claim"] is False


def test_backup_restore_preserves_injected_integrity_key_boundary(tmp_path) -> None:
    integrity_key = hashlib.sha256(b"p4e-custom-integrity-test-key").digest()
    integrity_key_id = "p4e-custom-integrity-test-key-v1"
    source = KeyLifecycleConfidentialCheckpointer(
        database_path=tmp_path / "source" / "checkpoints.sqlite3",
        anchor_database_path=tmp_path / "source" / "anchors.sqlite3",
        hmac_key=integrity_key,
        key_id=integrity_key_id,
    )
    put(
        source,
        thread_id="p4e-custom-integrity",
        checkpoint_id="00000001",
        marker="custom-integrity-state",
    )
    backup = tmp_path / "custom-integrity-backup"
    AuthenticatedCheckpointBackupManager(saver=source).create_backup(backup)
    manifest = open_package((backup / "manifest.json").read_bytes(), key=P4E_LOCAL_BACKUP_KEY)
    assert manifest["integrity_key_id"] == integrity_key_id

    target = KeyLifecycleConfidentialCheckpointer(
        database_path=tmp_path / "target" / "checkpoints.sqlite3",
        anchor_database_path=tmp_path / "target" / "anchors.sqlite3",
        hmac_key=integrity_key,
        key_id=integrity_key_id,
    )
    AuthenticatedCheckpointBackupManager(saver=target).restore_backup(backup)
    assert marker(target, "p4e-custom-integrity") == "custom-integrity-state"


def test_stale_restore_is_rejected_and_current_head_is_preserved(tmp_path) -> None:
    checkpointer = saver(tmp_path / "live")
    first = put(
        checkpointer,
        thread_id="p4e-stale-test",
        checkpoint_id="00000001",
        marker="generation-one",
    )
    backup = tmp_path / "backup"
    manager = AuthenticatedCheckpointBackupManager(saver=checkpointer)
    manager.create_backup(backup)
    put(
        checkpointer,
        thread_id="p4e-stale-test",
        checkpoint_id="00000002",
        marker="generation-two",
        parent=first,
    )
    with pytest.raises(CheckpointBackupError) as raised:
        manager.restore_backup(backup)
    assert raised.value.reason is CheckpointBackupReason.ROLLBACK_DETECTED
    assert marker(checkpointer, "p4e-stale-test") == "generation-two"


def test_backup_file_substitution_is_rejected_before_restore(tmp_path) -> None:
    trusted = saver(tmp_path / "trusted")
    alternate = saver(tmp_path / "alternate")
    put(
        trusted,
        thread_id="p4e-substitute-test",
        checkpoint_id="00000001",
        marker="trusted",
    )
    put(
        alternate,
        thread_id="p4e-substitute-test",
        checkpoint_id="00000001",
        marker="alternate",
    )
    trusted_backup = tmp_path / "trusted-backup"
    alternate_backup = tmp_path / "alternate-backup"
    AuthenticatedCheckpointBackupManager(saver=trusted).create_backup(trusted_backup)
    AuthenticatedCheckpointBackupManager(saver=alternate).create_backup(alternate_backup)
    shutil.copyfile(
        alternate_backup / "checkpoints.sqlite3",
        trusted_backup / "checkpoints.sqlite3",
    )
    shutil.copyfile(
        alternate_backup / "anchors.sqlite3",
        trusted_backup / "anchors.sqlite3",
    )
    target = saver(tmp_path / "target")
    with pytest.raises(CheckpointBackupError) as raised:
        AuthenticatedCheckpointBackupManager(saver=target).restore_backup(trusted_backup)
    assert raised.value.reason is CheckpointBackupReason.AUTHENTICATION_FAILED
    assert marker(target, "p4e-substitute-test") is None


def test_p4e_evaluation_exact_metrics_and_evidence_hygiene() -> None:
    report = build_report()
    assert report["passed"] is True
    baseline = report["variants"]["unauthenticated_restore_baseline"]["metrics"]
    hardened = report["variants"]["authenticated_monotonic_restore_boundary"]["metrics"]
    assert baseline["asr"] == [2, 2]
    assert hardened["asr"] == [0, 2]
    assert hardened["fpr"] == [0, 2]
    assert hardened["safe_task_rate"] == [2, 2]
    assert report["backup_payload_plaintext_added"] is False
    assert report["external_backup_custody"] is False
    assert report["raw_key_bytes_in_report"] is False
    assert report["real_external_operations"] is False
    assert report["production_backup_claim"] is False
