from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aegis.agent.checkpoint_backup_format import (
    P4E_BACKUP_SCHEMA,
    P4E_CHECKPOINT_BACKUP_POLICY_VERSION,
    P4E_LOCAL_BACKUP_KEY,
    P4E_LOCAL_BACKUP_KEY_ID,
    CheckpointBackupError,
    CheckpointBackupReason,
    canonical_json,
    open_package,
    sha256_hex,
)
from aegis.agent.checkpoint_backup_hash import sha256_file
from aegis.agent.checkpoint_backup_storage import (
    apply_restore,
    check_restore_boundary,
    require_active_ciphertext,
    row_counts,
    validate_heads,
)
from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_security import P4A_CHECKPOINT_POLICY_VERSION


@dataclass(frozen=True)
class CheckpointRestoreReport:
    backup_id: str
    checkpoint_heads: int
    checkpoint_rows: int
    write_rows: int
    active_encryption_key_id: str


def restore_checkpoint_backup(
    saver: KeyLifecycleConfidentialCheckpointer,
    backup_directory: Path,
    *,
    backup_key: bytes = P4E_LOCAL_BACKUP_KEY,
    backup_key_id: str = P4E_LOCAL_BACKUP_KEY_ID,
) -> CheckpointRestoreReport:
    root = Path(backup_directory)
    checkpoint_path = root / "checkpoints.sqlite3"
    anchor_path = root / "anchors.sqlite3"
    manifest_path = root / "manifest.json"
    if not checkpoint_path.is_file() or not anchor_path.is_file() or not manifest_path.is_file():
        raise CheckpointBackupError(CheckpointBackupReason.PACKAGE_INVALID)
    manifest = open_package(manifest_path.read_bytes(), key=bytes(backup_key))
    if (
        manifest.get("schema") != P4E_BACKUP_SCHEMA
        or manifest.get("policy_version") != P4E_CHECKPOINT_BACKUP_POLICY_VERSION
        or manifest.get("serialization_policy_version") != P4A_CHECKPOINT_POLICY_VERSION
        or manifest.get("key_lifecycle_policy_version") != saver.key_lifecycle_policy_version
        or manifest.get("backup_key_id") != backup_key_id
        or manifest.get("integrity_key_id") != saver.key_id
    ):
        raise CheckpointBackupError(CheckpointBackupReason.PACKAGE_INVALID)
    if manifest.get("active_encryption_key_id") != saver.key_provider.active_key_id:
        raise CheckpointBackupError(CheckpointBackupReason.ACTIVE_KEY_MISMATCH)
    if (
        manifest.get("checkpoint_sha256") != sha256_file(checkpoint_path)
        or manifest.get("anchor_sha256") != sha256_file(anchor_path)
    ):
        raise CheckpointBackupError(CheckpointBackupReason.AUTHENTICATION_FAILED)
    without_id = dict(manifest)
    backup_id = without_id.pop("backup_id", None)
    if not isinstance(backup_id, str) or backup_id != sha256_hex(canonical_json(without_id)):
        raise CheckpointBackupError(CheckpointBackupReason.PACKAGE_INVALID)
    raw_heads = manifest.get("checkpoint_heads")
    if not isinstance(raw_heads, list) or any(not isinstance(item, dict) for item in raw_heads):
        raise CheckpointBackupError(CheckpointBackupReason.PACKAGE_INVALID)
    backup_heads = [dict(item) for item in raw_heads]

    try:
        candidate = KeyLifecycleConfidentialCheckpointer(
            database_path=checkpoint_path,
            anchor_database_path=anchor_path,
            key_provider=saver.key_provider,
        )
        observed_heads = validate_heads(candidate)
        require_active_ciphertext(candidate)
    except CheckpointBackupError:
        raise
    except Exception as exc:
        raise CheckpointBackupError(CheckpointBackupReason.VALIDATION_FAILED) from exc
    if canonical_json({"heads": observed_heads}) != canonical_json({"heads": backup_heads}):
        raise CheckpointBackupError(CheckpointBackupReason.VALIDATION_FAILED)
    checkpoint_rows, write_rows = row_counts(checkpoint_path)

    with saver._lock:
        check_restore_boundary(
            saver,
            backup_database_path=checkpoint_path,
            backup_heads=backup_heads,
        )
        apply_restore(
            saver,
            backup_database_path=checkpoint_path,
            backup_anchor_path=anchor_path,
        )
        restored_heads = validate_heads(saver)
        require_active_ciphertext(saver)
    if canonical_json({"heads": restored_heads}) != canonical_json({"heads": backup_heads}):
        raise CheckpointBackupError(CheckpointBackupReason.VALIDATION_FAILED)

    return CheckpointRestoreReport(
        backup_id=backup_id,
        checkpoint_heads=len(backup_heads),
        checkpoint_rows=checkpoint_rows,
        write_rows=write_rows,
        active_encryption_key_id=saver.key_provider.active_key_id,
    )
