from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aegis.agent.checkpoint_backup_format import (
    P4E_LOCAL_BACKUP_KEY,
    P4E_LOCAL_BACKUP_KEY_ID,
    sign_package,
)
from aegis.agent.checkpoint_backup_hash import sha256_file
from aegis.agent.checkpoint_backup_manifest import build_manifest
from aegis.agent.checkpoint_backup_storage import (
    require_active_ciphertext,
    snapshot_sqlite,
    validate_heads,
)
from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_operation_runtime import (
    OperationProviderKeyLifecycleCheckpointer,
)
from aegis.agent.checkpoint_runtime_contracts import (
    CheckpointBackupAuthenticationOperationProvider,
)
from aegis.agent.checkpoint_runtime_providers import LocalSqliteCheckpointAnchorProvider


@dataclass(frozen=True)
class CheckpointBackupArtifact:
    backup_id: str
    checkpoint_heads: int
    active_encryption_key_id: str


def _snapshot_anchor(
    saver: KeyLifecycleConfidentialCheckpointer,
    destination: Path,
) -> None:
    provider = getattr(saver, "anchor_provider", None)
    snapshot = getattr(provider, "snapshot_to", None)
    if callable(snapshot):
        snapshot(destination)
        return
    snapshot_sqlite(saver.anchor_database_path, destination)


def _candidate_from_snapshot(
    saver: KeyLifecycleConfidentialCheckpointer,
    *,
    checkpoint_path: Path,
    anchor_path: Path,
) -> KeyLifecycleConfidentialCheckpointer:
    if isinstance(saver, OperationProviderKeyLifecycleCheckpointer):
        return OperationProviderKeyLifecycleCheckpointer(
            database_path=checkpoint_path,
            anchor_database_path=anchor_path,
            key_provider=saver.key_provider,
            integrity_provider=saver.integrity_provider,
            anchor_provider=LocalSqliteCheckpointAnchorProvider(
                database_path=anchor_path,
                provider_id=getattr(
                    saver.anchor_provider,
                    "provider_id",
                    "local-sqlite-agent-checkpoint-anchor",
                ),
            ),
        )
    return KeyLifecycleConfidentialCheckpointer(
        database_path=checkpoint_path,
        anchor_database_path=anchor_path,
        key_provider=saver.key_provider,
        hmac_key=saver._hmac_key,
        key_id=saver.key_id,
    )


def create_checkpoint_backup(
    saver: KeyLifecycleConfidentialCheckpointer,
    backup_directory: Path,
    *,
    backup_key: bytes = P4E_LOCAL_BACKUP_KEY,
    backup_key_id: str = P4E_LOCAL_BACKUP_KEY_ID,
    backup_authentication_provider: (
        CheckpointBackupAuthenticationOperationProvider | None
    ) = None,
) -> CheckpointBackupArtifact:
    root = Path(backup_directory)
    root.mkdir(parents=True, exist_ok=True)
    checkpoint_path = root / "checkpoints.sqlite3"
    anchor_path = root / "anchors.sqlite3"
    with saver._lock:
        snapshot_sqlite(saver.database_path, checkpoint_path)
        _snapshot_anchor(saver, anchor_path)
    candidate = _candidate_from_snapshot(
        saver,
        checkpoint_path=checkpoint_path,
        anchor_path=anchor_path,
    )
    heads = validate_heads(candidate)
    require_active_ciphertext(candidate)
    manifest = build_manifest(
        saver,
        backup_key_id=backup_key_id,
        checkpoint_sha256=sha256_file(checkpoint_path),
        anchor_sha256=sha256_file(anchor_path),
        heads=heads,
    )
    (root / "manifest.json").write_bytes(
        sign_package(
            manifest,
            key=(None if backup_authentication_provider is not None else bytes(backup_key)),
            provider=backup_authentication_provider,
        )
    )
    return CheckpointBackupArtifact(
        backup_id=str(manifest["backup_id"]),
        checkpoint_heads=len(heads),
        active_encryption_key_id=saver.key_provider.active_key_id,
    )
