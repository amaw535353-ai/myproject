from __future__ import annotations

import sqlite3
from enum import StrEnum
from pathlib import Path
from typing import Protocol, runtime_checkable

from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_keys import CheckpointKeyMigrationReport
from aegis.agent.checkpoint_runtime_contracts import CheckpointAnchorOperationProvider
from aegis.agent.checkpoint_runtime_providers import LocalSqliteCheckpointAnchorProvider


P4I_CHECKPOINT_LIFECYCLE_CAPABILITY_POLICY_VERSION = (
    "checkpoint-lifecycle-capability-provider-v1"
)


class CheckpointLifecycleCapability(StrEnum):
    MIGRATION = "checkpoint_encryption_migration"
    SNAPSHOT = "checkpoint_backup_snapshot"
    RESTORE = "checkpoint_backup_restore"


class CheckpointLifecycleReason(StrEnum):
    PROVIDER_MISSING = "checkpoint_lifecycle_provider_missing"
    ANCHOR_PROVIDER_MISMATCH = "checkpoint_lifecycle_anchor_provider_mismatch"
    CAPABILITY_UNSUPPORTED = "checkpoint_lifecycle_capability_unsupported"


class CheckpointLifecycleCapabilityError(RuntimeError):
    def __init__(
        self,
        reason: CheckpointLifecycleReason,
        *,
        capability: CheckpointLifecycleCapability | None = None,
    ) -> None:
        self.reason = reason
        self.capability = capability
        detail = reason.value
        if capability is not None:
            detail = f"{detail}:{capability.value}"
        super().__init__(detail)


@runtime_checkable
class CheckpointLifecycleOperationProvider(Protocol):
    provider_id: str
    anchor_provider_id: str
    capabilities: frozenset[CheckpointLifecycleCapability]
    synthetic_in_process: bool
    operationally_external: bool

    def migrate_to_active_encryption_key(
        self,
        saver: KeyLifecycleConfidentialCheckpointer,
    ) -> CheckpointKeyMigrationReport: ...

    def snapshot_pair(
        self,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        checkpoint_destination: Path,
        anchor_destination: Path,
    ) -> None: ...

    def restore_pair(
        self,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        backup_database_path: Path,
        backup_anchor_path: Path,
    ) -> None: ...


def assert_lifecycle_provider_compatible(
    anchor_provider: CheckpointAnchorOperationProvider,
    lifecycle_provider: CheckpointLifecycleOperationProvider,
) -> None:
    if (
        not str(getattr(lifecycle_provider, "provider_id", "")).strip()
        or str(getattr(lifecycle_provider, "anchor_provider_id", ""))
        != str(getattr(anchor_provider, "provider_id", ""))
    ):
        raise CheckpointLifecycleCapabilityError(
            CheckpointLifecycleReason.ANCHOR_PROVIDER_MISMATCH
        )
    bound_anchor = getattr(lifecycle_provider, "bound_anchor_provider", None)
    if bound_anchor is not None and bound_anchor is not anchor_provider:
        raise CheckpointLifecycleCapabilityError(
            CheckpointLifecycleReason.ANCHOR_PROVIDER_MISMATCH
        )


def require_lifecycle_capability(
    provider: CheckpointLifecycleOperationProvider | None,
    capability: CheckpointLifecycleCapability,
) -> CheckpointLifecycleOperationProvider:
    if provider is None:
        raise CheckpointLifecycleCapabilityError(
            CheckpointLifecycleReason.PROVIDER_MISSING,
            capability=capability,
        )
    capabilities = frozenset(getattr(provider, "capabilities", frozenset()))
    operation_name = {
        CheckpointLifecycleCapability.MIGRATION: "migrate_to_active_encryption_key",
        CheckpointLifecycleCapability.SNAPSHOT: "snapshot_pair",
        CheckpointLifecycleCapability.RESTORE: "restore_pair",
    }[capability]
    if capability not in capabilities or not callable(getattr(provider, operation_name, None)):
        raise CheckpointLifecycleCapabilityError(
            CheckpointLifecycleReason.CAPABILITY_UNSUPPORTED,
            capability=capability,
        )
    return provider


def _snapshot_sqlite(source: Path, destination: Path) -> None:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_connection = sqlite3.connect(source, timeout=5.0)
    destination_connection = sqlite3.connect(destination, timeout=5.0)
    try:
        source_connection.backup(destination_connection)
    finally:
        destination_connection.close()
        source_connection.close()


class LocalSqliteCheckpointLifecycleProvider:
    """Local-only lifecycle operations bound to one SQLite anchor provider.

    This provider exists to make the local P4-D/P4-E assumptions explicit. Its
    pair snapshot, restore, and migration coordination are single-process lab
    behavior; they do not establish distributed atomicity or external trust.
    """

    provider_id = "local-sqlite-agent-checkpoint-lifecycle"
    synthetic_in_process = True
    operationally_external = False
    capabilities = frozenset(CheckpointLifecycleCapability)

    def __init__(self, *, anchor_provider: LocalSqliteCheckpointAnchorProvider) -> None:
        self._anchor_provider = anchor_provider
        self.anchor_provider_id = str(anchor_provider.provider_id)
        self.migration_calls = 0
        self.snapshot_calls = 0
        self.restore_calls = 0

    @property
    def bound_anchor_provider(self) -> LocalSqliteCheckpointAnchorProvider:
        return self._anchor_provider

    def _assert_bound_saver(
        self,
        saver: KeyLifecycleConfidentialCheckpointer,
    ) -> None:
        saver_anchor = getattr(saver, "anchor_provider", None)
        if saver_anchor is not self._anchor_provider:
            raise CheckpointLifecycleCapabilityError(
                CheckpointLifecycleReason.ANCHOR_PROVIDER_MISMATCH
            )
        if Path(saver.anchor_database_path).resolve() != self._anchor_provider.database_path.resolve():
            raise CheckpointLifecycleCapabilityError(
                CheckpointLifecycleReason.ANCHOR_PROVIDER_MISMATCH
            )

    def migrate_to_active_encryption_key(
        self,
        saver: KeyLifecycleConfidentialCheckpointer,
    ) -> CheckpointKeyMigrationReport:
        require_lifecycle_capability(self, CheckpointLifecycleCapability.MIGRATION)
        self._assert_bound_saver(saver)
        self.migration_calls += 1
        with saver._lock:
            with self._anchor_provider._lock:
                return KeyLifecycleConfidentialCheckpointer.migrate_to_active_encryption_key(
                    saver
                )

    def snapshot_pair(
        self,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        checkpoint_destination: Path,
        anchor_destination: Path,
    ) -> None:
        require_lifecycle_capability(self, CheckpointLifecycleCapability.SNAPSHOT)
        self._assert_bound_saver(saver)
        self.snapshot_calls += 1
        with saver._lock:
            with self._anchor_provider._lock:
                _snapshot_sqlite(saver.database_path, checkpoint_destination)
                _snapshot_sqlite(
                    self._anchor_provider.database_path,
                    anchor_destination,
                )

    def restore_pair(
        self,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        backup_database_path: Path,
        backup_anchor_path: Path,
    ) -> None:
        require_lifecycle_capability(self, CheckpointLifecycleCapability.RESTORE)
        self._assert_bound_saver(saver)
        self.restore_calls += 1
        with saver._lock:
            with self._anchor_provider._lock:
                connection = saver._connect(saver.database_path)
                try:
                    connection.execute(
                        "ATTACH DATABASE ? AS target_anchor",
                        (str(self._anchor_provider.database_path),),
                    )
                    connection.execute(
                        "ATTACH DATABASE ? AS source_db",
                        (str(backup_database_path),),
                    )
                    connection.execute(
                        "ATTACH DATABASE ? AS source_anchor",
                        (str(backup_anchor_path),),
                    )
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute("DELETE FROM writes")
                    connection.execute("DELETE FROM checkpoints")
                    connection.execute("DELETE FROM target_anchor.write_heads")
                    connection.execute("DELETE FROM target_anchor.checkpoint_heads")
                    connection.execute(
                        "INSERT INTO checkpoints SELECT * FROM source_db.checkpoints"
                    )
                    connection.execute("INSERT INTO writes SELECT * FROM source_db.writes")
                    connection.execute(
                        "INSERT INTO target_anchor.checkpoint_heads "
                        "SELECT * FROM source_anchor.checkpoint_heads"
                    )
                    connection.execute(
                        "INSERT INTO target_anchor.write_heads "
                        "SELECT * FROM source_anchor.write_heads"
                    )
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
                finally:
                    connection.close()
