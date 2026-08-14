from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Mapping
from enum import StrEnum
from pathlib import Path
from typing import Any

from langchain_core.runnables import RunnableConfig

from aegis.agent.checkpoint_confidentiality import _typed_aad
from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_keys import CheckpointKeyMigrationReport
from aegis.agent.checkpoint_lifecycle_capabilities import (
    CheckpointLifecycleCapability,
    CheckpointLifecycleCapabilityError,
    CheckpointLifecycleReason,
    require_lifecycle_capability,
)


P4J_CHECKPOINT_EXTERNAL_LIFECYCLE_POLICY_VERSION = (
    "synthetic-external-checkpoint-lifecycle-contract-v1"
)
P4J_ANCHOR_SNAPSHOT_FORMAT = "sqlite-exported-external-anchor-state-v1"


class CheckpointExternalLifecycleReason(StrEnum):
    ANCHOR_STATE_EXPORT_UNSUPPORTED = "checkpoint_external_lifecycle_anchor_export_unsupported"
    ANCHOR_STATE_IMPORT_UNSUPPORTED = "checkpoint_external_lifecycle_anchor_import_unsupported"
    ANCHOR_SNAPSHOT_INVALID = "checkpoint_external_lifecycle_anchor_snapshot_invalid"


class CheckpointExternalLifecycleError(RuntimeError):
    def __init__(self, reason: CheckpointExternalLifecycleReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


def _snapshot_sqlite(source: Path, destination: Path) -> None:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        destination.unlink()
    source_connection = sqlite3.connect(source, timeout=5.0)
    destination_connection = sqlite3.connect(destination, timeout=5.0)
    try:
        source_connection.backup(destination_connection)
    finally:
        destination_connection.close()
        source_connection.close()


def _write_anchor_snapshot(
    destination: Path,
    *,
    checkpoint_heads: Iterable[Mapping[str, object]],
    write_heads: Iterable[Mapping[str, object]],
) -> None:
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        destination.unlink()
    connection = sqlite3.connect(destination, timeout=5.0)
    try:
        connection.executescript(
            """
            CREATE TABLE checkpoint_heads (
                thread_id TEXT NOT NULL,
                checkpoint_ns TEXT NOT NULL DEFAULT '',
                generation INTEGER NOT NULL CHECK (generation >= 1),
                checkpoint_id TEXT NOT NULL,
                checkpoint_digest TEXT NOT NULL,
                PRIMARY KEY (thread_id, checkpoint_ns)
            );
            CREATE TABLE write_heads (
                thread_id TEXT NOT NULL,
                checkpoint_ns TEXT NOT NULL DEFAULT '',
                checkpoint_id TEXT NOT NULL,
                write_count INTEGER NOT NULL CHECK (write_count >= 0),
                aggregate_digest TEXT NOT NULL,
                PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id)
            );
            """
        )
        connection.executemany(
            """
            INSERT INTO checkpoint_heads (
                thread_id, checkpoint_ns, generation, checkpoint_id, checkpoint_digest
            ) VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    str(item["thread_id"]),
                    str(item.get("checkpoint_ns", "")),
                    int(item["generation"]),
                    str(item["checkpoint_id"]),
                    str(item["checkpoint_digest"]),
                )
                for item in checkpoint_heads
            ],
        )
        connection.executemany(
            """
            INSERT INTO write_heads (
                thread_id, checkpoint_ns, checkpoint_id, write_count, aggregate_digest
            ) VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    str(item["thread_id"]),
                    str(item.get("checkpoint_ns", "")),
                    str(item["checkpoint_id"]),
                    int(item["write_count"]),
                    str(item["aggregate_digest"]),
                )
                for item in write_heads
            ],
        )
        connection.commit()
    except (KeyError, TypeError, ValueError, sqlite3.DatabaseError) as exc:
        raise CheckpointExternalLifecycleError(
            CheckpointExternalLifecycleReason.ANCHOR_SNAPSHOT_INVALID
        ) from exc
    finally:
        connection.close()


def _read_anchor_snapshot(
    source: Path,
) -> tuple[tuple[dict[str, object], ...], tuple[dict[str, object], ...]]:
    connection = sqlite3.connect(source, timeout=5.0)
    connection.row_factory = sqlite3.Row
    try:
        checkpoint_rows = connection.execute(
            """
            SELECT thread_id, checkpoint_ns, generation, checkpoint_id, checkpoint_digest
            FROM checkpoint_heads
            ORDER BY thread_id, checkpoint_ns
            """
        ).fetchall()
        write_rows = connection.execute(
            """
            SELECT thread_id, checkpoint_ns, checkpoint_id, write_count, aggregate_digest
            FROM write_heads
            ORDER BY thread_id, checkpoint_ns, checkpoint_id
            """
        ).fetchall()
    except sqlite3.DatabaseError as exc:
        raise CheckpointExternalLifecycleError(
            CheckpointExternalLifecycleReason.ANCHOR_SNAPSHOT_INVALID
        ) from exc
    finally:
        connection.close()
    return (
        tuple(dict(row) for row in checkpoint_rows),
        tuple(dict(row) for row in write_rows),
    )


class SyntheticExternalStyleCheckpointLifecycleProvider:
    """In-process external-style lifecycle contract bound to an external anchor bridge.

    The provider exercises P4-I migration, pair snapshot, and pair restore without
    consulting ``saver.anchor_database_path``. Checkpoint data remains in the local
    SQLite lab store, while authoritative anchor state is exported from and restored
    to the injected operation provider. The backup anchor artifact is SQLite-shaped
    solely for P4-E compatibility; it is generated from provider state and is not a
    snapshot of a live local anchor database.

    This class is a synthetic contract harness. It performs no network operations,
    provides no independent failure domain, and is not eligible for a production
    lifecycle or disaster-recovery claim.
    """

    provider_id = "synthetic-external-contract-checkpoint-lifecycle"
    synthetic_in_process = True
    operationally_external = False
    production_runtime_eligible = False
    local_anchor_path_dependency = False
    local_anchor_path_exposed = False
    anchor_snapshot_format = P4J_ANCHOR_SNAPSHOT_FORMAT
    capabilities = frozenset(CheckpointLifecycleCapability)

    def __init__(self, *, anchor_provider: Any) -> None:
        if not str(getattr(anchor_provider, "provider_id", "")).strip():
            raise ValueError("external lifecycle anchor provider id must be non-empty")
        self._anchor_provider = anchor_provider
        self.anchor_provider_id = str(anchor_provider.provider_id)
        self.migration_calls = 0
        self.snapshot_calls = 0
        self.restore_calls = 0
        self.compatibility_anchor_path_accesses = 0

    @property
    def bound_anchor_provider(self) -> Any:
        return self._anchor_provider

    def _assert_bound_saver(self, saver: KeyLifecycleConfidentialCheckpointer) -> None:
        if getattr(saver, "anchor_provider", None) is not self._anchor_provider:
            raise CheckpointLifecycleCapabilityError(
                CheckpointLifecycleReason.ANCHOR_PROVIDER_MISMATCH
            )
        if str(getattr(saver.anchor_provider, "provider_id", "")) != self.anchor_provider_id:
            raise CheckpointLifecycleCapabilityError(
                CheckpointLifecycleReason.ANCHOR_PROVIDER_MISMATCH
            )

    def _export_anchor_state(
        self,
    ) -> tuple[tuple[dict[str, object], ...], tuple[dict[str, object], ...]]:
        export_heads = getattr(self._anchor_provider, "export_heads", None)
        export_write_heads = getattr(self._anchor_provider, "export_write_heads", None)
        if not callable(export_heads) or not callable(export_write_heads):
            raise CheckpointExternalLifecycleError(
                CheckpointExternalLifecycleReason.ANCHOR_STATE_EXPORT_UNSUPPORTED
            )
        return (
            tuple(dict(item) for item in export_heads()),
            tuple(dict(item) for item in export_write_heads()),
        )

    def _replace_anchor_state(
        self,
        *,
        checkpoint_heads: Iterable[Mapping[str, object]],
        write_heads: Iterable[Mapping[str, object]],
    ) -> None:
        replace_state = getattr(self._anchor_provider, "replace_state", None)
        if not callable(replace_state):
            raise CheckpointExternalLifecycleError(
                CheckpointExternalLifecycleReason.ANCHOR_STATE_IMPORT_UNSUPPORTED
            )
        replace_state(
            checkpoint_heads=checkpoint_heads,
            write_heads=write_heads,
        )

    def migrate_to_active_encryption_key(
        self,
        saver: KeyLifecycleConfidentialCheckpointer,
    ) -> CheckpointKeyMigrationReport:
        require_lifecycle_capability(self, CheckpointLifecycleCapability.MIGRATION)
        self._assert_bound_saver(saver)
        self.migration_calls += 1
        active_key_id = saver.key_provider.active_key_id

        with saver._lock:
            with saver._connect(saver.database_path) as read_connection:
                identifiers = list(
                    read_connection.execute(
                        """
                        SELECT thread_id, checkpoint_ns, checkpoint_id
                        FROM checkpoints
                        ORDER BY thread_id, checkpoint_ns, generation
                        """
                    ).fetchall()
                )
                namespaces = list(
                    read_connection.execute(
                        """
                        SELECT DISTINCT thread_id, checkpoint_ns
                        FROM checkpoints
                        ORDER BY thread_id, checkpoint_ns
                        """
                    ).fetchall()
                )

            for namespace in namespaces:
                saver.get_tuple(
                    {
                        "configurable": {
                            "thread_id": str(namespace["thread_id"]),
                            "checkpoint_ns": str(namespace["checkpoint_ns"]),
                        }
                    }
                )
            for identifier in identifiers:
                saver.get_tuple(
                    {
                        "configurable": {
                            "thread_id": str(identifier["thread_id"]),
                            "checkpoint_ns": str(identifier["checkpoint_ns"]),
                            "checkpoint_id": str(identifier["checkpoint_id"]),
                        }
                    }
                )

            previous_checkpoint_heads, previous_write_heads = self._export_anchor_state()
            connection = saver._connect(saver.database_path)
            anchor_replaced = False
            checkpoint_rows: list[Any] = []
            write_rows: list[Any] = []
            checkpoints_reencrypted = 0
            writes_reencrypted = 0
            try:
                connection.execute("BEGIN IMMEDIATE")
                checkpoint_rows = list(
                    connection.execute(
                        """
                        SELECT thread_id, checkpoint_ns, checkpoint_id,
                               parent_checkpoint_id, type, checkpoint, metadata,
                               generation
                        FROM checkpoints
                        ORDER BY thread_id, checkpoint_ns, generation
                        """
                    ).fetchall()
                )
                previous_by_namespace: dict[tuple[str, str], str] = {}
                heads: dict[tuple[str, str], tuple[int, str, str]] = {}

                for row in checkpoint_rows:
                    thread_id = str(row["thread_id"])
                    checkpoint_ns = str(row["checkpoint_ns"])
                    checkpoint_id = str(row["checkpoint_id"])
                    type_tag = str(row["type"])
                    generation = int(row["generation"])
                    namespace = (thread_id, checkpoint_ns)
                    old_blob = bytes(row["checkpoint"])
                    plaintext = saver.key_provider.decrypt(
                        old_blob,
                        aad=_typed_aad(type_tag),
                    )
                    if saver.key_provider.envelope_key_id(old_blob) == active_key_id:
                        new_blob = old_blob
                    else:
                        new_blob = saver.key_provider.encrypt(
                            plaintext,
                            aad=_typed_aad(type_tag),
                        )
                        checkpoints_reencrypted += 1
                    previous_digest = (
                        "0" * 64
                        if generation == 1
                        else previous_by_namespace[namespace]
                    )
                    parent_checkpoint_id = (
                        None
                        if row["parent_checkpoint_id"] is None
                        else str(row["parent_checkpoint_id"])
                    )
                    digest = saver._checkpoint_digest(
                        thread_id=thread_id,
                        checkpoint_ns=checkpoint_ns,
                        checkpoint_id=checkpoint_id,
                        parent_checkpoint_id=parent_checkpoint_id,
                        type_tag=type_tag,
                        checkpoint_blob=new_blob,
                        metadata_blob=bytes(row["metadata"]),
                        generation=generation,
                        previous_digest=previous_digest,
                    )
                    connection.execute(
                        """
                        UPDATE checkpoints
                        SET checkpoint = ?, previous_digest = ?, integrity_digest = ?
                        WHERE thread_id = ? AND checkpoint_ns = ? AND checkpoint_id = ?
                        """,
                        (
                            new_blob,
                            previous_digest,
                            digest,
                            thread_id,
                            checkpoint_ns,
                            checkpoint_id,
                        ),
                    )
                    previous_by_namespace[namespace] = digest
                    heads[namespace] = (generation, checkpoint_id, digest)

                write_rows = list(
                    connection.execute(
                        """
                        SELECT thread_id, checkpoint_ns, checkpoint_id,
                               task_id, idx, channel, type, value
                        FROM writes
                        ORDER BY thread_id, checkpoint_ns, checkpoint_id, task_id, idx
                        """
                    ).fetchall()
                )
                write_groups: set[tuple[str, str, str]] = set()
                for row in write_rows:
                    thread_id = str(row["thread_id"])
                    checkpoint_ns = str(row["checkpoint_ns"])
                    checkpoint_id = str(row["checkpoint_id"])
                    task_id = str(row["task_id"])
                    idx = int(row["idx"])
                    channel = str(row["channel"])
                    type_tag = str(row["type"])
                    old_blob = bytes(row["value"])
                    plaintext = saver.key_provider.decrypt(
                        old_blob,
                        aad=_typed_aad(type_tag),
                    )
                    if saver.key_provider.envelope_key_id(old_blob) == active_key_id:
                        new_blob = old_blob
                    else:
                        new_blob = saver.key_provider.encrypt(
                            plaintext,
                            aad=_typed_aad(type_tag),
                        )
                        writes_reencrypted += 1
                    digest = saver._write_digest(
                        thread_id=thread_id,
                        checkpoint_ns=checkpoint_ns,
                        checkpoint_id=checkpoint_id,
                        task_id=task_id,
                        idx=idx,
                        channel=channel,
                        type_tag=type_tag,
                        value_blob=new_blob,
                    )
                    connection.execute(
                        """
                        UPDATE writes
                        SET value = ?, integrity_digest = ?
                        WHERE thread_id = ? AND checkpoint_ns = ? AND checkpoint_id = ?
                          AND task_id = ? AND idx = ?
                        """,
                        (
                            new_blob,
                            digest,
                            thread_id,
                            checkpoint_ns,
                            checkpoint_id,
                            task_id,
                            idx,
                        ),
                    )
                    write_groups.add((thread_id, checkpoint_ns, checkpoint_id))

                next_checkpoint_heads = tuple(
                    {
                        "thread_id": thread_id,
                        "checkpoint_ns": checkpoint_ns,
                        "generation": generation,
                        "checkpoint_id": checkpoint_id,
                        "checkpoint_digest": digest,
                    }
                    for (thread_id, checkpoint_ns), (
                        generation,
                        checkpoint_id,
                        digest,
                    ) in sorted(heads.items())
                )
                next_write_heads_by_key = {
                    (
                        str(item["thread_id"]),
                        str(item.get("checkpoint_ns", "")),
                        str(item["checkpoint_id"]),
                    ): dict(item)
                    for item in previous_write_heads
                }
                for thread_id, checkpoint_ns, checkpoint_id in sorted(write_groups):
                    rows = saver._write_rows(
                        connection,
                        thread_id=thread_id,
                        checkpoint_ns=checkpoint_ns,
                        checkpoint_id=checkpoint_id,
                    )
                    next_write_heads_by_key[(thread_id, checkpoint_ns, checkpoint_id)] = {
                        "thread_id": thread_id,
                        "checkpoint_ns": checkpoint_ns,
                        "checkpoint_id": checkpoint_id,
                        "write_count": len(rows),
                        "aggregate_digest": saver._write_aggregate(rows),
                    }

                self._replace_anchor_state(
                    checkpoint_heads=next_checkpoint_heads,
                    write_heads=tuple(
                        next_write_heads_by_key[key]
                        for key in sorted(next_write_heads_by_key)
                    ),
                )
                anchor_replaced = True
                connection.commit()
            except BaseException:
                connection.rollback()
                if anchor_replaced:
                    self._replace_anchor_state(
                        checkpoint_heads=previous_checkpoint_heads,
                        write_heads=previous_write_heads,
                    )
                raise
            finally:
                connection.close()

            for namespace in namespaces:
                current_config: RunnableConfig = {
                    "configurable": {
                        "thread_id": str(namespace["thread_id"]),
                        "checkpoint_ns": str(namespace["checkpoint_ns"]),
                    }
                }
                saver.get_tuple(current_config)

        return CheckpointKeyMigrationReport(
            active_key_id=active_key_id,
            checkpoints_reencrypted=checkpoints_reencrypted,
            writes_reencrypted=writes_reencrypted,
            checkpoints_examined=len(checkpoint_rows),
            writes_examined=len(write_rows),
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
            checkpoint_heads, write_heads = self._export_anchor_state()
            _snapshot_sqlite(saver.database_path, checkpoint_destination)
            _write_anchor_snapshot(
                anchor_destination,
                checkpoint_heads=checkpoint_heads,
                write_heads=write_heads,
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
        backup_checkpoint_heads, backup_write_heads = _read_anchor_snapshot(
            backup_anchor_path
        )

        with saver._lock:
            previous_checkpoint_heads, previous_write_heads = self._export_anchor_state()
            connection = saver._connect(saver.database_path)
            anchor_replaced = False
            try:
                connection.execute(
                    "ATTACH DATABASE ? AS source_db", (str(backup_database_path),)
                )
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("DELETE FROM writes")
                connection.execute("DELETE FROM checkpoints")
                connection.execute(
                    "INSERT INTO checkpoints SELECT * FROM source_db.checkpoints"
                )
                connection.execute("INSERT INTO writes SELECT * FROM source_db.writes")
                self._replace_anchor_state(
                    checkpoint_heads=backup_checkpoint_heads,
                    write_heads=backup_write_heads,
                )
                anchor_replaced = True
                connection.commit()
            except BaseException:
                connection.rollback()
                if anchor_replaced:
                    self._replace_anchor_state(
                        checkpoint_heads=previous_checkpoint_heads,
                        write_heads=previous_write_heads,
                    )
                raise
            finally:
                connection.close()

    def public_posture(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "anchor_provider_id": self.anchor_provider_id,
            "capabilities": sorted(capability.value for capability in self.capabilities),
            "synthetic_in_process": self.synthetic_in_process,
            "operationally_external": self.operationally_external,
            "production_runtime_eligible": self.production_runtime_eligible,
            "local_anchor_path_dependency": self.local_anchor_path_dependency,
            "local_anchor_path_exposed": self.local_anchor_path_exposed,
            "anchor_snapshot_format": self.anchor_snapshot_format,
            "compatibility_anchor_path_accesses": self.compatibility_anchor_path_accesses,
        }
