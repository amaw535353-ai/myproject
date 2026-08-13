from __future__ import annotations

from pathlib import Path

from langchain_core.runnables import RunnableConfig

from aegis.agent.checkpoint_confidentiality import (
    ConfidentialDurableIntegrityCheckpointer,
    _AeadCheckpointSerializer,
    _typed_aad,
)
from aegis.agent.checkpoint_durability import (
    P4B_LOCAL_SYNTHETIC_HMAC_KEY,
    P4B_LOCAL_SYNTHETIC_KEY_ID,
)
from aegis.agent.checkpoint_keys import (
    P4D_CHECKPOINT_KEY_LIFECYCLE_POLICY_VERSION,
    CheckpointEncryptionKeyProvider,
    CheckpointKeyMigrationReport,
    build_default_local_synthetic_checkpoint_key_provider,
)


class KeyLifecycleConfidentialCheckpointer(ConfidentialDurableIntegrityCheckpointer):
    """P4-C saver with a versioned provider and explicit re-encryption migration."""

    key_lifecycle_policy_version = P4D_CHECKPOINT_KEY_LIFECYCLE_POLICY_VERSION

    def __init__(
        self,
        *,
        database_path: Path,
        anchor_database_path: Path,
        key_provider: CheckpointEncryptionKeyProvider | None = None,
        hmac_key: bytes = P4B_LOCAL_SYNTHETIC_HMAC_KEY,
        key_id: str = P4B_LOCAL_SYNTHETIC_KEY_ID,
    ) -> None:
        provider = key_provider or build_default_local_synthetic_checkpoint_key_provider()
        super().__init__(
            database_path=database_path,
            anchor_database_path=anchor_database_path,
            hmac_key=hmac_key,
            key_id=key_id,
        )
        self._key_provider = provider
        self._cipher = provider
        self.encryption_key_id = provider.active_key_id
        self.serde = _AeadCheckpointSerializer(
            inner=self._plaintext_serde,
            cipher=provider,
        )

    @property
    def key_provider(self) -> CheckpointEncryptionKeyProvider:
        return self._key_provider

    def migrate_to_active_encryption_key(self) -> CheckpointKeyMigrationReport:
        """Re-encrypt durable checkpoint and pending-write ciphertext under the active key."""

        active_key_id = self._key_provider.active_key_id
        with self._lock:
            with self._connect(self.database_path) as connection:
                identifiers = list(
                    connection.execute(
                        """
                        SELECT thread_id, checkpoint_ns, checkpoint_id
                        FROM checkpoints
                        ORDER BY thread_id, checkpoint_ns, generation
                        """
                    ).fetchall()
                )
                namespaces = list(
                    connection.execute(
                        """
                        SELECT DISTINCT thread_id, checkpoint_ns
                        FROM checkpoints
                        ORDER BY thread_id, checkpoint_ns
                        """
                    ).fetchall()
                )

            for namespace in namespaces:
                self.get_tuple(
                    {
                        "configurable": {
                            "thread_id": str(namespace["thread_id"]),
                            "checkpoint_ns": str(namespace["checkpoint_ns"]),
                        }
                    }
                )
            for identifier in identifiers:
                self.get_tuple(
                    {
                        "configurable": {
                            "thread_id": str(identifier["thread_id"]),
                            "checkpoint_ns": str(identifier["checkpoint_ns"]),
                            "checkpoint_id": str(identifier["checkpoint_id"]),
                        }
                    }
                )

            connection = self._connect(self.database_path)
            try:
                connection.execute(
                    "ATTACH DATABASE ? AS anchor_db",
                    (str(self.anchor_database_path),),
                )
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
                checkpoints_reencrypted = 0
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
                    plaintext = self._key_provider.decrypt(
                        old_blob,
                        aad=_typed_aad(type_tag),
                    )
                    if self._key_provider.envelope_key_id(old_blob) == active_key_id:
                        new_blob = old_blob
                    else:
                        new_blob = self._key_provider.encrypt(
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
                    digest = self._checkpoint_digest(
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

                for (thread_id, checkpoint_ns), head in heads.items():
                    generation, checkpoint_id, digest = head
                    connection.execute(
                        """
                        UPDATE anchor_db.checkpoint_heads
                        SET generation = ?, checkpoint_id = ?, checkpoint_digest = ?
                        WHERE thread_id = ? AND checkpoint_ns = ?
                        """,
                        (generation, checkpoint_id, digest, thread_id, checkpoint_ns),
                    )

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
                writes_reencrypted = 0
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
                    plaintext = self._key_provider.decrypt(
                        old_blob,
                        aad=_typed_aad(type_tag),
                    )
                    if self._key_provider.envelope_key_id(old_blob) == active_key_id:
                        new_blob = old_blob
                    else:
                        new_blob = self._key_provider.encrypt(
                            plaintext,
                            aad=_typed_aad(type_tag),
                        )
                        writes_reencrypted += 1
                    digest = self._write_digest(
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

                for thread_id, checkpoint_ns, checkpoint_id in write_groups:
                    rows = self._write_rows(
                        connection,
                        thread_id=thread_id,
                        checkpoint_ns=checkpoint_ns,
                        checkpoint_id=checkpoint_id,
                    )
                    connection.execute(
                        """
                        UPDATE anchor_db.write_heads
                        SET write_count = ?, aggregate_digest = ?
                        WHERE thread_id = ? AND checkpoint_ns = ? AND checkpoint_id = ?
                        """,
                        (
                            len(rows),
                            self._write_aggregate(rows),
                            thread_id,
                            checkpoint_ns,
                            checkpoint_id,
                        ),
                    )
                connection.commit()
            except BaseException:
                connection.rollback()
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
                self.get_tuple(current_config)

        return CheckpointKeyMigrationReport(
            active_key_id=active_key_id,
            checkpoints_reencrypted=checkpoints_reencrypted,
            writes_reencrypted=writes_reencrypted,
            checkpoints_examined=len(checkpoint_rows),
            writes_examined=len(write_rows),
        )