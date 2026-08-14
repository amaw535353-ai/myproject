from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    WRITES_IDX_MAP,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    get_checkpoint_metadata,
)

from aegis.agent.checkpoint_confidentiality import _assert_metadata_minimized, _typed_aad
from aegis.agent.checkpoint_durability import (
    P4B_CHECKPOINT_SCHEMA,
    P4B_WRITE_SCHEMA,
    CheckpointIntegrityError,
    CheckpointIntegrityReason,
    _canonical_json,
    _sha256,
)
from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_keys import (
    CheckpointEncryptionKeyProvider,
    CheckpointKeyMigrationReport,
    build_default_local_synthetic_checkpoint_key_provider,
)
from aegis.agent.checkpoint_lifecycle_capabilities import (
    P4I_CHECKPOINT_LIFECYCLE_CAPABILITY_POLICY_VERSION,
    CheckpointLifecycleCapability,
    CheckpointLifecycleOperationProvider,
    LocalSqliteCheckpointLifecycleProvider,
    assert_lifecycle_provider_compatible,
    require_lifecycle_capability,
)
from aegis.agent.checkpoint_runtime_contracts import (
    P4H_CHECKPOINT_RUNTIME_PROVIDER_POLICY_VERSION,
    CheckpointAnchorOperationProvider,
    CheckpointIntegrityOperationProvider,
    encode_checkpoint_scope,
)
from aegis.agent.checkpoint_runtime_providers import LocalSqliteCheckpointAnchorProvider


_P4H_COMPATIBILITY_BOOTSTRAP_HMAC_KEY = b"\x00" * 32
_ZERO_DIGEST = "0" * 64


class OperationProviderKeyLifecycleCheckpointer(KeyLifecycleConfidentialCheckpointer):
    """Checkpoint runtime whose integrity, anchor, and lifecycle trust are providers.

    The inherited local HMAC/SQLite implementation remains available for backward
    compatibility elsewhere in the lab, but this class routes checkpoint/write
    authentication and current-head operations through injected provider
    contracts. P4-I additionally routes migration, pair snapshot, and restore
    through an explicit lifecycle provider when those operations are requested.
    The zero-valued constructor key is only a superclass bootstrap value and is
    discarded after initialization; it is never used to authenticate runtime
    state.
    """

    runtime_provider_policy_version = P4H_CHECKPOINT_RUNTIME_PROVIDER_POLICY_VERSION
    lifecycle_capability_policy_version = (
        P4I_CHECKPOINT_LIFECYCLE_CAPABILITY_POLICY_VERSION
    )

    def __init__(
        self,
        *,
        database_path: Path,
        anchor_database_path: Path,
        integrity_provider: CheckpointIntegrityOperationProvider,
        anchor_provider: CheckpointAnchorOperationProvider,
        key_provider: CheckpointEncryptionKeyProvider | None = None,
        lifecycle_provider: CheckpointLifecycleOperationProvider | None = None,
    ) -> None:
        resolved_lifecycle_provider = lifecycle_provider
        if (
            resolved_lifecycle_provider is None
            and isinstance(anchor_provider, LocalSqliteCheckpointAnchorProvider)
        ):
            resolved_lifecycle_provider = LocalSqliteCheckpointLifecycleProvider(
                anchor_provider=anchor_provider
            )
        if resolved_lifecycle_provider is not None:
            assert_lifecycle_provider_compatible(
                anchor_provider,
                resolved_lifecycle_provider,
            )

        self._integrity_provider = integrity_provider
        self._anchor_provider = anchor_provider
        self._lifecycle_provider = resolved_lifecycle_provider
        super().__init__(
            database_path=database_path,
            anchor_database_path=anchor_database_path,
            key_provider=(
                key_provider
                if key_provider is not None
                else build_default_local_synthetic_checkpoint_key_provider()
            ),
            hmac_key=_P4H_COMPATIBILITY_BOOTSTRAP_HMAC_KEY,
            key_id=integrity_provider.provider_id,
        )
        self._hmac_key = None
        self.key_id = integrity_provider.provider_id

    @property
    def integrity_provider(self) -> CheckpointIntegrityOperationProvider:
        return self._integrity_provider

    @property
    def anchor_provider(self) -> CheckpointAnchorOperationProvider:
        return self._anchor_provider

    @property
    def lifecycle_provider(self) -> CheckpointLifecycleOperationProvider | None:
        return self._lifecycle_provider

    def require_lifecycle_capability(
        self,
        capability: CheckpointLifecycleCapability,
    ) -> CheckpointLifecycleOperationProvider:
        provider = require_lifecycle_capability(self._lifecycle_provider, capability)
        assert_lifecycle_provider_compatible(self._anchor_provider, provider)
        return provider

    def migrate_to_active_encryption_key(self) -> CheckpointKeyMigrationReport:
        provider = self.require_lifecycle_capability(
            CheckpointLifecycleCapability.MIGRATION
        )
        return provider.migrate_to_active_encryption_key(self)

    @staticmethod
    def _scope(thread_id: str, checkpoint_ns: str) -> str:
        return encode_checkpoint_scope(thread_id, checkpoint_ns)

    def _checkpoint_authentication_payload(
        self,
        *,
        thread_id: str,
        checkpoint_ns: str,
        checkpoint_id: str,
        parent_checkpoint_id: str | None,
        type_tag: str,
        checkpoint_blob: bytes,
        metadata_blob: bytes,
        generation: int,
        previous_digest: str,
    ) -> bytes:
        return _canonical_json(
            {
                "schema_version": P4B_CHECKPOINT_SCHEMA,
                "thread_id": thread_id,
                "checkpoint_ns": checkpoint_ns,
                "checkpoint_id": checkpoint_id,
                "parent_checkpoint_id": parent_checkpoint_id,
                "type": type_tag,
                "checkpoint_sha256": _sha256(checkpoint_blob),
                "metadata_sha256": _sha256(metadata_blob),
                "generation": generation,
                "previous_digest": previous_digest,
                "key_id": self.key_id,
            }
        )

    def _write_authentication_payload(
        self,
        *,
        thread_id: str,
        checkpoint_ns: str,
        checkpoint_id: str,
        task_id: str,
        idx: int,
        channel: str,
        type_tag: str,
        value_blob: bytes,
    ) -> bytes:
        return _canonical_json(
            {
                "schema_version": P4B_WRITE_SCHEMA,
                "thread_id": thread_id,
                "checkpoint_ns": checkpoint_ns,
                "checkpoint_id": checkpoint_id,
                "task_id": task_id,
                "idx": idx,
                "channel": channel,
                "type": type_tag,
                "value_sha256": _sha256(value_blob),
                "key_id": self.key_id,
            }
        )

    def _write_aggregate_payload(self, rows: Sequence[Any]) -> bytes:
        entries = [
            {
                "task_id": str(row["task_id"]),
                "idx": int(row["idx"]),
                "channel": str(row["channel"]),
                "integrity_digest": str(row["integrity_digest"]),
            }
            for row in rows
        ]
        return _canonical_json(
            {
                "schema_version": P4B_WRITE_SCHEMA,
                "entries": entries,
                "key_id": self.key_id,
            }
        )

    def _hmac(self, payload: bytes) -> str:
        return self._integrity_provider.authenticate(bytes(payload))

    def _checkpoint_digest(self, **kwargs: Any) -> str:
        return self._integrity_provider.authenticate(
            self._checkpoint_authentication_payload(**kwargs)
        )

    def _write_digest(self, **kwargs: Any) -> str:
        return self._integrity_provider.authenticate(
            self._write_authentication_payload(**kwargs)
        )

    def _write_aggregate(self, rows: Sequence[Any]) -> str:
        return self._integrity_provider.authenticate(self._write_aggregate_payload(rows))

    def _verify_checkpoint_row(self, row: Any) -> None:
        parent_checkpoint_id = (
            None
            if row["parent_checkpoint_id"] is None
            else str(row["parent_checkpoint_id"])
        )
        payload = self._checkpoint_authentication_payload(
            thread_id=str(row["thread_id"]),
            checkpoint_ns=str(row["checkpoint_ns"]),
            checkpoint_id=str(row["checkpoint_id"]),
            parent_checkpoint_id=parent_checkpoint_id,
            type_tag=str(row["type"]),
            checkpoint_blob=bytes(row["checkpoint"]),
            metadata_blob=bytes(row["metadata"]),
            generation=int(row["generation"]),
            previous_digest=str(row["previous_digest"]),
        )
        if not self._integrity_provider.verify(payload, str(row["integrity_digest"])):
            raise CheckpointIntegrityError(
                CheckpointIntegrityReason.CHECKPOINT_INTEGRITY_MISMATCH
            )

    def _current_head(self, thread_id: str, checkpoint_ns: str):
        return self._anchor_provider.current_head(self._scope(thread_id, checkpoint_ns))

    def _verify_write_set(
        self,
        *,
        thread_id: str,
        checkpoint_ns: str,
        checkpoint_id: str,
        rows: Sequence[Any],
    ) -> None:
        for row in rows:
            payload = self._write_authentication_payload(
                thread_id=thread_id,
                checkpoint_ns=checkpoint_ns,
                checkpoint_id=checkpoint_id,
                task_id=str(row["task_id"]),
                idx=int(row["idx"]),
                channel=str(row["channel"]),
                type_tag=str(row["type"]),
                value_blob=bytes(row["value"]),
            )
            if not self._integrity_provider.verify(
                payload,
                str(row["integrity_digest"]),
            ):
                raise CheckpointIntegrityError(
                    CheckpointIntegrityReason.WRITE_INTEGRITY_MISMATCH
                )

        head = self._anchor_provider.current_write_head(
            self._scope(thread_id, checkpoint_ns),
            checkpoint_id,
        )
        if not rows and head is None:
            return
        if head is None:
            raise CheckpointIntegrityError(CheckpointIntegrityReason.WRITE_SET_MISMATCH)
        if (
            int(head.write_count) != len(rows)
            or not self._integrity_provider.verify(
                self._write_aggregate_payload(rows),
                str(head.aggregate_digest),
            )
        ):
            raise CheckpointIntegrityError(CheckpointIntegrityReason.WRITE_SET_MISMATCH)

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        del new_versions
        _assert_metadata_minimized(metadata)
        thread_id = str(config["configurable"]["thread_id"])
        checkpoint_ns = str(config["configurable"].get("checkpoint_ns", ""))
        checkpoint_id = str(checkpoint["id"])
        parent_checkpoint_id = config["configurable"].get("checkpoint_id")
        if parent_checkpoint_id is not None:
            parent_checkpoint_id = str(parent_checkpoint_id)

        new_type_tag, new_plaintext_blob = self._plaintext_serde.dumps_typed(checkpoint)
        metadata_blob = json.dumps(
            get_checkpoint_metadata(config, metadata),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", "ignore")

        with self._lock:
            with self._connect(self.database_path) as connection:
                existing = self._checkpoint_row(
                    connection,
                    thread_id=thread_id,
                    checkpoint_ns=checkpoint_ns,
                    checkpoint_id=checkpoint_id,
                )
            if existing is not None:
                self._verify_checkpoint_row(existing)
                existing_type = str(existing["type"])
                same_type = existing_type == str(new_type_tag)
                existing_plaintext = (
                    self._cipher.decrypt(
                        bytes(existing["checkpoint"]),
                        aad=_typed_aad(existing_type),
                    )
                    if same_type
                    else b""
                )
                existing_parent = (
                    None
                    if existing["parent_checkpoint_id"] is None
                    else str(existing["parent_checkpoint_id"])
                )
                if (
                    same_type
                    and existing_plaintext == bytes(new_plaintext_blob)
                    and bytes(existing["metadata"]) == metadata_blob
                    and existing_parent == parent_checkpoint_id
                ):
                    return {
                        "configurable": {
                            "thread_id": thread_id,
                            "checkpoint_ns": checkpoint_ns,
                            "checkpoint_id": checkpoint_id,
                        }
                    }
                raise CheckpointIntegrityError(
                    CheckpointIntegrityReason.CHECKPOINT_CONFLICT
                )

            type_tag, checkpoint_blob = self.serde.dumps_typed(checkpoint)
            head = self._current_head(thread_id, checkpoint_ns)
            generation = 1 if head is None else int(head.generation) + 1
            previous_digest = (
                _ZERO_DIGEST if head is None else str(head.checkpoint_digest)
            )
            digest = self._checkpoint_digest(
                thread_id=thread_id,
                checkpoint_ns=checkpoint_ns,
                checkpoint_id=checkpoint_id,
                parent_checkpoint_id=parent_checkpoint_id,
                type_tag=str(type_tag),
                checkpoint_blob=checkpoint_blob,
                metadata_blob=metadata_blob,
                generation=generation,
                previous_digest=previous_digest,
            )

            with self._connect(self.database_path) as connection:
                connection.execute(
                    """
                    INSERT INTO checkpoints (
                        thread_id, checkpoint_ns, checkpoint_id,
                        parent_checkpoint_id, type, checkpoint, metadata,
                        generation, previous_digest, integrity_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        thread_id,
                        checkpoint_ns,
                        checkpoint_id,
                        parent_checkpoint_id,
                        str(type_tag),
                        checkpoint_blob,
                        metadata_blob,
                        generation,
                        previous_digest,
                        digest,
                    ),
                )

            try:
                self._anchor_provider.advance(
                    self._scope(thread_id, checkpoint_ns),
                    generation=generation,
                    checkpoint_id=checkpoint_id,
                    checkpoint_digest=digest,
                    expected_generation=(None if head is None else int(head.generation)),
                )
            except BaseException:
                with self._connect(self.database_path) as connection:
                    connection.execute(
                        """
                        DELETE FROM checkpoints
                        WHERE thread_id = ? AND checkpoint_ns = ? AND checkpoint_id = ?
                        """,
                        (thread_id, checkpoint_ns, checkpoint_id),
                    )
                raise

        return {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_ns": checkpoint_ns,
                "checkpoint_id": checkpoint_id,
            }
        }

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        del task_path
        thread_id = str(config["configurable"]["thread_id"])
        checkpoint_ns = str(config["configurable"].get("checkpoint_ns", ""))
        checkpoint_id = str(config["configurable"]["checkpoint_id"])
        replace = all(channel in WRITES_IDX_MAP for channel, _ in writes)
        query = (
            "INSERT OR REPLACE INTO writes "
            if replace
            else "INSERT OR IGNORE INTO writes "
        ) + """(
            thread_id, checkpoint_ns, checkpoint_id, task_id, idx,
            channel, type, value, integrity_digest
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"""

        candidates: list[tuple[object, ...]] = []
        for idx, (channel, value) in enumerate(writes):
            resolved_idx = WRITES_IDX_MAP.get(channel, idx)
            type_tag, value_blob = self.serde.dumps_typed(value)
            digest = self._write_digest(
                thread_id=thread_id,
                checkpoint_ns=checkpoint_ns,
                checkpoint_id=checkpoint_id,
                task_id=task_id,
                idx=resolved_idx,
                channel=channel,
                type_tag=str(type_tag),
                value_blob=value_blob,
            )
            candidates.append(
                (
                    thread_id,
                    checkpoint_ns,
                    checkpoint_id,
                    task_id,
                    resolved_idx,
                    channel,
                    str(type_tag),
                    value_blob,
                    digest,
                )
            )

        with self._lock:
            with self._connect(self.database_path) as connection:
                if candidates:
                    connection.executemany(query, candidates)
                rows = self._write_rows(
                    connection,
                    thread_id=thread_id,
                    checkpoint_ns=checkpoint_ns,
                    checkpoint_id=checkpoint_id,
                )
            aggregate = self._write_aggregate(rows)
            self._anchor_provider.set_write_head(
                self._scope(thread_id, checkpoint_ns),
                checkpoint_id=checkpoint_id,
                write_count=len(rows),
                aggregate_digest=aggregate,
            )

    def delete_thread(self, thread_id: str) -> None:
        resolved = str(thread_id)
        with self._lock:
            with self._connect(self.database_path) as connection:
                connection.execute(
                    "DELETE FROM checkpoints WHERE thread_id = ?",
                    (resolved,),
                )
                connection.execute(
                    "DELETE FROM writes WHERE thread_id = ?",
                    (resolved,),
                )
            self._anchor_provider.delete_thread(resolved)
