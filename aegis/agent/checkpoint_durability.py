from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import random
import sqlite3
from collections.abc import AsyncIterator, Iterator, Sequence
from enum import StrEnum
from pathlib import Path
from threading import RLock
from typing import Any, cast

from langchain_core.runnables import RunnableConfig
from langgraph.checkpoint.base import (
    WRITES_IDX_MAP,
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
    get_checkpoint_id,
    get_checkpoint_metadata,
)

from aegis.agent.checkpoint_security import build_strict_checkpoint_serializer


P4B_CHECKPOINT_INTEGRITY_POLICY_VERSION = "durable-checkpoint-integrity-anchor-v1"
P4B_CHECKPOINT_SCHEMA = "aegis.agent-checkpoint-integrity.v1"
P4B_WRITE_SCHEMA = "aegis.agent-checkpoint-write-integrity.v1"
P4B_LOCAL_SYNTHETIC_KEY_ID = "local-synthetic-agent-checkpoint-hmac-v1"
P4B_LOCAL_SYNTHETIC_HMAC_KEY = (
    b"aegisdesk-local-synthetic-agent-checkpoint-integrity-key-v1-2026"
)
_ZERO_DIGEST = "0" * 64


class CheckpointIntegrityReason(StrEnum):
    CHECKPOINT_CONFLICT = "checkpoint_integrity_conflict"
    CHECKPOINT_INTEGRITY_MISMATCH = "checkpoint_integrity_mismatch"
    CHECKPOINT_CHAIN_BROKEN = "checkpoint_integrity_chain_broken"
    CHECKPOINT_ROLLBACK_DETECTED = "checkpoint_rollback_detected"
    WRITE_INTEGRITY_MISMATCH = "checkpoint_write_integrity_mismatch"
    WRITE_SET_MISMATCH = "checkpoint_write_set_mismatch"


class CheckpointIntegrityError(RuntimeError):
    def __init__(self, reason: CheckpointIntegrityReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


def _canonical_json(value: dict[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class DurableIntegrityCheckpointer(BaseCheckpointSaver[str]):
    """Local durable LangGraph saver with strict types and tamper-evident state.

    Checkpoint rows live in one SQLite database. A second local SQLite database
    stores the latest monotonic checkpoint head and pending-write set digests. The
    separation makes single-database rollback or modification fail closed in the
    lab model. Both files and the HMAC key are still local synthetic trust
    material, so this class does not establish a production durability or key-
    custody claim.
    """

    policy_version = P4B_CHECKPOINT_INTEGRITY_POLICY_VERSION

    def __init__(
        self,
        *,
        database_path: Path,
        anchor_database_path: Path,
        hmac_key: bytes = P4B_LOCAL_SYNTHETIC_HMAC_KEY,
        key_id: str = P4B_LOCAL_SYNTHETIC_KEY_ID,
    ) -> None:
        if len(hmac_key) < 32:
            raise ValueError("checkpoint integrity HMAC key must be at least 32 bytes")
        self.database_path = Path(database_path)
        self.anchor_database_path = Path(anchor_database_path)
        if self.database_path.resolve() == self.anchor_database_path.resolve():
            raise ValueError("checkpoint database and integrity anchor must be separate files")
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.anchor_database_path.parent.mkdir(parents=True, exist_ok=True)
        self._hmac_key = bytes(hmac_key)
        self.key_id = key_id
        self._lock = RLock()
        super().__init__(serde=build_strict_checkpoint_serializer())
        self._setup()

    @staticmethod
    def _connect(path: Path) -> sqlite3.Connection:
        connection = sqlite3.connect(path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _setup(self) -> None:
        with self._lock:
            with self._connect(self.database_path) as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS checkpoints (
                        thread_id TEXT NOT NULL,
                        checkpoint_ns TEXT NOT NULL DEFAULT '',
                        checkpoint_id TEXT NOT NULL,
                        parent_checkpoint_id TEXT,
                        type TEXT NOT NULL,
                        checkpoint BLOB NOT NULL,
                        metadata BLOB NOT NULL,
                        generation INTEGER NOT NULL CHECK (generation >= 1),
                        previous_digest TEXT NOT NULL,
                        integrity_digest TEXT NOT NULL,
                        PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id),
                        UNIQUE (thread_id, checkpoint_ns, generation)
                    );
                    CREATE TABLE IF NOT EXISTS writes (
                        thread_id TEXT NOT NULL,
                        checkpoint_ns TEXT NOT NULL DEFAULT '',
                        checkpoint_id TEXT NOT NULL,
                        task_id TEXT NOT NULL,
                        idx INTEGER NOT NULL,
                        channel TEXT NOT NULL,
                        type TEXT NOT NULL,
                        value BLOB NOT NULL,
                        integrity_digest TEXT NOT NULL,
                        PRIMARY KEY (
                            thread_id, checkpoint_ns, checkpoint_id, task_id, idx
                        )
                    );
                    """
                )
            with self._connect(self.anchor_database_path) as connection:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS checkpoint_heads (
                        thread_id TEXT NOT NULL,
                        checkpoint_ns TEXT NOT NULL DEFAULT '',
                        generation INTEGER NOT NULL CHECK (generation >= 1),
                        checkpoint_id TEXT NOT NULL,
                        checkpoint_digest TEXT NOT NULL,
                        PRIMARY KEY (thread_id, checkpoint_ns)
                    );
                    CREATE TABLE IF NOT EXISTS write_heads (
                        thread_id TEXT NOT NULL,
                        checkpoint_ns TEXT NOT NULL DEFAULT '',
                        checkpoint_id TEXT NOT NULL,
                        write_count INTEGER NOT NULL CHECK (write_count >= 0),
                        aggregate_digest TEXT NOT NULL,
                        PRIMARY KEY (thread_id, checkpoint_ns, checkpoint_id)
                    );
                    """
                )

    def _hmac(self, payload: bytes) -> str:
        return hmac.new(self._hmac_key, payload, hashlib.sha256).hexdigest()

    def _checkpoint_digest(
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
    ) -> str:
        return self._hmac(
            _canonical_json(
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
        )

    def _write_digest(
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
    ) -> str:
        return self._hmac(
            _canonical_json(
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
        )

    def _write_aggregate(self, rows: Sequence[sqlite3.Row]) -> str:
        entries = [
            {
                "task_id": str(row["task_id"]),
                "idx": int(row["idx"]),
                "channel": str(row["channel"]),
                "integrity_digest": str(row["integrity_digest"]),
            }
            for row in rows
        ]
        return self._hmac(
            _canonical_json(
                {
                    "schema_version": P4B_WRITE_SCHEMA,
                    "entries": entries,
                    "key_id": self.key_id,
                }
            )
        )

    def _current_head(self, thread_id: str, checkpoint_ns: str) -> sqlite3.Row | None:
        with self._connect(self.anchor_database_path) as connection:
            return connection.execute(
                """
                SELECT generation, checkpoint_id, checkpoint_digest
                FROM checkpoint_heads
                WHERE thread_id = ? AND checkpoint_ns = ?
                """,
                (thread_id, checkpoint_ns),
            ).fetchone()

    def _checkpoint_row(
        self,
        connection: sqlite3.Connection,
        *,
        thread_id: str,
        checkpoint_ns: str,
        checkpoint_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT thread_id, checkpoint_ns, checkpoint_id, parent_checkpoint_id,
                   type, checkpoint, metadata, generation, previous_digest,
                   integrity_digest
            FROM checkpoints
            WHERE thread_id = ? AND checkpoint_ns = ? AND checkpoint_id = ?
            """,
            (thread_id, checkpoint_ns, checkpoint_id),
        ).fetchone()

    def _verify_checkpoint_row(self, row: sqlite3.Row) -> None:
        expected = self._checkpoint_digest(
            thread_id=str(row["thread_id"]),
            checkpoint_ns=str(row["checkpoint_ns"]),
            checkpoint_id=str(row["checkpoint_id"]),
            parent_checkpoint_id=(
                None
                if row["parent_checkpoint_id"] is None
                else str(row["parent_checkpoint_id"])
            ),
            type_tag=str(row["type"]),
            checkpoint_blob=bytes(row["checkpoint"]),
            metadata_blob=bytes(row["metadata"]),
            generation=int(row["generation"]),
            previous_digest=str(row["previous_digest"]),
        )
        if not hmac.compare_digest(expected, str(row["integrity_digest"])):
            raise CheckpointIntegrityError(
                CheckpointIntegrityReason.CHECKPOINT_INTEGRITY_MISMATCH
            )

    def _verify_checkpoint_chain(
        self,
        connection: sqlite3.Connection,
        *,
        thread_id: str,
        checkpoint_ns: str,
        row: sqlite3.Row,
    ) -> None:
        current = row
        generation = int(current["generation"])
        while True:
            self._verify_checkpoint_row(current)
            if generation == 1:
                if str(current["previous_digest"]) != _ZERO_DIGEST:
                    raise CheckpointIntegrityError(
                        CheckpointIntegrityReason.CHECKPOINT_CHAIN_BROKEN
                    )
                return
            previous = connection.execute(
                """
                SELECT thread_id, checkpoint_ns, checkpoint_id, parent_checkpoint_id,
                       type, checkpoint, metadata, generation, previous_digest,
                       integrity_digest
                FROM checkpoints
                WHERE thread_id = ? AND checkpoint_ns = ? AND generation = ?
                """,
                (thread_id, checkpoint_ns, generation - 1),
            ).fetchone()
            if previous is None or not hmac.compare_digest(
                str(current["previous_digest"]), str(previous["integrity_digest"])
            ):
                raise CheckpointIntegrityError(
                    CheckpointIntegrityReason.CHECKPOINT_CHAIN_BROKEN
                )
            current = previous
            generation -= 1

    def _write_rows(
        self,
        connection: sqlite3.Connection,
        *,
        thread_id: str,
        checkpoint_ns: str,
        checkpoint_id: str,
    ) -> list[sqlite3.Row]:
        return list(
            connection.execute(
                """
                SELECT task_id, idx, channel, type, value, integrity_digest
                FROM writes
                WHERE thread_id = ? AND checkpoint_ns = ? AND checkpoint_id = ?
                ORDER BY task_id, idx
                """,
                (thread_id, checkpoint_ns, checkpoint_id),
            ).fetchall()
        )

    def _verify_write_set(
        self,
        *,
        thread_id: str,
        checkpoint_ns: str,
        checkpoint_id: str,
        rows: Sequence[sqlite3.Row],
    ) -> None:
        for row in rows:
            expected = self._write_digest(
                thread_id=thread_id,
                checkpoint_ns=checkpoint_ns,
                checkpoint_id=checkpoint_id,
                task_id=str(row["task_id"]),
                idx=int(row["idx"]),
                channel=str(row["channel"]),
                type_tag=str(row["type"]),
                value_blob=bytes(row["value"]),
            )
            if not hmac.compare_digest(expected, str(row["integrity_digest"])):
                raise CheckpointIntegrityError(
                    CheckpointIntegrityReason.WRITE_INTEGRITY_MISMATCH
                )

        with self._connect(self.anchor_database_path) as anchor:
            head = anchor.execute(
                """
                SELECT write_count, aggregate_digest
                FROM write_heads
                WHERE thread_id = ? AND checkpoint_ns = ? AND checkpoint_id = ?
                """,
                (thread_id, checkpoint_ns, checkpoint_id),
            ).fetchone()
        if not rows and head is None:
            return
        if head is None:
            raise CheckpointIntegrityError(CheckpointIntegrityReason.WRITE_SET_MISMATCH)
        if int(head["write_count"]) != len(rows) or not hmac.compare_digest(
            str(head["aggregate_digest"]), self._write_aggregate(rows)
        ):
            raise CheckpointIntegrityError(CheckpointIntegrityReason.WRITE_SET_MISMATCH)

    def _tuple_from_row(
        self,
        *,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        require_current_head: bool,
    ) -> CheckpointTuple:
        thread_id = str(row["thread_id"])
        checkpoint_ns = str(row["checkpoint_ns"])
        checkpoint_id = str(row["checkpoint_id"])
        self._verify_checkpoint_chain(
            connection,
            thread_id=thread_id,
            checkpoint_ns=checkpoint_ns,
            row=row,
        )
        if require_current_head:
            head = self._current_head(thread_id, checkpoint_ns)
            if head is None or (
                int(head["generation"]) != int(row["generation"])
                or str(head["checkpoint_id"]) != checkpoint_id
                or not hmac.compare_digest(
                    str(head["checkpoint_digest"]), str(row["integrity_digest"])
                )
            ):
                raise CheckpointIntegrityError(
                    CheckpointIntegrityReason.CHECKPOINT_ROLLBACK_DETECTED
                )

        write_rows = self._write_rows(
            connection,
            thread_id=thread_id,
            checkpoint_ns=checkpoint_ns,
            checkpoint_id=checkpoint_id,
        )
        self._verify_write_set(
            thread_id=thread_id,
            checkpoint_ns=checkpoint_ns,
            checkpoint_id=checkpoint_id,
            rows=write_rows,
        )
        config: RunnableConfig = {
            "configurable": {
                "thread_id": thread_id,
                "checkpoint_ns": checkpoint_ns,
                "checkpoint_id": checkpoint_id,
            }
        }
        parent_checkpoint_id = row["parent_checkpoint_id"]
        parent_config: RunnableConfig | None = None
        if parent_checkpoint_id is not None:
            parent_config = {
                "configurable": {
                    "thread_id": thread_id,
                    "checkpoint_ns": checkpoint_ns,
                    "checkpoint_id": str(parent_checkpoint_id),
                }
            }
        return CheckpointTuple(
            config,
            self.serde.loads_typed((str(row["type"]), bytes(row["checkpoint"]))),
            cast(CheckpointMetadata, json.loads(bytes(row["metadata"]))),
            parent_config,
            [
                (
                    str(write["task_id"]),
                    str(write["channel"]),
                    self.serde.loads_typed(
                        (str(write["type"]), bytes(write["value"]))
                    ),
                )
                for write in write_rows
            ],
        )

    def get_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        thread_id = str(config["configurable"]["thread_id"])
        checkpoint_ns = str(config["configurable"].get("checkpoint_ns", ""))
        requested_id = get_checkpoint_id(config)
        require_current_head = requested_id is None

        with self._lock:
            if requested_id is None:
                head = self._current_head(thread_id, checkpoint_ns)
                if head is None:
                    return None
                checkpoint_id = str(head["checkpoint_id"])
            else:
                checkpoint_id = str(requested_id)

            with self._connect(self.database_path) as connection:
                row = self._checkpoint_row(
                    connection,
                    thread_id=thread_id,
                    checkpoint_ns=checkpoint_ns,
                    checkpoint_id=checkpoint_id,
                )
                if row is None:
                    if require_current_head:
                        raise CheckpointIntegrityError(
                            CheckpointIntegrityReason.CHECKPOINT_ROLLBACK_DETECTED
                        )
                    return None
                return self._tuple_from_row(
                    connection=connection,
                    row=row,
                    require_current_head=require_current_head,
                )

    def list(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> Iterator[CheckpointTuple]:
        params: list[object] = []
        clauses: list[str] = []
        if config is not None:
            clauses.append("thread_id = ?")
            params.append(str(config["configurable"]["thread_id"]))
            clauses.append("checkpoint_ns = ?")
            params.append(str(config["configurable"].get("checkpoint_ns", "")))
        if before is not None and (before_id := get_checkpoint_id(before)) is not None:
            clauses.append("checkpoint_id < ?")
            params.append(str(before_id))
        where = "" if not clauses else "WHERE " + " AND ".join(clauses)
        query = (
            "SELECT thread_id, checkpoint_ns, checkpoint_id FROM checkpoints "
            + where
            + " ORDER BY checkpoint_id DESC"
        )

        with self._lock:
            with self._connect(self.database_path) as connection:
                identifiers = list(connection.execute(query, params).fetchall())

            emitted = 0
            for identifier in identifiers:
                explicit: RunnableConfig = {
                    "configurable": {
                        "thread_id": str(identifier["thread_id"]),
                        "checkpoint_ns": str(identifier["checkpoint_ns"]),
                        "checkpoint_id": str(identifier["checkpoint_id"]),
                    }
                }
                item = self.get_tuple(explicit)
                if item is None:
                    continue
                if filter is not None and any(
                    item.metadata.get(key) != value for key, value in filter.items()
                ):
                    continue
                yield item
                emitted += 1
                if limit is not None and emitted >= limit:
                    return

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        del new_versions
        thread_id = str(config["configurable"]["thread_id"])
        checkpoint_ns = str(config["configurable"].get("checkpoint_ns", ""))
        checkpoint_id = str(checkpoint["id"])
        parent_checkpoint_id = config["configurable"].get("checkpoint_id")
        if parent_checkpoint_id is not None:
            parent_checkpoint_id = str(parent_checkpoint_id)
        type_tag, checkpoint_blob = self.serde.dumps_typed(checkpoint)
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
                    if (
                        str(existing["type"]) == str(type_tag)
                        and bytes(existing["checkpoint"]) == checkpoint_blob
                        and bytes(existing["metadata"]) == metadata_blob
                        and (
                            None
                            if existing["parent_checkpoint_id"] is None
                            else str(existing["parent_checkpoint_id"])
                        )
                        == parent_checkpoint_id
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

            head = self._current_head(thread_id, checkpoint_ns)
            generation = 1 if head is None else int(head["generation"]) + 1
            previous_digest = (
                _ZERO_DIGEST if head is None else str(head["checkpoint_digest"])
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
                with self._connect(self.anchor_database_path) as anchor:
                    current = anchor.execute(
                        """
                        SELECT generation, checkpoint_id, checkpoint_digest
                        FROM checkpoint_heads
                        WHERE thread_id = ? AND checkpoint_ns = ?
                        """,
                        (thread_id, checkpoint_ns),
                    ).fetchone()
                    if head is None:
                        if current is not None:
                            raise CheckpointIntegrityError(
                                CheckpointIntegrityReason.CHECKPOINT_CONFLICT
                            )
                        anchor.execute(
                            """
                            INSERT INTO checkpoint_heads (
                                thread_id, checkpoint_ns, generation,
                                checkpoint_id, checkpoint_digest
                            ) VALUES (?, ?, ?, ?, ?)
                            """,
                            (
                                thread_id,
                                checkpoint_ns,
                                generation,
                                checkpoint_id,
                                digest,
                            ),
                        )
                    else:
                        if current is None or (
                            int(current["generation"]) != int(head["generation"])
                            or str(current["checkpoint_id"])
                            != str(head["checkpoint_id"])
                            or not hmac.compare_digest(
                                str(current["checkpoint_digest"]),
                                str(head["checkpoint_digest"]),
                            )
                        ):
                            raise CheckpointIntegrityError(
                                CheckpointIntegrityReason.CHECKPOINT_CONFLICT
                            )
                        anchor.execute(
                            """
                            UPDATE checkpoint_heads
                            SET generation = ?, checkpoint_id = ?, checkpoint_digest = ?
                            WHERE thread_id = ? AND checkpoint_ns = ?
                            """,
                            (
                                generation,
                                checkpoint_id,
                                digest,
                                thread_id,
                                checkpoint_ns,
                            ),
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
            with self._connect(self.anchor_database_path) as anchor:
                anchor.execute(
                    """
                    INSERT INTO write_heads (
                        thread_id, checkpoint_ns, checkpoint_id,
                        write_count, aggregate_digest
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(thread_id, checkpoint_ns, checkpoint_id)
                    DO UPDATE SET
                        write_count = excluded.write_count,
                        aggregate_digest = excluded.aggregate_digest
                    """,
                    (
                        thread_id,
                        checkpoint_ns,
                        checkpoint_id,
                        len(rows),
                        aggregate,
                    ),
                )

    def delete_thread(self, thread_id: str) -> None:
        thread_id = str(thread_id)
        with self._lock:
            with self._connect(self.database_path) as connection:
                connection.execute("DELETE FROM checkpoints WHERE thread_id = ?", (thread_id,))
                connection.execute("DELETE FROM writes WHERE thread_id = ?", (thread_id,))
            with self._connect(self.anchor_database_path) as anchor:
                anchor.execute("DELETE FROM checkpoint_heads WHERE thread_id = ?", (thread_id,))
                anchor.execute("DELETE FROM write_heads WHERE thread_id = ?", (thread_id,))

    async def aget_tuple(self, config: RunnableConfig) -> CheckpointTuple | None:
        return await asyncio.to_thread(self.get_tuple, config)

    async def alist(
        self,
        config: RunnableConfig | None,
        *,
        filter: dict[str, Any] | None = None,
        before: RunnableConfig | None = None,
        limit: int | None = None,
    ) -> AsyncIterator[CheckpointTuple]:
        items = await asyncio.to_thread(
            lambda: list(
                self.list(config, filter=filter, before=before, limit=limit)
            )
        )
        for item in items:
            yield item

    async def aput(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        return await asyncio.to_thread(
            self.put, config, checkpoint, metadata, new_versions
        )

    async def aput_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        await asyncio.to_thread(
            self.put_writes, config, writes, task_id, task_path
        )

    async def adelete_thread(self, thread_id: str) -> None:
        await asyncio.to_thread(self.delete_thread, thread_id)

    def get_next_version(self, current: str | None, channel: None) -> str:
        del channel
        if current is None:
            current_v = 0
        elif isinstance(current, int):
            current_v = current
        else:
            current_v = int(str(current).split(".")[0])
        next_v = current_v + 1
        return f"{next_v:032}.{random.random():016}"
