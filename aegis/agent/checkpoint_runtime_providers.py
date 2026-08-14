from __future__ import annotations

import hashlib
import hmac
import sqlite3
from enum import StrEnum
from pathlib import Path
from threading import RLock

from aegis.agent.checkpoint_runtime_contracts import (
    CheckpointAnchorHead,
    CheckpointWriteHead,
    RecoveryAuthorizationRequest,
    decode_checkpoint_scope,
)


class CheckpointRuntimeProviderReason(StrEnum):
    ANCHOR_CONFLICT = "checkpoint_runtime_anchor_conflict"
    ANCHOR_ROLLBACK_REJECTED = "checkpoint_runtime_anchor_rollback_rejected"
    BACKUP_AUTHENTICATION_FAILED = "checkpoint_runtime_backup_authentication_failed"
    RECOVERY_AUTHORIZATION_DENIED = "checkpoint_runtime_recovery_authorization_denied"


class CheckpointRuntimeProviderError(RuntimeError):
    def __init__(self, reason: CheckpointRuntimeProviderReason) -> None:
        self.reason = reason
        super().__init__(reason.value)


class LocalSyntheticCheckpointIntegrityProvider:
    synthetic_in_process = True
    operationally_external = False
    external_key_custody = False

    def __init__(self, *, key: bytes, provider_id: str) -> None:
        if len(key) < 32:
            raise ValueError("checkpoint integrity HMAC key must be at least 32 bytes")
        if not str(provider_id).strip():
            raise ValueError("checkpoint integrity provider id must be non-empty")
        self.provider_id = str(provider_id)
        self._key = bytes(key)

    def authenticate(self, payload: bytes) -> str:
        return hmac.new(self._key, bytes(payload), hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, authenticator: str) -> bool:
        expected = self.authenticate(payload)
        return hmac.compare_digest(expected, str(authenticator))


class LocalSqliteCheckpointAnchorProvider:
    synthetic_in_process = True
    operationally_external = False

    def __init__(
        self,
        *,
        database_path: Path,
        provider_id: str = "local-sqlite-agent-checkpoint-anchor",
    ) -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.provider_id = str(provider_id)
        self._lock = RLock()
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

    def current_head(self, scope: str) -> CheckpointAnchorHead | None:
        thread_id, checkpoint_ns = decode_checkpoint_scope(scope)
        with self._lock:
            with self._connect(self.database_path) as connection:
                row = connection.execute(
                    """
                    SELECT generation, checkpoint_id, checkpoint_digest
                    FROM checkpoint_heads
                    WHERE thread_id = ? AND checkpoint_ns = ?
                    """,
                    (thread_id, checkpoint_ns),
                ).fetchone()
        if row is None:
            return None
        return CheckpointAnchorHead(
            generation=int(row["generation"]),
            checkpoint_id=str(row["checkpoint_id"]),
            checkpoint_digest=str(row["checkpoint_digest"]),
        )

    def advance(
        self,
        scope: str,
        *,
        generation: int,
        checkpoint_id: str,
        checkpoint_digest: str,
        expected_generation: int | None,
    ) -> CheckpointAnchorHead:
        thread_id, checkpoint_ns = decode_checkpoint_scope(scope)
        if generation < 1:
            raise CheckpointRuntimeProviderError(
                CheckpointRuntimeProviderReason.ANCHOR_ROLLBACK_REJECTED
            )
        with self._lock:
            with self._connect(self.database_path) as connection:
                current = connection.execute(
                    """
                    SELECT generation, checkpoint_id, checkpoint_digest
                    FROM checkpoint_heads
                    WHERE thread_id = ? AND checkpoint_ns = ?
                    """,
                    (thread_id, checkpoint_ns),
                ).fetchone()
                current_generation = None if current is None else int(current["generation"])
                if current_generation != expected_generation:
                    raise CheckpointRuntimeProviderError(
                        CheckpointRuntimeProviderReason.ANCHOR_CONFLICT
                    )
                if current is None:
                    if generation != 1:
                        raise CheckpointRuntimeProviderError(
                            CheckpointRuntimeProviderReason.ANCHOR_CONFLICT
                        )
                    connection.execute(
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
                            str(checkpoint_id),
                            str(checkpoint_digest),
                        ),
                    )
                else:
                    if generation <= current_generation:
                        raise CheckpointRuntimeProviderError(
                            CheckpointRuntimeProviderReason.ANCHOR_ROLLBACK_REJECTED
                        )
                    if generation != current_generation + 1:
                        raise CheckpointRuntimeProviderError(
                            CheckpointRuntimeProviderReason.ANCHOR_CONFLICT
                        )
                    connection.execute(
                        """
                        UPDATE checkpoint_heads
                        SET generation = ?, checkpoint_id = ?, checkpoint_digest = ?
                        WHERE thread_id = ? AND checkpoint_ns = ?
                        """,
                        (
                            generation,
                            str(checkpoint_id),
                            str(checkpoint_digest),
                            thread_id,
                            checkpoint_ns,
                        ),
                    )
        return CheckpointAnchorHead(
            generation=generation,
            checkpoint_id=str(checkpoint_id),
            checkpoint_digest=str(checkpoint_digest),
        )

    def current_write_head(
        self,
        scope: str,
        checkpoint_id: str,
    ) -> CheckpointWriteHead | None:
        thread_id, checkpoint_ns = decode_checkpoint_scope(scope)
        with self._lock:
            with self._connect(self.database_path) as connection:
                row = connection.execute(
                    """
                    SELECT write_count, aggregate_digest
                    FROM write_heads
                    WHERE thread_id = ? AND checkpoint_ns = ? AND checkpoint_id = ?
                    """,
                    (thread_id, checkpoint_ns, str(checkpoint_id)),
                ).fetchone()
        if row is None:
            return None
        return CheckpointWriteHead(
            write_count=int(row["write_count"]),
            aggregate_digest=str(row["aggregate_digest"]),
        )

    def set_write_head(
        self,
        scope: str,
        *,
        checkpoint_id: str,
        write_count: int,
        aggregate_digest: str,
    ) -> CheckpointWriteHead:
        thread_id, checkpoint_ns = decode_checkpoint_scope(scope)
        with self._lock:
            with self._connect(self.database_path) as connection:
                connection.execute(
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
                        str(checkpoint_id),
                        int(write_count),
                        str(aggregate_digest),
                    ),
                )
        return CheckpointWriteHead(
            write_count=int(write_count),
            aggregate_digest=str(aggregate_digest),
        )

    def delete_thread(self, thread_id: str) -> None:
        with self._lock:
            with self._connect(self.database_path) as connection:
                connection.execute(
                    "DELETE FROM checkpoint_heads WHERE thread_id = ?",
                    (str(thread_id),),
                )
                connection.execute(
                    "DELETE FROM write_heads WHERE thread_id = ?",
                    (str(thread_id),),
                )

    def snapshot_to(self, destination: Path) -> None:
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            source = sqlite3.connect(self.database_path, timeout=5.0)
            target = sqlite3.connect(destination, timeout=5.0)
            try:
                source.backup(target)
            finally:
                target.close()
                source.close()

    def export_heads(self) -> tuple[dict[str, object], ...]:
        with self._lock:
            with self._connect(self.database_path) as connection:
                rows = connection.execute(
                    """
                    SELECT thread_id, checkpoint_ns, generation,
                           checkpoint_id, checkpoint_digest
                    FROM checkpoint_heads
                    ORDER BY thread_id, checkpoint_ns
                    """
                ).fetchall()
        return tuple(dict(row) for row in rows)


class LocalSyntheticCheckpointBackupAuthenticationProvider:
    synthetic_in_process = True
    operationally_external = False
    external_key_custody = False

    def __init__(self, *, key: bytes, provider_id: str) -> None:
        if len(key) < 32:
            raise ValueError("checkpoint backup authentication key must be at least 32 bytes")
        if not str(provider_id).strip():
            raise ValueError("checkpoint backup provider id must be non-empty")
        self.provider_id = str(provider_id)
        self._key = bytes(key)

    def authenticate(self, payload: bytes) -> str:
        return hmac.new(self._key, bytes(payload), hashlib.sha256).hexdigest()

    def verify_or_raise(self, payload: bytes, authenticator: str) -> None:
        expected = self.authenticate(payload)
        if not hmac.compare_digest(expected, str(authenticator)):
            raise CheckpointRuntimeProviderError(
                CheckpointRuntimeProviderReason.BACKUP_AUTHENTICATION_FAILED
            )


class LocalSyntheticCheckpointRecoveryAuthorityProvider:
    synthetic_in_process = True
    operationally_external = False

    def __init__(
        self,
        *,
        provider_id: str = "local-process-checkpoint-recovery-authority",
        allowed_operator_ids: frozenset[str] = frozenset(
            {"local-synthetic-recovery-operator"}
        ),
    ) -> None:
        self.provider_id = str(provider_id)
        self._allowed_operator_ids = frozenset(str(item) for item in allowed_operator_ids)

    def authorize_restore(self, request: RecoveryAuthorizationRequest) -> None:
        if (
            request.operator_id not in self._allowed_operator_ids
            or not request.backup_authenticated
            or not request.monotonic_anchor_verified
        ):
            raise CheckpointRuntimeProviderError(
                CheckpointRuntimeProviderReason.RECOVERY_AUTHORIZATION_DENIED
            )
