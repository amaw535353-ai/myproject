from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_lifecycle_capabilities import require_lifecycle_capability
from aegis.agent.checkpoint_lifecycle_fencing import (
    CheckpointLifecycleCommand,
    CheckpointLifecycleCommandOperation,
    CheckpointLifecycleCommandReceipt,
)


P4M_DURABLE_LIFECYCLE_JOURNAL_POLICY_VERSION = (
    "durable-synthetic-checkpoint-lifecycle-journal-v1"
)
P4M_DURABLE_LIFECYCLE_JOURNAL_SCHEMA_VERSION = "p4m-lifecycle-journal-schema-v1"


class CheckpointLifecycleJournalState(StrEnum):
    PREPARED = "prepared"
    PROVIDER_STARTED = "provider_started"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    COMMITTED = "committed"


class CheckpointLifecycleJournalFaultMode(StrEnum):
    NONE = "none"
    AFTER_PREPARED_BEFORE_PROVIDER = "after_prepared_before_provider"
    AFTER_PROVIDER_BEFORE_COMMIT = "after_provider_before_commit"
    AFTER_COMMIT_BEFORE_RESPONSE = "after_commit_before_response"


class CheckpointLifecycleJournalReason(StrEnum):
    JOURNAL_INTEGRITY_FAILED = "checkpoint_lifecycle_journal_integrity_failed"
    JOURNAL_COMMAND_CONFLICT = "checkpoint_lifecycle_journal_command_conflict"
    JOURNAL_COMMAND_MISSING = "checkpoint_lifecycle_journal_command_missing"
    JOURNAL_FENCE_STALE = "checkpoint_lifecycle_journal_fence_stale"
    JOURNAL_STATE_INVALID = "checkpoint_lifecycle_journal_state_invalid"
    RECONCILIATION_REQUIRED = "checkpoint_lifecycle_reconciliation_required"
    RECONCILIATION_UNPROVABLE = "checkpoint_lifecycle_reconciliation_unprovable"
    PROVIDER_ID_MISMATCH = "checkpoint_lifecycle_journal_provider_id_mismatch"
    ANCHOR_FENCE_MISMATCH = "checkpoint_lifecycle_anchor_fence_mismatch"
    OPERATION_ARGUMENTS_INVALID = "checkpoint_lifecycle_operation_arguments_invalid"
    SYNTHETIC_CRASH = "checkpoint_lifecycle_synthetic_crash"


class CheckpointLifecycleJournalError(RuntimeError):
    def __init__(
        self,
        reason: CheckpointLifecycleJournalReason,
        *,
        command_id: str | None = None,
        fault_mode: CheckpointLifecycleJournalFaultMode | None = None,
    ) -> None:
        self.reason = reason
        self.command_id = command_id
        self.fault_mode = fault_mode
        detail = reason.value
        if command_id is not None:
            detail = f"{detail}:{command_id}"
        if fault_mode is not None:
            detail = f"{detail}:{fault_mode.value}"
        super().__init__(detail)


@dataclass(frozen=True)
class DurableCheckpointLifecycleJournalRecord:
    command: CheckpointLifecycleCommand
    state: CheckpointLifecycleJournalState
    pre_observation: dict[str, object]
    anchor_fingerprint_after: str | None
    provider_id: str


class DurableSyntheticCheckpointLifecycleCoordinator:
    """Restart-verifiable local lifecycle journal and fencing harness.

    The journal persists command identity, issued/committed fence generations,
    pre-operation observation, state transitions, and committed receipts in a
    local SQLite file authenticated by a separate local HMAC key file. It is a
    same-filesystem synthetic durability harness, not a distributed lock,
    rollback-resistant ledger, remote idempotency service, or exactly-once
    execution mechanism.
    """

    synthetic_in_process = True
    durable_local_journal = True
    distributed_fencing = False
    rollback_resistant_journal = False
    exactly_once_execution = False
    operationally_external = False
    production_runtime_eligible = False
    network_operations = 0

    def __init__(
        self,
        *,
        lifecycle_provider: Any,
        journal_path: Path,
        integrity_key_path: Path | None = None,
    ) -> None:
        self._provider = lifecycle_provider
        self._anchor_provider = getattr(lifecycle_provider, "bound_anchor_provider", None)
        self.journal_path = Path(journal_path)
        self.integrity_key_path = (
            Path(integrity_key_path)
            if integrity_key_path is not None
            else self.journal_path.with_suffix(self.journal_path.suffix + ".hmac-key")
        )
        self._fault_mode = CheckpointLifecycleJournalFaultMode.NONE
        self.provider_invocations = 0
        self.replay_hits = 0
        self.reconciliations = 0
        self._integrity_key = self._open_or_create_store()
        self._verify_store()
        self._recover_started_commands()

    @property
    def provider_id(self) -> str:
        return str(getattr(self._provider, "provider_id", ""))

    def arm_fault(self, mode: CheckpointLifecycleJournalFaultMode) -> None:
        self._fault_mode = CheckpointLifecycleJournalFaultMode(mode)

    def _consume_fault(self) -> CheckpointLifecycleJournalFaultMode:
        mode = self._fault_mode
        self._fault_mode = CheckpointLifecycleJournalFaultMode.NONE
        return mode

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.journal_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _open_or_create_store(self) -> bytes:
        journal_exists = self.journal_path.exists()
        key_exists = self.integrity_key_path.exists()
        if journal_exists != key_exists:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID
            )
        if journal_exists:
            try:
                key = self.integrity_key_path.read_bytes()
            except OSError as exc:
                raise CheckpointLifecycleJournalError(
                    CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID
                ) from exc
            if len(key) != 32:
                raise CheckpointLifecycleJournalError(
                    CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID
                )
            return key

        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        self.integrity_key_path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        descriptor = os.open(
            self.integrity_key_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            os.write(descriptor, key)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

        connection = sqlite3.connect(self.journal_path, timeout=5.0)
        try:
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE journal_meta (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version TEXT NOT NULL,
                    highest_issued_fence INTEGER NOT NULL CHECK (highest_issued_fence >= 0),
                    highest_committed_fence INTEGER NOT NULL CHECK (highest_committed_fence >= 0),
                    integrity_tag TEXT NOT NULL
                );
                CREATE TABLE lifecycle_commands (
                    command_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    fence_token INTEGER NOT NULL UNIQUE CHECK (fence_token >= 1),
                    expected_anchor_fingerprint TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    command_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    pre_observation_json TEXT NOT NULL,
                    anchor_fingerprint_after TEXT,
                    provider_id TEXT NOT NULL,
                    integrity_tag TEXT NOT NULL
                );
                """
            )
            tag = self._meta_tag_for_key(
                key,
                highest_issued_fence=0,
                highest_committed_fence=0,
            )
            connection.execute(
                """
                INSERT INTO journal_meta (
                    singleton, schema_version, highest_issued_fence,
                    highest_committed_fence, integrity_tag
                ) VALUES (1, ?, 0, 0, ?)
                """,
                (P4M_DURABLE_LIFECYCLE_JOURNAL_SCHEMA_VERSION, tag),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            try:
                self.journal_path.unlink()
            except OSError:
                pass
            try:
                self.integrity_key_path.unlink()
            except OSError:
                pass
            raise
        finally:
            connection.close()
        return key

    @staticmethod
    def _canonical_json(payload: dict[str, object]) -> bytes:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def _meta_tag_for_key(
        cls,
        key: bytes,
        *,
        highest_issued_fence: int,
        highest_committed_fence: int,
    ) -> str:
        payload = cls._canonical_json(
            {
                "policy_version": P4M_DURABLE_LIFECYCLE_JOURNAL_POLICY_VERSION,
                "schema_version": P4M_DURABLE_LIFECYCLE_JOURNAL_SCHEMA_VERSION,
                "highest_issued_fence": int(highest_issued_fence),
                "highest_committed_fence": int(highest_committed_fence),
            }
        )
        return hmac.new(key, payload, hashlib.sha256).hexdigest()

    def _meta_tag(self, *, highest_issued_fence: int, highest_committed_fence: int) -> str:
        return self._meta_tag_for_key(
            self._integrity_key,
            highest_issued_fence=highest_issued_fence,
            highest_committed_fence=highest_committed_fence,
        )

    def _command_tag(
        self,
        *,
        command: CheckpointLifecycleCommand,
        state: CheckpointLifecycleJournalState,
        pre_observation_json: str,
        anchor_fingerprint_after: str | None,
        provider_id: str,
    ) -> str:
        payload = self._canonical_json(
            {
                "policy_version": P4M_DURABLE_LIFECYCLE_JOURNAL_POLICY_VERSION,
                "command_id": command.command_id,
                "operation": command.operation.value,
                "fence_token": command.fence_token,
                "expected_anchor_fingerprint": command.expected_anchor_fingerprint,
                "resource_id": command.resource_id,
                "command_digest": command.digest(),
                "state": state.value,
                "pre_observation_json": pre_observation_json,
                "anchor_fingerprint_after": anchor_fingerprint_after,
                "provider_id": provider_id,
            }
        )
        return hmac.new(self._integrity_key, payload, hashlib.sha256).hexdigest()

    def _read_meta(self, connection: sqlite3.Connection) -> sqlite3.Row:
        try:
            row = connection.execute(
                """
                SELECT schema_version, highest_issued_fence,
                       highest_committed_fence, integrity_tag
                FROM journal_meta
                WHERE singleton = 1
                """
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID
            ) from exc
        if row is None or str(row["schema_version"]) != P4M_DURABLE_LIFECYCLE_JOURNAL_SCHEMA_VERSION:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID
            )
        issued = int(row["highest_issued_fence"])
        committed = int(row["highest_committed_fence"])
        expected = self._meta_tag(
            highest_issued_fence=issued,
            highest_committed_fence=committed,
        )
        if not hmac.compare_digest(str(row["integrity_tag"]), expected):
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_INTEGRITY_FAILED
            )
        if committed > issued:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID
            )
        return row

    def _row_to_record(self, row: sqlite3.Row) -> DurableCheckpointLifecycleJournalRecord:
        try:
            command = CheckpointLifecycleCommand(
                command_id=str(row["command_id"]),
                operation=CheckpointLifecycleCommandOperation(str(row["operation"])),
                fence_token=int(row["fence_token"]),
                expected_anchor_fingerprint=str(row["expected_anchor_fingerprint"]),
                resource_id=str(row["resource_id"]),
            )
            state = CheckpointLifecycleJournalState(str(row["state"]))
            pre_observation_json = str(row["pre_observation_json"])
            parsed = json.loads(pre_observation_json)
            if not isinstance(parsed, dict):
                raise ValueError("pre observation is not an object")
            pre_observation = dict(parsed)
            anchor_after = (
                None
                if row["anchor_fingerprint_after"] is None
                else str(row["anchor_fingerprint_after"])
            )
            provider_id = str(row["provider_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID
            ) from exc

        if str(row["command_digest"]) != command.digest():
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_INTEGRITY_FAILED,
                command_id=command.command_id,
            )
        expected_tag = self._command_tag(
            command=command,
            state=state,
            pre_observation_json=pre_observation_json,
            anchor_fingerprint_after=anchor_after,
            provider_id=provider_id,
        )
        if not hmac.compare_digest(str(row["integrity_tag"]), expected_tag):
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_INTEGRITY_FAILED,
                command_id=command.command_id,
            )
        if state is CheckpointLifecycleJournalState.COMMITTED and not anchor_after:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID,
                command_id=command.command_id,
            )
        return DurableCheckpointLifecycleJournalRecord(
            command=command,
            state=state,
            pre_observation=pre_observation,
            anchor_fingerprint_after=anchor_after,
            provider_id=provider_id,
        )

    def _load_row(self, connection: sqlite3.Connection, command_id: str) -> sqlite3.Row | None:
        try:
            return connection.execute(
                """
                SELECT command_id, operation, fence_token,
                       expected_anchor_fingerprint, resource_id, command_digest,
                       state, pre_observation_json, anchor_fingerprint_after,
                       provider_id, integrity_tag
                FROM lifecycle_commands
                WHERE command_id = ?
                """,
                (command_id,),
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID
            ) from exc

    def _verify_store(self) -> None:
        connection = self._connect()
        try:
            meta = self._read_meta(connection)
            rows = connection.execute(
                """
                SELECT command_id, operation, fence_token,
                       expected_anchor_fingerprint, resource_id, command_digest,
                       state, pre_observation_json, anchor_fingerprint_after,
                       provider_id, integrity_tag
                FROM lifecycle_commands
                ORDER BY fence_token
                """
            ).fetchall()
            records = [self._row_to_record(row) for row in rows]
            if records:
                highest_issued = max(record.command.fence_token for record in records)
                if highest_issued != int(meta["highest_issued_fence"]):
                    raise CheckpointLifecycleJournalError(
                        CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID
                    )
                committed = [
                    record.command.fence_token
                    for record in records
                    if record.state is CheckpointLifecycleJournalState.COMMITTED
                ]
                if max(committed, default=0) != int(meta["highest_committed_fence"]):
                    raise CheckpointLifecycleJournalError(
                        CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID
                    )
            elif int(meta["highest_issued_fence"]) != 0 or int(meta["highest_committed_fence"]) != 0:
                raise CheckpointLifecycleJournalError(
                    CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID
                )
        except sqlite3.DatabaseError as exc:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID
            ) from exc
        finally:
            connection.close()

    def _recover_started_commands(self) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._read_meta(connection)
            rows = connection.execute(
                """
                SELECT command_id, operation, fence_token,
                       expected_anchor_fingerprint, resource_id, command_digest,
                       state, pre_observation_json, anchor_fingerprint_after,
                       provider_id, integrity_tag
                FROM lifecycle_commands
                WHERE state = ?
                ORDER BY fence_token
                """,
                (CheckpointLifecycleJournalState.PROVIDER_STARTED.value,),
            ).fetchall()
            for row in rows:
                record = self._row_to_record(row)
                pre_json = json.dumps(
                    record.pre_observation,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                next_state = CheckpointLifecycleJournalState.RECONCILIATION_REQUIRED
                tag = self._command_tag(
                    command=record.command,
                    state=next_state,
                    pre_observation_json=pre_json,
                    anchor_fingerprint_after=None,
                    provider_id=record.provider_id,
                )
                connection.execute(
                    """
                    UPDATE lifecycle_commands
                    SET state = ?, integrity_tag = ?
                    WHERE command_id = ?
                    """,
                    (next_state.value, tag, record.command.command_id),
                )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _export_anchor_state(
        self,
    ) -> tuple[tuple[dict[str, object], ...], tuple[dict[str, object], ...]]:
        export_heads = getattr(self._anchor_provider, "export_heads", None)
        export_write_heads = getattr(self._anchor_provider, "export_write_heads", None)
        if not callable(export_heads) or not callable(export_write_heads):
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID
            )
        return (
            tuple(dict(item) for item in export_heads()),
            tuple(dict(item) for item in export_write_heads()),
        )

    @staticmethod
    def _fingerprint_state(
        checkpoint_heads: tuple[dict[str, object], ...],
        write_heads: tuple[dict[str, object], ...],
    ) -> str:
        payload = json.dumps(
            {
                "checkpoint_heads": checkpoint_heads,
                "write_heads": write_heads,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def anchor_fingerprint(self) -> str:
        return self._fingerprint_state(*self._export_anchor_state())

    def _migration_observation(
        self, saver: KeyLifecycleConfidentialCheckpointer
    ) -> dict[str, object]:
        active_key_id = saver.key_provider.active_key_id
        with saver._lock:
            with saver._connect(saver.database_path) as connection:
                checkpoint_rows = connection.execute(
                    "SELECT checkpoint FROM checkpoints ORDER BY thread_id, checkpoint_ns, generation"
                ).fetchall()
                write_rows = connection.execute(
                    """
                    SELECT value FROM writes
                    ORDER BY thread_id, checkpoint_ns, checkpoint_id, task_id, idx
                    """
                ).fetchall()
        checkpoint_ids = [
            saver.key_provider.envelope_key_id(bytes(row["checkpoint"]))
            for row in checkpoint_rows
        ]
        write_ids = [
            saver.key_provider.envelope_key_id(bytes(row["value"]))
            for row in write_rows
        ]
        return {
            "anchor_fingerprint": self.anchor_fingerprint(),
            "active_key_id": active_key_id,
            "checkpoint_total": len(checkpoint_ids),
            "checkpoint_active": sum(1 for key_id in checkpoint_ids if key_id == active_key_id),
            "write_total": len(write_ids),
            "write_active": sum(1 for key_id in write_ids if key_id == active_key_id),
        }

    def _operation_observation(
        self,
        operation: CheckpointLifecycleCommandOperation,
        saver: KeyLifecycleConfidentialCheckpointer,
    ) -> dict[str, object]:
        if operation is CheckpointLifecycleCommandOperation.MIGRATION:
            return self._migration_observation(saver)
        return {"anchor_fingerprint": self.anchor_fingerprint()}

    def issue_command(
        self,
        *,
        command_id: str,
        operation: CheckpointLifecycleCommandOperation,
        resource_id: str,
        saver: KeyLifecycleConfidentialCheckpointer,
    ) -> CheckpointLifecycleCommand:
        operation = CheckpointLifecycleCommandOperation(operation)
        if not command_id.strip() or not resource_id.strip():
            raise ValueError("checkpoint lifecycle command and resource ids must be non-empty")
        current_anchor = self.anchor_fingerprint()
        pre_observation = self._operation_observation(operation, saver)
        if pre_observation.get("anchor_fingerprint") != current_anchor:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.ANCHOR_FENCE_MISMATCH,
                command_id=command_id,
            )
        pre_json = json.dumps(pre_observation, sort_keys=True, separators=(",", ":"))

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            meta = self._read_meta(connection)
            existing_row = self._load_row(connection, command_id)
            if existing_row is not None:
                existing = self._row_to_record(existing_row)
                if (
                    existing.command.operation is not operation
                    or existing.command.resource_id != resource_id
                    or existing.provider_id != self.provider_id
                ):
                    raise CheckpointLifecycleJournalError(
                        CheckpointLifecycleJournalReason.JOURNAL_COMMAND_CONFLICT,
                        command_id=command_id,
                    )
                connection.commit()
                return existing.command

            fence = int(meta["highest_issued_fence"]) + 1
            command = CheckpointLifecycleCommand(
                command_id=command_id,
                operation=operation,
                fence_token=fence,
                expected_anchor_fingerprint=current_anchor,
                resource_id=resource_id,
            )
            tag = self._command_tag(
                command=command,
                state=CheckpointLifecycleJournalState.PREPARED,
                pre_observation_json=pre_json,
                anchor_fingerprint_after=None,
                provider_id=self.provider_id,
            )
            connection.execute(
                """
                INSERT INTO lifecycle_commands (
                    command_id, operation, fence_token, expected_anchor_fingerprint,
                    resource_id, command_digest, state, pre_observation_json,
                    anchor_fingerprint_after, provider_id, integrity_tag
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    command.command_id,
                    command.operation.value,
                    command.fence_token,
                    command.expected_anchor_fingerprint,
                    command.resource_id,
                    command.digest(),
                    CheckpointLifecycleJournalState.PREPARED.value,
                    pre_json,
                    self.provider_id,
                    tag,
                ),
            )
            committed = int(meta["highest_committed_fence"])
            meta_tag = self._meta_tag(
                highest_issued_fence=fence,
                highest_committed_fence=committed,
            )
            connection.execute(
                """
                UPDATE journal_meta
                SET highest_issued_fence = ?, integrity_tag = ?
                WHERE singleton = 1
                """,
                (fence, meta_tag),
            )
            connection.commit()
            return command
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _load_record_for_command(
        self,
        command: CheckpointLifecycleCommand,
    ) -> tuple[DurableCheckpointLifecycleJournalRecord, int]:
        connection = self._connect()
        try:
            meta = self._read_meta(connection)
            row = self._load_row(connection, command.command_id)
            if row is None:
                raise CheckpointLifecycleJournalError(
                    CheckpointLifecycleJournalReason.JOURNAL_COMMAND_MISSING,
                    command_id=command.command_id,
                )
            record = self._row_to_record(row)
            if record.command.digest() != command.digest():
                raise CheckpointLifecycleJournalError(
                    CheckpointLifecycleJournalReason.JOURNAL_COMMAND_CONFLICT,
                    command_id=command.command_id,
                )
            if record.provider_id != self.provider_id:
                raise CheckpointLifecycleJournalError(
                    CheckpointLifecycleJournalReason.PROVIDER_ID_MISMATCH,
                    command_id=command.command_id,
                )
            return record, int(meta["highest_committed_fence"])
        finally:
            connection.close()

    def _set_state(
        self,
        record: DurableCheckpointLifecycleJournalRecord,
        state: CheckpointLifecycleJournalState,
    ) -> DurableCheckpointLifecycleJournalRecord:
        pre_json = json.dumps(
            record.pre_observation,
            sort_keys=True,
            separators=(",", ":"),
        )
        tag = self._command_tag(
            command=record.command,
            state=state,
            pre_observation_json=pre_json,
            anchor_fingerprint_after=record.anchor_fingerprint_after,
            provider_id=record.provider_id,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._read_meta(connection)
            current_row = self._load_row(connection, record.command.command_id)
            if current_row is None:
                raise CheckpointLifecycleJournalError(
                    CheckpointLifecycleJournalReason.JOURNAL_COMMAND_MISSING,
                    command_id=record.command.command_id,
                )
            current = self._row_to_record(current_row)
            if current.command.digest() != record.command.digest():
                raise CheckpointLifecycleJournalError(
                    CheckpointLifecycleJournalReason.JOURNAL_COMMAND_CONFLICT,
                    command_id=record.command.command_id,
                )
            connection.execute(
                "UPDATE lifecycle_commands SET state = ?, integrity_tag = ? WHERE command_id = ?",
                (state.value, tag, record.command.command_id),
            )
            connection.commit()
            return replace(record, state=state)
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _commit_receipt(
        self,
        record: DurableCheckpointLifecycleJournalRecord,
        *,
        anchor_fingerprint_after: str,
    ) -> CheckpointLifecycleCommandReceipt:
        pre_json = json.dumps(
            record.pre_observation,
            sort_keys=True,
            separators=(",", ":"),
        )
        next_state = CheckpointLifecycleJournalState.COMMITTED
        tag = self._command_tag(
            command=record.command,
            state=next_state,
            pre_observation_json=pre_json,
            anchor_fingerprint_after=anchor_fingerprint_after,
            provider_id=record.provider_id,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            meta = self._read_meta(connection)
            current_row = self._load_row(connection, record.command.command_id)
            if current_row is None:
                raise CheckpointLifecycleJournalError(
                    CheckpointLifecycleJournalReason.JOURNAL_COMMAND_MISSING,
                    command_id=record.command.command_id,
                )
            current = self._row_to_record(current_row)
            if current.command.digest() != record.command.digest():
                raise CheckpointLifecycleJournalError(
                    CheckpointLifecycleJournalReason.JOURNAL_COMMAND_CONFLICT,
                    command_id=record.command.command_id,
                )
            connection.execute(
                """
                UPDATE lifecycle_commands
                SET state = ?, anchor_fingerprint_after = ?, integrity_tag = ?
                WHERE command_id = ?
                """,
                (
                    next_state.value,
                    anchor_fingerprint_after,
                    tag,
                    record.command.command_id,
                ),
            )
            issued = int(meta["highest_issued_fence"])
            committed = max(
                int(meta["highest_committed_fence"]),
                record.command.fence_token,
            )
            meta_tag = self._meta_tag(
                highest_issued_fence=issued,
                highest_committed_fence=committed,
            )
            connection.execute(
                """
                UPDATE journal_meta
                SET highest_committed_fence = ?, integrity_tag = ?
                WHERE singleton = 1
                """,
                (committed, meta_tag),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return CheckpointLifecycleCommandReceipt(
            command_id=record.command.command_id,
            operation=record.command.operation,
            fence_token=record.command.fence_token,
            command_digest=record.command.digest(),
            anchor_fingerprint_after=anchor_fingerprint_after,
            provider_id=record.provider_id,
        )

    def _receipt_from_record(
        self,
        record: DurableCheckpointLifecycleJournalRecord,
        *,
        replayed: bool,
    ) -> CheckpointLifecycleCommandReceipt:
        if record.anchor_fingerprint_after is None:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID,
                command_id=record.command.command_id,
            )
        return CheckpointLifecycleCommandReceipt(
            command_id=record.command.command_id,
            operation=record.command.operation,
            fence_token=record.command.fence_token,
            command_digest=record.command.digest(),
            anchor_fingerprint_after=record.anchor_fingerprint_after,
            provider_id=record.provider_id,
            replayed=replayed,
        )

    @staticmethod
    def _validate_operation_arguments(
        command: CheckpointLifecycleCommand,
        *,
        checkpoint_destination: Path | None,
        anchor_destination: Path | None,
        backup_database_path: Path | None,
        backup_anchor_path: Path | None,
    ) -> None:
        if command.operation is CheckpointLifecycleCommandOperation.SNAPSHOT:
            if checkpoint_destination is None or anchor_destination is None:
                raise CheckpointLifecycleJournalError(
                    CheckpointLifecycleJournalReason.OPERATION_ARGUMENTS_INVALID,
                    command_id=command.command_id,
                )
        if command.operation is CheckpointLifecycleCommandOperation.RESTORE:
            if backup_database_path is None or backup_anchor_path is None:
                raise CheckpointLifecycleJournalError(
                    CheckpointLifecycleJournalReason.OPERATION_ARGUMENTS_INVALID,
                    command_id=command.command_id,
                )

    def _invoke_provider(
        self,
        command: CheckpointLifecycleCommand,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        checkpoint_destination: Path | None,
        anchor_destination: Path | None,
        backup_database_path: Path | None,
        backup_anchor_path: Path | None,
    ) -> None:
        self.provider_invocations += 1
        if command.operation is CheckpointLifecycleCommandOperation.MIGRATION:
            self._provider.migrate_to_active_encryption_key(saver)
            return
        if command.operation is CheckpointLifecycleCommandOperation.SNAPSHOT:
            self._provider.snapshot_pair(
                saver,
                checkpoint_destination=Path(checkpoint_destination),
                anchor_destination=Path(anchor_destination),
            )
            return
        if command.operation is CheckpointLifecycleCommandOperation.RESTORE:
            self._provider.restore_pair(
                saver,
                backup_database_path=Path(backup_database_path),
                backup_anchor_path=Path(backup_anchor_path),
            )
            return
        raise CheckpointLifecycleJournalError(
            CheckpointLifecycleJournalReason.OPERATION_ARGUMENTS_INVALID,
            command_id=command.command_id,
        )

    def execute(
        self,
        command: CheckpointLifecycleCommand,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        checkpoint_destination: Path | None = None,
        anchor_destination: Path | None = None,
        backup_database_path: Path | None = None,
        backup_anchor_path: Path | None = None,
    ) -> CheckpointLifecycleCommandReceipt:
        record, highest_committed = self._load_record_for_command(command)
        if record.state is CheckpointLifecycleJournalState.COMMITTED:
            self.replay_hits += 1
            return self._receipt_from_record(record, replayed=True)
        if record.state is CheckpointLifecycleJournalState.PROVIDER_STARTED:
            record = self._set_state(
                record,
                CheckpointLifecycleJournalState.RECONCILIATION_REQUIRED,
            )
        if record.state is CheckpointLifecycleJournalState.RECONCILIATION_REQUIRED:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.RECONCILIATION_REQUIRED,
                command_id=command.command_id,
            )
        if record.state is not CheckpointLifecycleJournalState.PREPARED:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_STATE_INVALID,
                command_id=command.command_id,
            )
        if command.fence_token <= highest_committed:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.JOURNAL_FENCE_STALE,
                command_id=command.command_id,
            )
        if command.expected_anchor_fingerprint != self.anchor_fingerprint():
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.ANCHOR_FENCE_MISMATCH,
                command_id=command.command_id,
            )

        self._validate_operation_arguments(
            command,
            checkpoint_destination=checkpoint_destination,
            anchor_destination=anchor_destination,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
        )
        require_lifecycle_capability(self._provider, command.operation.capability)
        fault = self._consume_fault()
        if fault is CheckpointLifecycleJournalFaultMode.AFTER_PREPARED_BEFORE_PROVIDER:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.SYNTHETIC_CRASH,
                command_id=command.command_id,
                fault_mode=fault,
            )

        record = self._set_state(
            record,
            CheckpointLifecycleJournalState.PROVIDER_STARTED,
        )
        try:
            self._invoke_provider(
                command,
                saver,
                checkpoint_destination=checkpoint_destination,
                anchor_destination=anchor_destination,
                backup_database_path=backup_database_path,
                backup_anchor_path=backup_anchor_path,
            )
        except BaseException as exc:
            self._set_state(
                record,
                CheckpointLifecycleJournalState.RECONCILIATION_REQUIRED,
            )
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.RECONCILIATION_REQUIRED,
                command_id=command.command_id,
            ) from exc

        if fault is CheckpointLifecycleJournalFaultMode.AFTER_PROVIDER_BEFORE_COMMIT:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.SYNTHETIC_CRASH,
                command_id=command.command_id,
                fault_mode=fault,
            )

        receipt = self._commit_receipt(
            record,
            anchor_fingerprint_after=self.anchor_fingerprint(),
        )
        if fault is CheckpointLifecycleJournalFaultMode.AFTER_COMMIT_BEFORE_RESPONSE:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.SYNTHETIC_CRASH,
                command_id=command.command_id,
                fault_mode=fault,
            )
        return receipt

    @staticmethod
    def _migration_commit_proven(
        before: dict[str, object],
        current: dict[str, object],
    ) -> bool:
        try:
            before_total = int(before["checkpoint_total"]) + int(before["write_total"])
            before_active = int(before["checkpoint_active"]) + int(before["write_active"])
            current_total = int(current["checkpoint_total"]) + int(current["write_total"])
            current_active = int(current["checkpoint_active"]) + int(current["write_active"])
            return bool(
                before_total > 0
                and before_total == current_total
                and before_active < before_total
                and current_active == current_total
                and str(before["active_key_id"]) == str(current["active_key_id"])
                and str(before["anchor_fingerprint"]) != str(current["anchor_fingerprint"])
            )
        except (KeyError, TypeError, ValueError):
            return False

    def reconcile(
        self,
        command: CheckpointLifecycleCommand,
        saver: KeyLifecycleConfidentialCheckpointer,
    ) -> CheckpointLifecycleCommandReceipt:
        record, _ = self._load_record_for_command(command)
        if record.state is CheckpointLifecycleJournalState.COMMITTED:
            self.replay_hits += 1
            return self._receipt_from_record(record, replayed=True)
        if record.state is CheckpointLifecycleJournalState.PROVIDER_STARTED:
            record = self._set_state(
                record,
                CheckpointLifecycleJournalState.RECONCILIATION_REQUIRED,
            )
        if record.state is not CheckpointLifecycleJournalState.RECONCILIATION_REQUIRED:
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.RECONCILIATION_UNPROVABLE,
                command_id=command.command_id,
            )

        if command.operation is CheckpointLifecycleCommandOperation.MIGRATION:
            current = self._migration_observation(saver)
            if self._migration_commit_proven(record.pre_observation, current):
                receipt = self._commit_receipt(
                    record,
                    anchor_fingerprint_after=str(current["anchor_fingerprint"]),
                )
                self.reconciliations += 1
                return replace(receipt, replayed=True)

        raise CheckpointLifecycleJournalError(
            CheckpointLifecycleJournalReason.RECONCILIATION_UNPROVABLE,
            command_id=command.command_id,
        )

    @property
    def highest_issued_fence(self) -> int:
        connection = self._connect()
        try:
            row = self._read_meta(connection)
            return int(row["highest_issued_fence"])
        finally:
            connection.close()

    @property
    def highest_committed_fence(self) -> int:
        connection = self._connect()
        try:
            row = self._read_meta(connection)
            return int(row["highest_committed_fence"])
        finally:
            connection.close()

    @property
    def receipt_count(self) -> int:
        connection = self._connect()
        try:
            self._read_meta(connection)
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM lifecycle_commands WHERE state = ?",
                (CheckpointLifecycleJournalState.COMMITTED.value,),
            ).fetchone()
            return int(row["count"])
        finally:
            connection.close()

    def public_posture(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "policy_version": P4M_DURABLE_LIFECYCLE_JOURNAL_POLICY_VERSION,
            "synthetic_in_process": self.synthetic_in_process,
            "durable_local_journal": self.durable_local_journal,
            "distributed_fencing": self.distributed_fencing,
            "rollback_resistant_journal": self.rollback_resistant_journal,
            "exactly_once_execution": self.exactly_once_execution,
            "operationally_external": self.operationally_external,
            "production_runtime_eligible": self.production_runtime_eligible,
            "network_operations": self.network_operations,
            "highest_issued_fence": self.highest_issued_fence,
            "highest_committed_fence": self.highest_committed_fence,
            "receipt_count": self.receipt_count,
            "provider_invocations": self.provider_invocations,
            "replay_hits": self.replay_hits,
            "reconciliations": self.reconciliations,
        }
