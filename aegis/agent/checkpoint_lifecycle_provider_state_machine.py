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

from aegis.agent.checkpoint_external_lifecycle import _read_anchor_snapshot
from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_lifecycle_capabilities import require_lifecycle_capability
from aegis.agent.checkpoint_lifecycle_fencing import (
    CheckpointLifecycleCommand,
    CheckpointLifecycleCommandOperation,
    CheckpointLifecycleCommandReceipt,
)
from aegis.agent.checkpoint_lifecycle_journal import (
    CheckpointLifecycleJournalError,
    CheckpointLifecycleJournalReason,
    CheckpointLifecycleJournalState,
)
from aegis.agent.checkpoint_lifecycle_outcome_receipts import (
    ProviderLifecycleOutcomeError,
    ProviderLifecycleOutcomeReason,
    ProviderLifecycleOutcomeReceipt,
    ProviderOutcomeRecoveringLifecycleCoordinator,
    SyntheticProviderOutcomeReceiptStore,
)


P4P_PROVIDER_COMMAND_STATE_POLICY_VERSION = "crash-safe-provider-command-state-v1"
P4P_PROVIDER_COMMAND_STATE_SCHEMA_VERSION = "p4p-provider-command-state-schema-v1"


class ProviderCommandState(StrEnum):
    PREPARED = "prepared"
    MUTATION_STARTED = "mutation_started"
    COMMITTED = "committed"


class ProviderCommandFaultMode(StrEnum):
    NONE = "none"
    AFTER_PREPARE_BEFORE_MUTATION = "after_prepare_before_mutation"
    AFTER_MUTATION_BEFORE_RECEIPT = "after_mutation_before_receipt"
    AFTER_RECEIPT_BEFORE_RESPONSE = "after_receipt_before_response"


class ProviderCommandStateReason(StrEnum):
    STORE_STATE_INVALID = "checkpoint_lifecycle_provider_command_store_invalid"
    INTEGRITY_FAILED = "checkpoint_lifecycle_provider_command_integrity_failed"
    COMMAND_CONFLICT = "checkpoint_lifecycle_provider_command_conflict"
    COMMAND_MISSING = "checkpoint_lifecycle_provider_command_missing"
    ARGUMENT_CONFLICT = "checkpoint_lifecycle_provider_command_argument_conflict"
    STATE_INVALID = "checkpoint_lifecycle_provider_command_state_invalid"
    RECONCILIATION_UNPROVABLE = "checkpoint_lifecycle_provider_reconciliation_unprovable"
    SYNTHETIC_CRASH = "checkpoint_lifecycle_provider_synthetic_crash"


class ProviderCommandStateError(RuntimeError):
    def __init__(
        self,
        reason: ProviderCommandStateReason,
        *,
        command_id: str | None = None,
        fault_mode: ProviderCommandFaultMode | None = None,
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
class ProviderCommandStateRecord:
    command: CheckpointLifecycleCommand
    argument_digest: str
    state: ProviderCommandState
    pre_observation: dict[str, object]
    anchor_fingerprint_after: str | None
    provider_id: str


class SyntheticProviderCommandStateStore:
    """Authenticated local synthetic provider command state.

    This store models durable command identity inside the lifecycle-provider boundary.
    It remains a same-host SQLite/HMAC lab artifact and is intentionally not claimed
    as an independent failure domain or production transaction manager.
    """

    def __init__(self, *, database_path: Path, integrity_key_path: Path | None = None) -> None:
        self.database_path = Path(database_path)
        self.integrity_key_path = (
            Path(integrity_key_path)
            if integrity_key_path is not None
            else self.database_path.with_suffix(self.database_path.suffix + ".hmac-key")
        )
        self._integrity_key = self._open_or_create()
        self._verify_all()

    @staticmethod
    def _canonical(payload: dict[str, object]) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _open_or_create(self) -> bytes:
        store_exists = self.database_path.exists()
        key_exists = self.integrity_key_path.exists()
        if store_exists != key_exists:
            raise ProviderCommandStateError(ProviderCommandStateReason.STORE_STATE_INVALID)
        if store_exists:
            try:
                key = self.integrity_key_path.read_bytes()
            except OSError as exc:
                raise ProviderCommandStateError(
                    ProviderCommandStateReason.STORE_STATE_INVALID
                ) from exc
            if len(key) != 32:
                raise ProviderCommandStateError(ProviderCommandStateReason.STORE_STATE_INVALID)
            return key

        self.database_path.parent.mkdir(parents=True, exist_ok=True)
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

        connection = sqlite3.connect(self.database_path, timeout=5.0)
        try:
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute(
                """
                CREATE TABLE provider_commands (
                    command_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    fence_token INTEGER NOT NULL CHECK (fence_token >= 1),
                    expected_anchor_fingerprint TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    command_digest TEXT NOT NULL,
                    argument_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    pre_observation_json TEXT NOT NULL,
                    anchor_fingerprint_after TEXT,
                    provider_id TEXT NOT NULL,
                    integrity_tag TEXT NOT NULL
                )
                """
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            try:
                self.database_path.unlink()
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

    def _tag(
        self,
        *,
        command: CheckpointLifecycleCommand,
        argument_digest: str,
        state: ProviderCommandState,
        pre_observation_json: str,
        anchor_fingerprint_after: str | None,
        provider_id: str,
    ) -> str:
        return hmac.new(
            self._integrity_key,
            self._canonical(
                {
                    "policy_version": P4P_PROVIDER_COMMAND_STATE_POLICY_VERSION,
                    "schema_version": P4P_PROVIDER_COMMAND_STATE_SCHEMA_VERSION,
                    "command_id": command.command_id,
                    "operation": command.operation.value,
                    "fence_token": command.fence_token,
                    "expected_anchor_fingerprint": command.expected_anchor_fingerprint,
                    "resource_id": command.resource_id,
                    "command_digest": command.digest(),
                    "argument_digest": argument_digest,
                    "state": state.value,
                    "pre_observation_json": pre_observation_json,
                    "anchor_fingerprint_after": anchor_fingerprint_after,
                    "provider_id": provider_id,
                }
            ),
            hashlib.sha256,
        ).hexdigest()

    def _row_to_record(self, row: sqlite3.Row) -> ProviderCommandStateRecord:
        try:
            command = CheckpointLifecycleCommand(
                command_id=str(row["command_id"]),
                operation=CheckpointLifecycleCommandOperation(str(row["operation"])),
                fence_token=int(row["fence_token"]),
                expected_anchor_fingerprint=str(row["expected_anchor_fingerprint"]),
                resource_id=str(row["resource_id"]),
            )
            argument_digest = str(row["argument_digest"])
            state = ProviderCommandState(str(row["state"]))
            pre_json = str(row["pre_observation_json"])
            parsed = json.loads(pre_json)
            if not isinstance(parsed, dict):
                raise ValueError("provider pre observation is not an object")
            pre_observation = dict(parsed)
            anchor_after = (
                None
                if row["anchor_fingerprint_after"] is None
                else str(row["anchor_fingerprint_after"])
            )
            provider_id = str(row["provider_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderCommandStateError(ProviderCommandStateReason.STORE_STATE_INVALID) from exc
        if str(row["command_digest"]) != command.digest():
            raise ProviderCommandStateError(
                ProviderCommandStateReason.INTEGRITY_FAILED,
                command_id=command.command_id,
            )
        expected_tag = self._tag(
            command=command,
            argument_digest=argument_digest,
            state=state,
            pre_observation_json=pre_json,
            anchor_fingerprint_after=anchor_after,
            provider_id=provider_id,
        )
        if not hmac.compare_digest(str(row["integrity_tag"]), expected_tag):
            raise ProviderCommandStateError(
                ProviderCommandStateReason.INTEGRITY_FAILED,
                command_id=command.command_id,
            )
        if state is ProviderCommandState.COMMITTED and not anchor_after:
            raise ProviderCommandStateError(
                ProviderCommandStateReason.STATE_INVALID,
                command_id=command.command_id,
            )
        return ProviderCommandStateRecord(
            command=command,
            argument_digest=argument_digest,
            state=state,
            pre_observation=pre_observation,
            anchor_fingerprint_after=anchor_after,
            provider_id=provider_id,
        )

    def _load_row(self, connection: sqlite3.Connection, command_id: str) -> sqlite3.Row | None:
        return connection.execute(
            """
            SELECT command_id, operation, fence_token, expected_anchor_fingerprint,
                   resource_id, command_digest, argument_digest, state,
                   pre_observation_json, anchor_fingerprint_after, provider_id,
                   integrity_tag
            FROM provider_commands
            WHERE command_id = ?
            """,
            (command_id,),
        ).fetchone()

    def _verify_all(self) -> None:
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT command_id, operation, fence_token, expected_anchor_fingerprint,
                       resource_id, command_digest, argument_digest, state,
                       pre_observation_json, anchor_fingerprint_after, provider_id,
                       integrity_tag
                FROM provider_commands
                ORDER BY command_id
                """
            ).fetchall()
            for row in rows:
                self._row_to_record(row)
        except sqlite3.DatabaseError as exc:
            raise ProviderCommandStateError(
                ProviderCommandStateReason.STORE_STATE_INVALID
            ) from exc
        finally:
            connection.close()

    def prepare(
        self,
        *,
        command: CheckpointLifecycleCommand,
        argument_digest: str,
        pre_observation: dict[str, object],
        provider_id: str,
    ) -> ProviderCommandStateRecord:
        pre_json = json.dumps(pre_observation, sort_keys=True, separators=(",", ":"))
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing_row = self._load_row(connection, command.command_id)
            if existing_row is not None:
                existing = self._row_to_record(existing_row)
                if existing.command.digest() != command.digest():
                    raise ProviderCommandStateError(
                        ProviderCommandStateReason.COMMAND_CONFLICT,
                        command_id=command.command_id,
                    )
                if existing.argument_digest != argument_digest:
                    raise ProviderCommandStateError(
                        ProviderCommandStateReason.ARGUMENT_CONFLICT,
                        command_id=command.command_id,
                    )
                if existing.provider_id != provider_id:
                    raise ProviderCommandStateError(
                        ProviderCommandStateReason.COMMAND_CONFLICT,
                        command_id=command.command_id,
                    )
                connection.commit()
                return existing

            state = ProviderCommandState.PREPARED
            tag = self._tag(
                command=command,
                argument_digest=argument_digest,
                state=state,
                pre_observation_json=pre_json,
                anchor_fingerprint_after=None,
                provider_id=provider_id,
            )
            connection.execute(
                """
                INSERT INTO provider_commands (
                    command_id, operation, fence_token, expected_anchor_fingerprint,
                    resource_id, command_digest, argument_digest, state,
                    pre_observation_json, anchor_fingerprint_after, provider_id,
                    integrity_tag
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                """,
                (
                    command.command_id,
                    command.operation.value,
                    command.fence_token,
                    command.expected_anchor_fingerprint,
                    command.resource_id,
                    command.digest(),
                    argument_digest,
                    state.value,
                    pre_json,
                    provider_id,
                    tag,
                ),
            )
            connection.commit()
            return ProviderCommandStateRecord(
                command=command,
                argument_digest=argument_digest,
                state=state,
                pre_observation=dict(pre_observation),
                anchor_fingerprint_after=None,
                provider_id=provider_id,
            )
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def require(
        self,
        command: CheckpointLifecycleCommand,
        *,
        argument_digest: str | None = None,
    ) -> ProviderCommandStateRecord:
        connection = self._connect()
        try:
            row = self._load_row(connection, command.command_id)
        except sqlite3.DatabaseError as exc:
            raise ProviderCommandStateError(
                ProviderCommandStateReason.STORE_STATE_INVALID,
                command_id=command.command_id,
            ) from exc
        finally:
            connection.close()
        if row is None:
            raise ProviderCommandStateError(
                ProviderCommandStateReason.COMMAND_MISSING,
                command_id=command.command_id,
            )
        record = self._row_to_record(row)
        if record.command.digest() != command.digest():
            raise ProviderCommandStateError(
                ProviderCommandStateReason.COMMAND_CONFLICT,
                command_id=command.command_id,
            )
        if argument_digest is not None and record.argument_digest != argument_digest:
            raise ProviderCommandStateError(
                ProviderCommandStateReason.ARGUMENT_CONFLICT,
                command_id=command.command_id,
            )
        return record

    def set_state(
        self,
        record: ProviderCommandStateRecord,
        state: ProviderCommandState,
        *,
        anchor_fingerprint_after: str | None = None,
    ) -> ProviderCommandStateRecord:
        next_anchor = (
            record.anchor_fingerprint_after
            if anchor_fingerprint_after is None
            else anchor_fingerprint_after
        )
        pre_json = json.dumps(record.pre_observation, sort_keys=True, separators=(",", ":"))
        tag = self._tag(
            command=record.command,
            argument_digest=record.argument_digest,
            state=state,
            pre_observation_json=pre_json,
            anchor_fingerprint_after=next_anchor,
            provider_id=record.provider_id,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current_row = self._load_row(connection, record.command.command_id)
            if current_row is None:
                raise ProviderCommandStateError(
                    ProviderCommandStateReason.COMMAND_MISSING,
                    command_id=record.command.command_id,
                )
            current = self._row_to_record(current_row)
            if current.command.digest() != record.command.digest():
                raise ProviderCommandStateError(
                    ProviderCommandStateReason.COMMAND_CONFLICT,
                    command_id=record.command.command_id,
                )
            connection.execute(
                """
                UPDATE provider_commands
                SET state = ?, anchor_fingerprint_after = ?, integrity_tag = ?
                WHERE command_id = ?
                """,
                (
                    state.value,
                    next_anchor,
                    tag,
                    record.command.command_id,
                ),
            )
            connection.commit()
            return replace(
                record,
                state=state,
                anchor_fingerprint_after=next_anchor,
            )
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @property
    def command_count(self) -> int:
        connection = self._connect()
        try:
            row = connection.execute("SELECT COUNT(*) AS count FROM provider_commands").fetchone()
            return int(row["count"])
        finally:
            connection.close()


def _canonical_digest(payload: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _logical_checkpoint_db_fingerprint(database_path: Path) -> str:
    connection = sqlite3.connect(Path(database_path), timeout=5.0)
    try:
        checkpoint_rows = connection.execute(
            """
            SELECT thread_id, checkpoint_ns, checkpoint_id, parent_checkpoint_id,
                   type, hex(checkpoint), hex(metadata), generation,
                   previous_digest, integrity_digest
            FROM checkpoints
            ORDER BY thread_id, checkpoint_ns, generation
            """
        ).fetchall()
        write_rows = connection.execute(
            """
            SELECT thread_id, checkpoint_ns, checkpoint_id, task_id, idx, channel,
                   type, hex(value), integrity_digest
            FROM writes
            ORDER BY thread_id, checkpoint_ns, checkpoint_id, task_id, idx
            """
        ).fetchall()
    except sqlite3.DatabaseError as exc:
        raise ProviderCommandStateError(ProviderCommandStateReason.STORE_STATE_INVALID) from exc
    finally:
        connection.close()
    return _canonical_digest(
        {
            "checkpoints": [list(row) for row in checkpoint_rows],
            "writes": [list(row) for row in write_rows],
        }
    )


def _anchor_snapshot_fingerprint(anchor_path: Path) -> str:
    checkpoint_heads, write_heads = _read_anchor_snapshot(Path(anchor_path))
    return _canonical_digest(
        {
            "checkpoint_heads": checkpoint_heads,
            "write_heads": write_heads,
        }
    )


class SyntheticCrashSafeOutcomeReceiptLifecycleProvider:
    """Synthetic provider command state machine closing the P4-O mutation/receipt gap.

    Provider command identity is durably prepared before mutation. After a crash in
    the mutation-to-receipt window, recovery proves the observed lifecycle outcome
    before emitting the provider-owned P4-O receipt. No operation is re-run unless
    the durable provider state proves mutation never started.
    """

    provider_id = "synthetic-crash-safe-provider-outcome-checkpoint-lifecycle"
    synthetic_in_process = True
    operationally_external = False
    production_runtime_eligible = False
    independent_failure_domain = False
    exactly_once_execution = False
    provider_internal_crash_recovery = True
    network_operations = 0

    def __init__(
        self,
        *,
        lifecycle_provider: Any,
        command_database_path: Path,
        outcome_database_path: Path,
    ) -> None:
        if not str(getattr(lifecycle_provider, "provider_id", "")).strip():
            raise ValueError("inner lifecycle provider id must be non-empty")
        self._inner = lifecycle_provider
        self._anchor_provider = getattr(lifecycle_provider, "bound_anchor_provider", None)
        if self._anchor_provider is None:
            raise ValueError("inner lifecycle provider must expose its bound anchor")
        self.anchor_provider_id = str(getattr(lifecycle_provider, "anchor_provider_id", ""))
        self.capabilities = frozenset(getattr(lifecycle_provider, "capabilities", frozenset()))
        self.command_store = SyntheticProviderCommandStateStore(
            database_path=Path(command_database_path)
        )
        self.outcome_store = SyntheticProviderOutcomeReceiptStore(
            database_path=Path(outcome_database_path)
        )
        self.command_invocations = 0
        self.provider_replay_hits = 0
        self.provider_reconciliations = 0
        self._fault_mode = ProviderCommandFaultMode.NONE

    @property
    def bound_anchor_provider(self) -> Any:
        return self._anchor_provider

    @property
    def inner_provider(self) -> Any:
        return self._inner

    def arm_fault(self, mode: ProviderCommandFaultMode) -> None:
        self._fault_mode = ProviderCommandFaultMode(mode)

    def _consume_fault(self) -> ProviderCommandFaultMode:
        mode = self._fault_mode
        self._fault_mode = ProviderCommandFaultMode.NONE
        return mode

    def _export_anchor_state(
        self,
    ) -> tuple[tuple[dict[str, object], ...], tuple[dict[str, object], ...]]:
        export_heads = getattr(self._anchor_provider, "export_heads", None)
        export_write_heads = getattr(self._anchor_provider, "export_write_heads", None)
        if not callable(export_heads) or not callable(export_write_heads):
            raise ProviderLifecycleOutcomeError(ProviderLifecycleOutcomeReason.STORE_STATE_INVALID)
        return (
            tuple(dict(item) for item in export_heads()),
            tuple(dict(item) for item in export_write_heads()),
        )

    @staticmethod
    def _fingerprint_state(
        checkpoint_heads: tuple[dict[str, object], ...],
        write_heads: tuple[dict[str, object], ...],
    ) -> str:
        return _canonical_digest(
            {
                "checkpoint_heads": checkpoint_heads,
                "write_heads": write_heads,
            }
        )

    def anchor_fingerprint(self) -> str:
        return self._fingerprint_state(*self._export_anchor_state())

    @staticmethod
    def _validate_arguments(
        command: CheckpointLifecycleCommand,
        *,
        checkpoint_destination: Path | None,
        anchor_destination: Path | None,
        backup_database_path: Path | None,
        backup_anchor_path: Path | None,
    ) -> None:
        if command.operation is CheckpointLifecycleCommandOperation.SNAPSHOT and (
            checkpoint_destination is None or anchor_destination is None
        ):
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.OPERATION_ARGUMENTS_INVALID,
                command_id=command.command_id,
            )
        if command.operation is CheckpointLifecycleCommandOperation.RESTORE and (
            backup_database_path is None or backup_anchor_path is None
        ):
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.OPERATION_ARGUMENTS_INVALID,
                command_id=command.command_id,
            )

    @staticmethod
    def _path_token(path: Path | None) -> str | None:
        if path is None:
            return None
        return str(Path(path).resolve(strict=False))

    def _argument_digest(
        self,
        command: CheckpointLifecycleCommand,
        *,
        checkpoint_destination: Path | None,
        anchor_destination: Path | None,
        backup_database_path: Path | None,
        backup_anchor_path: Path | None,
    ) -> str:
        return _canonical_digest(
            {
                "operation": command.operation.value,
                "checkpoint_destination": self._path_token(checkpoint_destination),
                "anchor_destination": self._path_token(anchor_destination),
                "backup_database_path": self._path_token(backup_database_path),
                "backup_anchor_path": self._path_token(backup_anchor_path),
            }
        )

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
            "database_fingerprint": _logical_checkpoint_db_fingerprint(saver.database_path),
        }

    def _pre_observation(
        self,
        command: CheckpointLifecycleCommand,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        backup_database_path: Path | None,
        backup_anchor_path: Path | None,
    ) -> dict[str, object]:
        if command.operation is CheckpointLifecycleCommandOperation.MIGRATION:
            return self._migration_observation(saver)
        observation: dict[str, object] = {
            "anchor_fingerprint": self.anchor_fingerprint(),
            "database_fingerprint": _logical_checkpoint_db_fingerprint(saver.database_path),
        }
        if command.operation is CheckpointLifecycleCommandOperation.RESTORE:
            observation["backup_database_fingerprint"] = _logical_checkpoint_db_fingerprint(
                Path(backup_database_path)
            )
            observation["backup_anchor_fingerprint"] = _anchor_snapshot_fingerprint(
                Path(backup_anchor_path)
            )
        return observation

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

    def _snapshot_commit_proven(
        self,
        before: dict[str, object],
        *,
        checkpoint_destination: Path | None,
        anchor_destination: Path | None,
    ) -> bool:
        if checkpoint_destination is None or anchor_destination is None:
            return False
        try:
            return bool(
                Path(checkpoint_destination).is_file()
                and Path(anchor_destination).is_file()
                and _logical_checkpoint_db_fingerprint(Path(checkpoint_destination))
                == str(before["database_fingerprint"])
                and _anchor_snapshot_fingerprint(Path(anchor_destination))
                == str(before["anchor_fingerprint"])
            )
        except (KeyError, OSError, ProviderCommandStateError):
            return False

    def _restore_commit_proven(
        self,
        before: dict[str, object],
        saver: KeyLifecycleConfidentialCheckpointer,
    ) -> bool:
        try:
            return bool(
                _logical_checkpoint_db_fingerprint(saver.database_path)
                == str(before["backup_database_fingerprint"])
                and self.anchor_fingerprint() == str(before["backup_anchor_fingerprint"])
            )
        except (KeyError, OSError, ProviderCommandStateError):
            return False

    def _invoke_inner(
        self,
        command: CheckpointLifecycleCommand,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        checkpoint_destination: Path | None,
        anchor_destination: Path | None,
        backup_database_path: Path | None,
        backup_anchor_path: Path | None,
    ) -> None:
        self.command_invocations += 1
        if command.operation is CheckpointLifecycleCommandOperation.MIGRATION:
            self._inner.migrate_to_active_encryption_key(saver)
            return
        if command.operation is CheckpointLifecycleCommandOperation.SNAPSHOT:
            self._inner.snapshot_pair(
                saver,
                checkpoint_destination=Path(checkpoint_destination),
                anchor_destination=Path(anchor_destination),
            )
            return
        if command.operation is CheckpointLifecycleCommandOperation.RESTORE:
            self._inner.restore_pair(
                saver,
                backup_database_path=Path(backup_database_path),
                backup_anchor_path=Path(backup_anchor_path),
            )
            return
        raise ProviderLifecycleOutcomeError(
            ProviderLifecycleOutcomeReason.OPERATION_ARGUMENTS_INVALID,
            command_id=command.command_id,
        )

    def _receipt(
        self,
        command: CheckpointLifecycleCommand,
        *,
        anchor_fingerprint_after: str,
        replayed: bool = False,
    ) -> ProviderLifecycleOutcomeReceipt:
        return ProviderLifecycleOutcomeReceipt(
            command_id=command.command_id,
            operation=command.operation,
            fence_token=command.fence_token,
            resource_id=command.resource_id,
            command_digest=command.digest(),
            expected_anchor_fingerprint=command.expected_anchor_fingerprint,
            anchor_fingerprint_after=anchor_fingerprint_after,
            provider_id=self.provider_id,
            replayed=replayed,
        )

    def execute_lifecycle_command(
        self,
        command: CheckpointLifecycleCommand,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        checkpoint_destination: Path | None = None,
        anchor_destination: Path | None = None,
        backup_database_path: Path | None = None,
        backup_anchor_path: Path | None = None,
    ) -> ProviderLifecycleOutcomeReceipt:
        self._validate_arguments(
            command,
            checkpoint_destination=checkpoint_destination,
            anchor_destination=anchor_destination,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
        )
        argument_digest = self._argument_digest(
            command,
            checkpoint_destination=checkpoint_destination,
            anchor_destination=anchor_destination,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
        )
        existing = self.outcome_store.get(command)
        if existing is not None:
            self.command_store.require(command, argument_digest=argument_digest)
            self.provider_replay_hits += 1
            return replace(existing, replayed=True)

        require_lifecycle_capability(self, command.operation.capability)
        pre_observation = self._pre_observation(
            command,
            saver,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
        )
        record = self.command_store.prepare(
            command=command,
            argument_digest=argument_digest,
            pre_observation=pre_observation,
            provider_id=self.provider_id,
        )

        if record.state is ProviderCommandState.MUTATION_STARTED:
            return self.recover_lifecycle_command(
                command,
                saver,
                checkpoint_destination=checkpoint_destination,
                anchor_destination=anchor_destination,
                backup_database_path=backup_database_path,
                backup_anchor_path=backup_anchor_path,
            )
        if record.state is ProviderCommandState.COMMITTED:
            raise ProviderCommandStateError(
                ProviderCommandStateReason.STATE_INVALID,
                command_id=command.command_id,
            )
        if command.expected_anchor_fingerprint != self.anchor_fingerprint():
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.ANCHOR_PRECONDITION_MISMATCH,
                command_id=command.command_id,
            )

        fault = self._consume_fault()
        if fault is ProviderCommandFaultMode.AFTER_PREPARE_BEFORE_MUTATION:
            raise ProviderCommandStateError(
                ProviderCommandStateReason.SYNTHETIC_CRASH,
                command_id=command.command_id,
                fault_mode=fault,
            )

        record = self.command_store.set_state(record, ProviderCommandState.MUTATION_STARTED)
        self._invoke_inner(
            command,
            saver,
            checkpoint_destination=checkpoint_destination,
            anchor_destination=anchor_destination,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
        )

        if fault is ProviderCommandFaultMode.AFTER_MUTATION_BEFORE_RECEIPT:
            raise ProviderCommandStateError(
                ProviderCommandStateReason.SYNTHETIC_CRASH,
                command_id=command.command_id,
                fault_mode=fault,
            )

        receipt = self._receipt(
            command,
            anchor_fingerprint_after=self.anchor_fingerprint(),
        )
        receipt = self.outcome_store.put(receipt)
        self.command_store.set_state(
            record,
            ProviderCommandState.COMMITTED,
            anchor_fingerprint_after=receipt.anchor_fingerprint_after,
        )

        if fault is ProviderCommandFaultMode.AFTER_RECEIPT_BEFORE_RESPONSE:
            raise ProviderCommandStateError(
                ProviderCommandStateReason.SYNTHETIC_CRASH,
                command_id=command.command_id,
                fault_mode=fault,
            )
        return receipt

    def recover_lifecycle_command(
        self,
        command: CheckpointLifecycleCommand,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        checkpoint_destination: Path | None = None,
        anchor_destination: Path | None = None,
        backup_database_path: Path | None = None,
        backup_anchor_path: Path | None = None,
    ) -> ProviderLifecycleOutcomeReceipt:
        self._validate_arguments(
            command,
            checkpoint_destination=checkpoint_destination,
            anchor_destination=anchor_destination,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
        )
        argument_digest = self._argument_digest(
            command,
            checkpoint_destination=checkpoint_destination,
            anchor_destination=anchor_destination,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
        )
        record = self.command_store.require(command, argument_digest=argument_digest)
        existing = self.outcome_store.get(command)
        if existing is not None:
            if record.state is not ProviderCommandState.COMMITTED:
                record = self.command_store.set_state(
                    record,
                    ProviderCommandState.COMMITTED,
                    anchor_fingerprint_after=existing.anchor_fingerprint_after,
                )
            self.provider_replay_hits += 1
            return replace(existing, replayed=True)

        if record.state is ProviderCommandState.PREPARED:
            return replace(
                self.execute_lifecycle_command(
                    command,
                    saver,
                    checkpoint_destination=checkpoint_destination,
                    anchor_destination=anchor_destination,
                    backup_database_path=backup_database_path,
                    backup_anchor_path=backup_anchor_path,
                ),
                replayed=True,
            )

        if record.state is not ProviderCommandState.MUTATION_STARTED:
            raise ProviderCommandStateError(
                ProviderCommandStateReason.STATE_INVALID,
                command_id=command.command_id,
            )

        if command.operation is CheckpointLifecycleCommandOperation.MIGRATION:
            current = self._migration_observation(saver)
            proven = self._migration_commit_proven(record.pre_observation, current)
        elif command.operation is CheckpointLifecycleCommandOperation.SNAPSHOT:
            proven = self._snapshot_commit_proven(
                record.pre_observation,
                checkpoint_destination=checkpoint_destination,
                anchor_destination=anchor_destination,
            )
        elif command.operation is CheckpointLifecycleCommandOperation.RESTORE:
            proven = self._restore_commit_proven(record.pre_observation, saver)
        else:
            proven = False

        if not proven:
            raise ProviderCommandStateError(
                ProviderCommandStateReason.RECONCILIATION_UNPROVABLE,
                command_id=command.command_id,
            )

        anchor_after = self.anchor_fingerprint()
        receipt = self.outcome_store.put(
            self._receipt(
                command,
                anchor_fingerprint_after=anchor_after,
            )
        )
        self.command_store.set_state(
            record,
            ProviderCommandState.COMMITTED,
            anchor_fingerprint_after=anchor_after,
        )
        self.provider_reconciliations += 1
        return replace(receipt, replayed=True)

    def get_lifecycle_outcome_receipt(
        self, command: CheckpointLifecycleCommand
    ) -> ProviderLifecycleOutcomeReceipt:
        return self.outcome_store.require(command)

    def public_posture(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "anchor_provider_id": self.anchor_provider_id,
            "policy_version": P4P_PROVIDER_COMMAND_STATE_POLICY_VERSION,
            "capabilities": sorted(capability.value for capability in self.capabilities),
            "synthetic_in_process": self.synthetic_in_process,
            "operationally_external": self.operationally_external,
            "production_runtime_eligible": self.production_runtime_eligible,
            "independent_failure_domain": self.independent_failure_domain,
            "exactly_once_execution": self.exactly_once_execution,
            "provider_internal_crash_recovery": self.provider_internal_crash_recovery,
            "network_operations": self.network_operations,
            "provider_owned_command_state": True,
            "authenticated_provider_command_state": True,
            "authenticated_outcome_receipts": True,
            "command_count": self.command_store.command_count,
            "receipt_count": self.outcome_store.receipt_count,
            "command_invocations": self.command_invocations,
            "provider_replay_hits": self.provider_replay_hits,
            "provider_reconciliations": self.provider_reconciliations,
        }


class ProviderStateMachineRecoveringLifecycleCoordinator(
    ProviderOutcomeRecoveringLifecycleCoordinator
):
    """Caller coordinator that asks P4-P provider state to resolve internal ambiguity."""

    def reconcile(
        self,
        command: CheckpointLifecycleCommand,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        checkpoint_destination: Path | None = None,
        anchor_destination: Path | None = None,
        backup_database_path: Path | None = None,
        backup_anchor_path: Path | None = None,
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

        recover = getattr(self._provider, "recover_lifecycle_command", None)
        if not callable(recover):
            raise ProviderCommandStateError(
                ProviderCommandStateReason.RECONCILIATION_UNPROVABLE,
                command_id=command.command_id,
            )
        provider_receipt = recover(
            command,
            saver,
            checkpoint_destination=checkpoint_destination,
            anchor_destination=anchor_destination,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
        )
        if provider_receipt.provider_id != self.provider_id:
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.PROVIDER_ID_MISMATCH,
                command_id=command.command_id,
            )
        if provider_receipt.anchor_fingerprint_after != self.anchor_fingerprint():
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.ANCHOR_POSTCONDITION_MISMATCH,
                command_id=command.command_id,
            )

        receipt = self._commit_receipt(
            record,
            anchor_fingerprint_after=provider_receipt.anchor_fingerprint_after,
        )
        self.reconciliations += 1
        return replace(receipt, replayed=True)
