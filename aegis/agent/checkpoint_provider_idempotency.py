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
from aegis.agent.checkpoint_lifecycle_journal import (
    CheckpointLifecycleJournalReason,
    CheckpointLifecycleJournalState,
    DurableSyntheticCheckpointLifecycleCoordinator,
)


P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_POLICY_VERSION = (
    "synthetic-provider-lifecycle-idempotency-receipt-v1"
)
P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_SCHEMA_VERSION = (
    "p4o-provider-lifecycle-idempotency-schema-v1"
)


class CheckpointProviderLifecycleState(StrEnum):
    ACCEPTED = "accepted"
    STARTED = "started"
    APPLIED = "applied"


class CheckpointProviderLifecycleFaultMode(StrEnum):
    NONE = "none"
    AFTER_ACCEPTED_BEFORE_SIDE_EFFECT = "after_accepted_before_side_effect"
    AFTER_SIDE_EFFECT_BEFORE_APPLIED = "after_side_effect_before_applied"
    AFTER_APPLIED_BEFORE_RESPONSE = "after_applied_before_response"


class CheckpointProviderLifecycleReason(StrEnum):
    LEDGER_INTEGRITY_FAILED = "checkpoint_lifecycle_provider_ledger_integrity_failed"
    LEDGER_STATE_INVALID = "checkpoint_lifecycle_provider_ledger_state_invalid"
    COMMAND_CONFLICT = "checkpoint_lifecycle_provider_command_conflict"
    FENCE_STALE = "checkpoint_lifecycle_provider_fence_stale"
    ANCHOR_PRECONDITION_FAILED = "checkpoint_lifecycle_provider_anchor_precondition_failed"
    OPERATION_ARGUMENTS_INVALID = "checkpoint_lifecycle_provider_operation_arguments_invalid"
    OUTCOME_UNKNOWN = "checkpoint_lifecycle_provider_outcome_unknown"
    OUTCOME_MISMATCH = "checkpoint_lifecycle_provider_outcome_mismatch"
    RECEIPT_INVALID = "checkpoint_lifecycle_provider_receipt_invalid"
    RECEIPT_COMMAND_MISMATCH = "checkpoint_lifecycle_provider_receipt_command_mismatch"
    COMMAND_CONTEXT_REQUIRED = "checkpoint_lifecycle_provider_command_context_required"
    SYNTHETIC_CRASH = "checkpoint_lifecycle_provider_synthetic_crash"


class CheckpointProviderLifecycleError(RuntimeError):
    def __init__(
        self,
        reason: CheckpointProviderLifecycleReason,
        *,
        command_id: str | None = None,
        fault_mode: CheckpointProviderLifecycleFaultMode | None = None,
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
class ProviderLifecycleOutcomeReceipt:
    provider_id: str
    command_id: str
    command_digest: str
    operation: CheckpointLifecycleCommandOperation
    fence_token: int
    resource_id: str
    expected_anchor_fingerprint: str
    request_digest: str
    anchor_fingerprint_after: str
    result_digest: str
    receipt_tag: str
    replayed: bool = False

    def signed_payload(self) -> dict[str, object]:
        return {
            "policy_version": P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_POLICY_VERSION,
            "provider_id": self.provider_id,
            "command_id": self.command_id,
            "command_digest": self.command_digest,
            "operation": self.operation.value,
            "fence_token": self.fence_token,
            "resource_id": self.resource_id,
            "expected_anchor_fingerprint": self.expected_anchor_fingerprint,
            "request_digest": self.request_digest,
            "anchor_fingerprint_after": self.anchor_fingerprint_after,
            "result_digest": self.result_digest,
        }


@dataclass(frozen=True)
class ProviderLifecycleRecord:
    command: CheckpointLifecycleCommand
    request_digest: str
    state: CheckpointProviderLifecycleState
    anchor_fingerprint_after: str | None
    result_digest: str | None
    receipt_tag: str | None


class SyntheticProviderIdempotentCheckpointLifecycleProvider:
    """Provider-owned durable idempotency and outcome-receipt harness.

    A separate SQLite ledger records provider acceptance, start, and applied
    outcomes. Exact duplicate applied commands return the authenticated provider
    receipt without re-invoking the wrapped P4-J lifecycle provider. A command
    left in STARTED has an ambiguous provider outcome and fails closed instead of
    replaying the side effect.

    This is synthetic, local, and in-process. It is not an external service, a
    distributed transaction coordinator, or an exactly-once execution system.
    """

    provider_id = "synthetic-provider-idempotent-checkpoint-lifecycle"
    synthetic_in_process = True
    operationally_external = False
    production_runtime_eligible = False
    independent_failure_domain = False
    provider_owned_durable_idempotency_ledger = True
    exactly_once_execution = False
    distributed_transaction = False
    network_operations = 0

    def __init__(
        self,
        *,
        lifecycle_provider: Any,
        ledger_path: Path,
        integrity_key_path: Path | None = None,
    ) -> None:
        if not str(getattr(lifecycle_provider, "provider_id", "")).strip():
            raise ValueError("wrapped lifecycle provider id must be non-empty")
        self._delegate = lifecycle_provider
        self.ledger_path = Path(ledger_path)
        self.integrity_key_path = (
            Path(integrity_key_path)
            if integrity_key_path is not None
            else self.ledger_path.with_suffix(self.ledger_path.suffix + ".hmac-key")
        )
        self.anchor_provider_id = str(getattr(lifecycle_provider, "anchor_provider_id", ""))
        self.capabilities = frozenset(getattr(lifecycle_provider, "capabilities", frozenset()))
        self._fault_mode = CheckpointProviderLifecycleFaultMode.NONE
        self.side_effect_invocations = 0
        self.replay_hits = 0
        self.query_hits = 0
        self._integrity_key = self._open_or_create_store()
        self._verify_store()

    @property
    def bound_anchor_provider(self) -> Any:
        return getattr(self._delegate, "bound_anchor_provider", None)

    @property
    def wrapped_provider_id(self) -> str:
        return str(getattr(self._delegate, "provider_id", ""))

    def arm_fault(self, mode: CheckpointProviderLifecycleFaultMode) -> None:
        self._fault_mode = CheckpointProviderLifecycleFaultMode(mode)

    def _consume_fault(self) -> CheckpointProviderLifecycleFaultMode:
        mode = self._fault_mode
        self._fault_mode = CheckpointProviderLifecycleFaultMode.NONE
        return mode

    @staticmethod
    def _canonical_json(payload: object) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.ledger_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _open_or_create_store(self) -> bytes:
        ledger_exists = self.ledger_path.exists()
        key_exists = self.integrity_key_path.exists()
        if ledger_exists != key_exists:
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID
            )
        if ledger_exists:
            try:
                key = self.integrity_key_path.read_bytes()
            except OSError as exc:
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID
                ) from exc
            if len(key) != 32:
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID
                )
            return key

        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
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

        connection = sqlite3.connect(self.ledger_path, timeout=5.0)
        try:
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE provider_meta (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version TEXT NOT NULL,
                    highest_accepted_fence INTEGER NOT NULL CHECK (highest_accepted_fence >= 0),
                    integrity_tag TEXT NOT NULL
                );
                CREATE TABLE provider_commands (
                    command_id TEXT PRIMARY KEY,
                    command_digest TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    fence_token INTEGER NOT NULL UNIQUE CHECK (fence_token >= 1),
                    resource_id TEXT NOT NULL,
                    expected_anchor_fingerprint TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    anchor_fingerprint_after TEXT,
                    result_digest TEXT,
                    receipt_tag TEXT,
                    integrity_tag TEXT NOT NULL
                );
                """
            )
            tag = self._meta_tag_for_key(key, highest_accepted_fence=0)
            connection.execute(
                """
                INSERT INTO provider_meta (
                    singleton, schema_version, highest_accepted_fence, integrity_tag
                ) VALUES (1, ?, 0, ?)
                """,
                (P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_SCHEMA_VERSION, tag),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            try:
                self.ledger_path.unlink()
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

    @classmethod
    def _meta_tag_for_key(cls, key: bytes, *, highest_accepted_fence: int) -> str:
        payload = {
            "policy_version": P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_POLICY_VERSION,
            "schema_version": P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_SCHEMA_VERSION,
            "provider_id": cls.provider_id,
            "highest_accepted_fence": int(highest_accepted_fence),
        }
        return hmac.new(key, cls._canonical_json(payload), hashlib.sha256).hexdigest()

    def _meta_tag(self, *, highest_accepted_fence: int) -> str:
        return self._meta_tag_for_key(
            self._integrity_key,
            highest_accepted_fence=highest_accepted_fence,
        )

    def _row_tag(
        self,
        *,
        command: CheckpointLifecycleCommand,
        request_digest: str,
        state: CheckpointProviderLifecycleState,
        anchor_fingerprint_after: str | None,
        result_digest: str | None,
        receipt_tag: str | None,
    ) -> str:
        payload = {
            "policy_version": P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_POLICY_VERSION,
            "provider_id": self.provider_id,
            "command_id": command.command_id,
            "command_digest": command.digest(),
            "operation": command.operation.value,
            "fence_token": command.fence_token,
            "resource_id": command.resource_id,
            "expected_anchor_fingerprint": command.expected_anchor_fingerprint,
            "request_digest": request_digest,
            "state": state.value,
            "anchor_fingerprint_after": anchor_fingerprint_after,
            "result_digest": result_digest,
            "receipt_tag": receipt_tag,
        }
        return hmac.new(
            self._integrity_key,
            self._canonical_json(payload),
            hashlib.sha256,
        ).hexdigest()

    def _receipt_tag(self, payload: dict[str, object]) -> str:
        return hmac.new(
            self._integrity_key,
            self._canonical_json(payload),
            hashlib.sha256,
        ).hexdigest()

    def _read_meta(self, connection: sqlite3.Connection) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM provider_meta WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID
            )
        if str(row["schema_version"]) != P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_SCHEMA_VERSION:
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID
            )
        highest = int(row["highest_accepted_fence"])
        expected = self._meta_tag(highest_accepted_fence=highest)
        if not hmac.compare_digest(str(row["integrity_tag"]), expected):
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.LEDGER_INTEGRITY_FAILED
            )
        return row

    @staticmethod
    def _command_from_row(row: sqlite3.Row) -> CheckpointLifecycleCommand:
        try:
            return CheckpointLifecycleCommand(
                command_id=str(row["command_id"]),
                operation=CheckpointLifecycleCommandOperation(str(row["operation"])),
                fence_token=int(row["fence_token"]),
                expected_anchor_fingerprint=str(row["expected_anchor_fingerprint"]),
                resource_id=str(row["resource_id"]),
            )
        except (TypeError, ValueError) as exc:
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID
            ) from exc

    def _record_from_row(self, row: sqlite3.Row) -> ProviderLifecycleRecord:
        command = self._command_from_row(row)
        if str(row["command_digest"]) != command.digest():
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.LEDGER_INTEGRITY_FAILED,
                command_id=command.command_id,
            )
        try:
            state = CheckpointProviderLifecycleState(str(row["state"]))
        except ValueError as exc:
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID,
                command_id=command.command_id,
            ) from exc
        request_digest = str(row["request_digest"])
        anchor_after = (
            None if row["anchor_fingerprint_after"] is None else str(row["anchor_fingerprint_after"])
        )
        result_digest = None if row["result_digest"] is None else str(row["result_digest"])
        receipt_tag = None if row["receipt_tag"] is None else str(row["receipt_tag"])
        expected = self._row_tag(
            command=command,
            request_digest=request_digest,
            state=state,
            anchor_fingerprint_after=anchor_after,
            result_digest=result_digest,
            receipt_tag=receipt_tag,
        )
        if not hmac.compare_digest(str(row["integrity_tag"]), expected):
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.LEDGER_INTEGRITY_FAILED,
                command_id=command.command_id,
            )
        if state is CheckpointProviderLifecycleState.APPLIED:
            if anchor_after is None or result_digest is None or receipt_tag is None:
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID,
                    command_id=command.command_id,
                )
        elif anchor_after is not None or result_digest is not None or receipt_tag is not None:
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID,
                command_id=command.command_id,
            )
        return ProviderLifecycleRecord(
            command=command,
            request_digest=request_digest,
            state=state,
            anchor_fingerprint_after=anchor_after,
            result_digest=result_digest,
            receipt_tag=receipt_tag,
        )

    def _verify_store(self) -> None:
        connection = self._connect()
        try:
            meta = self._read_meta(connection)
            rows = connection.execute(
                "SELECT * FROM provider_commands ORDER BY fence_token"
            ).fetchall()
            records = [self._record_from_row(row) for row in rows]
        except sqlite3.DatabaseError as exc:
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID
            ) from exc
        finally:
            connection.close()
        fences = [record.command.fence_token for record in records]
        if len(fences) != len(set(fences)):
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID
            )
        if fences and max(fences) > int(meta["highest_accepted_fence"]):
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID
            )

    def _load_record(self, command_id: str) -> ProviderLifecycleRecord | None:
        connection = self._connect()
        try:
            self._read_meta(connection)
            row = connection.execute(
                "SELECT * FROM provider_commands WHERE command_id = ?",
                (command_id,),
            ).fetchone()
            return None if row is None else self._record_from_row(row)
        finally:
            connection.close()

    def _anchor_fingerprint(self) -> str:
        anchor = self.bound_anchor_provider
        export_heads = getattr(anchor, "export_heads", None)
        export_write_heads = getattr(anchor, "export_write_heads", None)
        if not callable(export_heads) or not callable(export_write_heads):
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID
            )
        payload = {
            "checkpoint_heads": tuple(dict(item) for item in export_heads()),
            "write_heads": tuple(dict(item) for item in export_write_heads()),
        }
        return hashlib.sha256(self._canonical_json(payload)).hexdigest()

    @staticmethod
    def _path_identity(path: Path | None) -> str | None:
        if path is None:
            return None
        return str(Path(path).resolve())

    def _request_digest(
        self,
        command: CheckpointLifecycleCommand,
        *,
        checkpoint_destination: Path | None,
        anchor_destination: Path | None,
        backup_database_path: Path | None,
        backup_anchor_path: Path | None,
    ) -> str:
        payload = {
            "policy_version": P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_POLICY_VERSION,
            "provider_id": self.provider_id,
            "command_digest": command.digest(),
            "checkpoint_destination": self._path_identity(checkpoint_destination),
            "anchor_destination": self._path_identity(anchor_destination),
            "backup_database_path": self._path_identity(backup_database_path),
            "backup_anchor_path": self._path_identity(backup_anchor_path),
        }
        return hashlib.sha256(self._canonical_json(payload)).hexdigest()

    @staticmethod
    def _validate_arguments(
        command: CheckpointLifecycleCommand,
        *,
        checkpoint_destination: Path | None,
        anchor_destination: Path | None,
        backup_database_path: Path | None,
        backup_anchor_path: Path | None,
    ) -> None:
        if command.operation is CheckpointLifecycleCommandOperation.MIGRATION:
            if any(
                value is not None
                for value in (
                    checkpoint_destination,
                    anchor_destination,
                    backup_database_path,
                    backup_anchor_path,
                )
            ):
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.OPERATION_ARGUMENTS_INVALID,
                    command_id=command.command_id,
                )
            return
        if command.operation is CheckpointLifecycleCommandOperation.SNAPSHOT:
            if (
                checkpoint_destination is None
                or anchor_destination is None
                or backup_database_path is not None
                or backup_anchor_path is not None
            ):
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.OPERATION_ARGUMENTS_INVALID,
                    command_id=command.command_id,
                )
            return
        if command.operation is CheckpointLifecycleCommandOperation.RESTORE:
            if (
                backup_database_path is None
                or backup_anchor_path is None
                or checkpoint_destination is not None
                or anchor_destination is not None
            ):
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.OPERATION_ARGUMENTS_INVALID,
                    command_id=command.command_id,
                )
            return
        raise CheckpointProviderLifecycleError(
            CheckpointProviderLifecycleReason.OPERATION_ARGUMENTS_INVALID,
            command_id=command.command_id,
        )

    def _insert_accepted(
        self,
        command: CheckpointLifecycleCommand,
        *,
        request_digest: str,
    ) -> ProviderLifecycleRecord:
        tag = self._row_tag(
            command=command,
            request_digest=request_digest,
            state=CheckpointProviderLifecycleState.ACCEPTED,
            anchor_fingerprint_after=None,
            result_digest=None,
            receipt_tag=None,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            meta = self._read_meta(connection)
            highest = int(meta["highest_accepted_fence"])
            if command.fence_token <= highest:
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.FENCE_STALE,
                    command_id=command.command_id,
                )
            if connection.execute(
                "SELECT 1 FROM provider_commands WHERE command_id = ?",
                (command.command_id,),
            ).fetchone() is not None:
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.COMMAND_CONFLICT,
                    command_id=command.command_id,
                )
            connection.execute(
                """
                INSERT INTO provider_commands (
                    command_id, command_digest, operation, fence_token, resource_id,
                    expected_anchor_fingerprint, request_digest, state,
                    anchor_fingerprint_after, result_digest, receipt_tag, integrity_tag
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, ?)
                """,
                (
                    command.command_id,
                    command.digest(),
                    command.operation.value,
                    command.fence_token,
                    command.resource_id,
                    command.expected_anchor_fingerprint,
                    request_digest,
                    CheckpointProviderLifecycleState.ACCEPTED.value,
                    tag,
                ),
            )
            meta_tag = self._meta_tag(highest_accepted_fence=command.fence_token)
            connection.execute(
                """
                UPDATE provider_meta
                SET highest_accepted_fence = ?, integrity_tag = ?
                WHERE singleton = 1
                """,
                (command.fence_token, meta_tag),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return ProviderLifecycleRecord(
            command=command,
            request_digest=request_digest,
            state=CheckpointProviderLifecycleState.ACCEPTED,
            anchor_fingerprint_after=None,
            result_digest=None,
            receipt_tag=None,
        )

    def _set_state(
        self,
        record: ProviderLifecycleRecord,
        state: CheckpointProviderLifecycleState,
    ) -> ProviderLifecycleRecord:
        if record.state is not CheckpointProviderLifecycleState.ACCEPTED:
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID,
                command_id=record.command.command_id,
            )
        tag = self._row_tag(
            command=record.command,
            request_digest=record.request_digest,
            state=state,
            anchor_fingerprint_after=None,
            result_digest=None,
            receipt_tag=None,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM provider_commands WHERE command_id = ?",
                (record.command.command_id,),
            ).fetchone()
            if current is None or self._record_from_row(current) != record:
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.COMMAND_CONFLICT,
                    command_id=record.command.command_id,
                )
            connection.execute(
                "UPDATE provider_commands SET state = ?, integrity_tag = ? WHERE command_id = ?",
                (state.value, tag, record.command.command_id),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return replace(record, state=state)

    @staticmethod
    def _file_digest(path: Path) -> str:
        digest = hashlib.sha256()
        with Path(path).open("rb") as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()

    def _result_digest(
        self,
        command: CheckpointLifecycleCommand,
        result: object,
        *,
        checkpoint_destination: Path | None,
        anchor_destination: Path | None,
        backup_database_path: Path | None,
        backup_anchor_path: Path | None,
        anchor_fingerprint_after: str,
    ) -> str:
        summary: dict[str, object] = {
            "operation": command.operation.value,
            "anchor_fingerprint_after": anchor_fingerprint_after,
        }
        if command.operation is CheckpointLifecycleCommandOperation.MIGRATION:
            summary["migration"] = {
                "active_key_id": str(getattr(result, "active_key_id", "")),
                "checkpoints_reencrypted": int(getattr(result, "checkpoints_reencrypted", 0)),
                "writes_reencrypted": int(getattr(result, "writes_reencrypted", 0)),
                "checkpoints_examined": int(getattr(result, "checkpoints_examined", 0)),
                "writes_examined": int(getattr(result, "writes_examined", 0)),
            }
        elif command.operation is CheckpointLifecycleCommandOperation.SNAPSHOT:
            summary["snapshot"] = {
                "checkpoint_digest": self._file_digest(Path(checkpoint_destination)),
                "anchor_digest": self._file_digest(Path(anchor_destination)),
            }
        else:
            summary["restore_input"] = {
                "checkpoint_digest": self._file_digest(Path(backup_database_path)),
                "anchor_digest": self._file_digest(Path(backup_anchor_path)),
            }
        return hashlib.sha256(self._canonical_json(summary)).hexdigest()

    def _receipt_payload(
        self,
        record: ProviderLifecycleRecord,
        *,
        anchor_fingerprint_after: str,
        result_digest: str,
    ) -> dict[str, object]:
        return {
            "policy_version": P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_POLICY_VERSION,
            "provider_id": self.provider_id,
            "command_id": record.command.command_id,
            "command_digest": record.command.digest(),
            "operation": record.command.operation.value,
            "fence_token": record.command.fence_token,
            "resource_id": record.command.resource_id,
            "expected_anchor_fingerprint": record.command.expected_anchor_fingerprint,
            "request_digest": record.request_digest,
            "anchor_fingerprint_after": anchor_fingerprint_after,
            "result_digest": result_digest,
        }

    def _commit_applied(
        self,
        record: ProviderLifecycleRecord,
        *,
        anchor_fingerprint_after: str,
        result_digest: str,
    ) -> ProviderLifecycleOutcomeReceipt:
        payload = self._receipt_payload(
            record,
            anchor_fingerprint_after=anchor_fingerprint_after,
            result_digest=result_digest,
        )
        receipt_tag = self._receipt_tag(payload)
        row_tag = self._row_tag(
            command=record.command,
            request_digest=record.request_digest,
            state=CheckpointProviderLifecycleState.APPLIED,
            anchor_fingerprint_after=anchor_fingerprint_after,
            result_digest=result_digest,
            receipt_tag=receipt_tag,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT * FROM provider_commands WHERE command_id = ?",
                (record.command.command_id,),
            ).fetchone()
            if current is None:
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID,
                    command_id=record.command.command_id,
                )
            current_record = self._record_from_row(current)
            if current_record.state is not CheckpointProviderLifecycleState.STARTED:
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.LEDGER_STATE_INVALID,
                    command_id=record.command.command_id,
                )
            connection.execute(
                """
                UPDATE provider_commands
                SET state = ?, anchor_fingerprint_after = ?, result_digest = ?,
                    receipt_tag = ?, integrity_tag = ?
                WHERE command_id = ?
                """,
                (
                    CheckpointProviderLifecycleState.APPLIED.value,
                    anchor_fingerprint_after,
                    result_digest,
                    receipt_tag,
                    row_tag,
                    record.command.command_id,
                ),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return ProviderLifecycleOutcomeReceipt(
            provider_id=self.provider_id,
            command_id=record.command.command_id,
            command_digest=record.command.digest(),
            operation=record.command.operation,
            fence_token=record.command.fence_token,
            resource_id=record.command.resource_id,
            expected_anchor_fingerprint=record.command.expected_anchor_fingerprint,
            request_digest=record.request_digest,
            anchor_fingerprint_after=anchor_fingerprint_after,
            result_digest=result_digest,
            receipt_tag=receipt_tag,
        )

    def _receipt_from_record(
        self,
        record: ProviderLifecycleRecord,
        *,
        replayed: bool,
    ) -> ProviderLifecycleOutcomeReceipt:
        if (
            record.state is not CheckpointProviderLifecycleState.APPLIED
            or record.anchor_fingerprint_after is None
            or record.result_digest is None
            or record.receipt_tag is None
        ):
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.OUTCOME_UNKNOWN,
                command_id=record.command.command_id,
            )
        receipt = ProviderLifecycleOutcomeReceipt(
            provider_id=self.provider_id,
            command_id=record.command.command_id,
            command_digest=record.command.digest(),
            operation=record.command.operation,
            fence_token=record.command.fence_token,
            resource_id=record.command.resource_id,
            expected_anchor_fingerprint=record.command.expected_anchor_fingerprint,
            request_digest=record.request_digest,
            anchor_fingerprint_after=record.anchor_fingerprint_after,
            result_digest=record.result_digest,
            receipt_tag=record.receipt_tag,
            replayed=replayed,
        )
        return self.verify_receipt(receipt, record.command)

    def verify_receipt(
        self,
        receipt: ProviderLifecycleOutcomeReceipt,
        command: CheckpointLifecycleCommand,
    ) -> ProviderLifecycleOutcomeReceipt:
        if (
            receipt.provider_id != self.provider_id
            or receipt.command_id != command.command_id
            or receipt.command_digest != command.digest()
            or receipt.operation is not command.operation
            or receipt.fence_token != command.fence_token
            or receipt.resource_id != command.resource_id
            or receipt.expected_anchor_fingerprint != command.expected_anchor_fingerprint
        ):
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.RECEIPT_COMMAND_MISMATCH,
                command_id=command.command_id,
            )
        expected = self._receipt_tag(receipt.signed_payload())
        if not hmac.compare_digest(receipt.receipt_tag, expected):
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.RECEIPT_INVALID,
                command_id=command.command_id,
            )
        return receipt

    def query_outcome(
        self,
        command: CheckpointLifecycleCommand,
    ) -> ProviderLifecycleOutcomeReceipt | None:
        self._verify_store()
        record = self._load_record(command.command_id)
        if record is None:
            return None
        if record.command.digest() != command.digest():
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.COMMAND_CONFLICT,
                command_id=command.command_id,
            )
        self.query_hits += 1
        if record.state is CheckpointProviderLifecycleState.APPLIED:
            return self._receipt_from_record(record, replayed=True)
        if record.state is CheckpointProviderLifecycleState.ACCEPTED:
            return None
        raise CheckpointProviderLifecycleError(
            CheckpointProviderLifecycleReason.OUTCOME_UNKNOWN,
            command_id=command.command_id,
        )

    def _invoke_delegate(
        self,
        command: CheckpointLifecycleCommand,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        checkpoint_destination: Path | None,
        anchor_destination: Path | None,
        backup_database_path: Path | None,
        backup_anchor_path: Path | None,
    ) -> object:
        self.side_effect_invocations += 1
        if command.operation is CheckpointLifecycleCommandOperation.MIGRATION:
            return self._delegate.migrate_to_active_encryption_key(saver)
        if command.operation is CheckpointLifecycleCommandOperation.SNAPSHOT:
            return self._delegate.snapshot_pair(
                saver,
                checkpoint_destination=Path(checkpoint_destination),
                anchor_destination=Path(anchor_destination),
            )
        if command.operation is CheckpointLifecycleCommandOperation.RESTORE:
            return self._delegate.restore_pair(
                saver,
                backup_database_path=Path(backup_database_path),
                backup_anchor_path=Path(backup_anchor_path),
            )
        raise CheckpointProviderLifecycleError(
            CheckpointProviderLifecycleReason.OPERATION_ARGUMENTS_INVALID,
            command_id=command.command_id,
        )

    def execute_command(
        self,
        command: CheckpointLifecycleCommand,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        checkpoint_destination: Path | None = None,
        anchor_destination: Path | None = None,
        backup_database_path: Path | None = None,
        backup_anchor_path: Path | None = None,
    ) -> ProviderLifecycleOutcomeReceipt:
        self._verify_store()
        self._validate_arguments(
            command,
            checkpoint_destination=checkpoint_destination,
            anchor_destination=anchor_destination,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
        )
        require_lifecycle_capability(self, command.operation.capability)
        request_digest = self._request_digest(
            command,
            checkpoint_destination=checkpoint_destination,
            anchor_destination=anchor_destination,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
        )
        record = self._load_record(command.command_id)
        if record is not None:
            if (
                record.command.digest() != command.digest()
                or record.request_digest != request_digest
            ):
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.COMMAND_CONFLICT,
                    command_id=command.command_id,
                )
            if record.state is CheckpointProviderLifecycleState.APPLIED:
                self.replay_hits += 1
                return self._receipt_from_record(record, replayed=True)
            if record.state is CheckpointProviderLifecycleState.STARTED:
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.OUTCOME_UNKNOWN,
                    command_id=command.command_id,
                )
            if self._anchor_fingerprint() != command.expected_anchor_fingerprint:
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.ANCHOR_PRECONDITION_FAILED,
                    command_id=command.command_id,
                )
        else:
            if self._anchor_fingerprint() != command.expected_anchor_fingerprint:
                raise CheckpointProviderLifecycleError(
                    CheckpointProviderLifecycleReason.ANCHOR_PRECONDITION_FAILED,
                    command_id=command.command_id,
                )
            record = self._insert_accepted(command, request_digest=request_digest)

        fault = self._consume_fault()
        if fault is CheckpointProviderLifecycleFaultMode.AFTER_ACCEPTED_BEFORE_SIDE_EFFECT:
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.SYNTHETIC_CRASH,
                command_id=command.command_id,
                fault_mode=fault,
            )

        record = self._set_state(record, CheckpointProviderLifecycleState.STARTED)
        try:
            result = self._invoke_delegate(
                command,
                saver,
                checkpoint_destination=checkpoint_destination,
                anchor_destination=anchor_destination,
                backup_database_path=backup_database_path,
                backup_anchor_path=backup_anchor_path,
            )
        except BaseException as exc:
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.OUTCOME_UNKNOWN,
                command_id=command.command_id,
            ) from exc

        anchor_after = self._anchor_fingerprint()
        result_digest = self._result_digest(
            command,
            result,
            checkpoint_destination=checkpoint_destination,
            anchor_destination=anchor_destination,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
            anchor_fingerprint_after=anchor_after,
        )
        if fault is CheckpointProviderLifecycleFaultMode.AFTER_SIDE_EFFECT_BEFORE_APPLIED:
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.SYNTHETIC_CRASH,
                command_id=command.command_id,
                fault_mode=fault,
            )

        receipt = self._commit_applied(
            record,
            anchor_fingerprint_after=anchor_after,
            result_digest=result_digest,
        )
        if fault is CheckpointProviderLifecycleFaultMode.AFTER_APPLIED_BEFORE_RESPONSE:
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.SYNTHETIC_CRASH,
                command_id=command.command_id,
                fault_mode=fault,
            )
        return receipt

    # Plain P4-I calls intentionally fail closed: P4-O requires a command-bound
    # provider request so the ledger can enforce identity and idempotency.
    def migrate_to_active_encryption_key(self, saver: KeyLifecycleConfidentialCheckpointer):
        raise CheckpointProviderLifecycleError(
            CheckpointProviderLifecycleReason.COMMAND_CONTEXT_REQUIRED
        )

    def snapshot_pair(self, saver: KeyLifecycleConfidentialCheckpointer, **_: object) -> None:
        raise CheckpointProviderLifecycleError(
            CheckpointProviderLifecycleReason.COMMAND_CONTEXT_REQUIRED
        )

    def restore_pair(self, saver: KeyLifecycleConfidentialCheckpointer, **_: object) -> None:
        raise CheckpointProviderLifecycleError(
            CheckpointProviderLifecycleReason.COMMAND_CONTEXT_REQUIRED
        )

    @property
    def highest_accepted_fence(self) -> int:
        connection = self._connect()
        try:
            return int(self._read_meta(connection)["highest_accepted_fence"])
        finally:
            connection.close()

    def public_posture(self) -> dict[str, object]:
        self._verify_store()
        return {
            "provider_id": self.provider_id,
            "wrapped_provider_id": self.wrapped_provider_id,
            "anchor_provider_id": self.anchor_provider_id,
            "policy_version": P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_POLICY_VERSION,
            "capabilities": sorted(capability.value for capability in self.capabilities),
            "provider_owned_durable_idempotency_ledger": True,
            "provider_outcome_receipt_authenticated": True,
            "synthetic_in_process": self.synthetic_in_process,
            "independent_failure_domain": self.independent_failure_domain,
            "operationally_external": self.operationally_external,
            "production_runtime_eligible": self.production_runtime_eligible,
            "exactly_once_execution": self.exactly_once_execution,
            "distributed_transaction": self.distributed_transaction,
            "network_operations": self.network_operations,
            "highest_accepted_fence": self.highest_accepted_fence,
            "side_effect_invocations": self.side_effect_invocations,
            "replay_hits": self.replay_hits,
            "query_hits": self.query_hits,
            "production_checkpoint_lifecycle_claim": False,
        }


class ProviderOutcomeAwareDurableCheckpointLifecycleCoordinator(
    DurableSyntheticCheckpointLifecycleCoordinator
):
    """P4-M local journal that reconciles from a provider-owned P4-O receipt."""

    provider_outcome_receipt_reconciliation = True
    exactly_once_execution = False
    distributed_transaction = False
    production_runtime_eligible = False

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
        execute_command = getattr(self._provider, "execute_command", None)
        if not callable(execute_command):
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.COMMAND_CONTEXT_REQUIRED,
                command_id=command.command_id,
            )
        self.provider_invocations += 1
        execute_command(
            command,
            saver,
            checkpoint_destination=checkpoint_destination,
            anchor_destination=anchor_destination,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
        )

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
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.OUTCOME_UNKNOWN,
                command_id=command.command_id,
            )

        query_outcome = getattr(self._provider, "query_outcome", None)
        verify_receipt = getattr(self._provider, "verify_receipt", None)
        if not callable(query_outcome) or not callable(verify_receipt):
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.OUTCOME_UNKNOWN,
                command_id=command.command_id,
            )
        provider_receipt = query_outcome(command)
        if provider_receipt is None:
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.OUTCOME_UNKNOWN,
                command_id=command.command_id,
            )
        provider_receipt = verify_receipt(provider_receipt, command)
        if self.anchor_fingerprint() != provider_receipt.anchor_fingerprint_after:
            raise CheckpointProviderLifecycleError(
                CheckpointProviderLifecycleReason.OUTCOME_MISMATCH,
                command_id=command.command_id,
            )
        receipt = self._commit_receipt(
            record,
            anchor_fingerprint_after=provider_receipt.anchor_fingerprint_after,
        )
        self.reconciliations += 1
        return replace(receipt, replayed=True)

    def public_posture(self) -> dict[str, object]:
        posture = super().public_posture()
        posture.update(
            {
                "provider_outcome_receipt_reconciliation": True,
                "provider_policy_version": P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_POLICY_VERSION,
                "exactly_once_execution": False,
                "distributed_transaction": False,
                "production_runtime_eligible": False,
                "production_checkpoint_lifecycle_claim": False,
            }
        )
        return posture
