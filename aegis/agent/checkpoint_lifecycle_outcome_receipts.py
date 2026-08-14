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
from aegis.agent.checkpoint_keys import CheckpointKeyMigrationReport
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
    DurableSyntheticCheckpointLifecycleCoordinator,
)


P4O_PROVIDER_OUTCOME_RECEIPT_POLICY_VERSION = "provider-owned-lifecycle-outcome-receipt-v1"
P4O_PROVIDER_OUTCOME_RECEIPT_SCHEMA_VERSION = "p4o-provider-outcome-receipt-schema-v1"


class ProviderLifecycleOutcomeReason(StrEnum):
    STORE_STATE_INVALID = "checkpoint_lifecycle_provider_outcome_store_invalid"
    RECEIPT_INTEGRITY_FAILED = "checkpoint_lifecycle_provider_outcome_integrity_failed"
    COMMAND_CONFLICT = "checkpoint_lifecycle_provider_outcome_command_conflict"
    RECEIPT_NOT_FOUND = "checkpoint_lifecycle_provider_outcome_receipt_not_found"
    PROVIDER_ID_MISMATCH = "checkpoint_lifecycle_provider_outcome_provider_id_mismatch"
    ANCHOR_PRECONDITION_MISMATCH = "checkpoint_lifecycle_provider_outcome_anchor_precondition_mismatch"
    ANCHOR_POSTCONDITION_MISMATCH = "checkpoint_lifecycle_provider_outcome_anchor_postcondition_mismatch"
    OPERATION_ARGUMENTS_INVALID = "checkpoint_lifecycle_provider_outcome_arguments_invalid"


class ProviderLifecycleOutcomeError(RuntimeError):
    def __init__(
        self,
        reason: ProviderLifecycleOutcomeReason,
        *,
        command_id: str | None = None,
    ) -> None:
        self.reason = reason
        self.command_id = command_id
        detail = reason.value
        if command_id is not None:
            detail = f"{detail}:{command_id}"
        super().__init__(detail)


@dataclass(frozen=True)
class ProviderLifecycleOutcomeReceipt:
    command_id: str
    operation: CheckpointLifecycleCommandOperation
    fence_token: int
    resource_id: str
    command_digest: str
    expected_anchor_fingerprint: str
    anchor_fingerprint_after: str
    provider_id: str
    replayed: bool = False

    def digest(self) -> str:
        return hashlib.sha256(
            json.dumps(
                {
                    "schema_version": P4O_PROVIDER_OUTCOME_RECEIPT_SCHEMA_VERSION,
                    "command_id": self.command_id,
                    "operation": self.operation.value,
                    "fence_token": self.fence_token,
                    "resource_id": self.resource_id,
                    "command_digest": self.command_digest,
                    "expected_anchor_fingerprint": self.expected_anchor_fingerprint,
                    "anchor_fingerprint_after": self.anchor_fingerprint_after,
                    "provider_id": self.provider_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()


class SyntheticProviderOutcomeReceiptStore:
    """Authenticated local synthetic provider-owned outcome ledger.

    The SQLite file and its HMAC key model storage owned by the lifecycle provider,
    not the caller-side P4-M journal. This is still a same-host lab boundary: it is
    rollbackable with its key and does not establish a remote trust domain.
    """

    def __init__(self, *, database_path: Path, integrity_key_path: Path | None = None) -> None:
        self.database_path = Path(database_path)
        self.integrity_key_path = (
            Path(integrity_key_path)
            if integrity_key_path is not None
            else self.database_path.with_suffix(self.database_path.suffix + ".hmac-key")
        )
        self._integrity_key = self._open_or_create()

    @staticmethod
    def _canonical(payload: dict[str, object]) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _tag(self, receipt: ProviderLifecycleOutcomeReceipt) -> str:
        return hmac.new(
            self._integrity_key,
            self._canonical(
                {
                    "schema_version": P4O_PROVIDER_OUTCOME_RECEIPT_SCHEMA_VERSION,
                    "receipt_digest": receipt.digest(),
                }
            ),
            hashlib.sha256,
        ).hexdigest()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _open_or_create(self) -> bytes:
        store_exists = self.database_path.exists()
        key_exists = self.integrity_key_path.exists()
        if store_exists != key_exists:
            raise ProviderLifecycleOutcomeError(ProviderLifecycleOutcomeReason.STORE_STATE_INVALID)
        if store_exists:
            try:
                key = self.integrity_key_path.read_bytes()
            except OSError as exc:
                raise ProviderLifecycleOutcomeError(
                    ProviderLifecycleOutcomeReason.STORE_STATE_INVALID
                ) from exc
            if len(key) != 32:
                raise ProviderLifecycleOutcomeError(
                    ProviderLifecycleOutcomeReason.STORE_STATE_INVALID
                )
            self._verify_all(key)
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
                CREATE TABLE provider_outcome_receipts (
                    command_id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    fence_token INTEGER NOT NULL CHECK (fence_token >= 1),
                    resource_id TEXT NOT NULL,
                    command_digest TEXT NOT NULL,
                    expected_anchor_fingerprint TEXT NOT NULL,
                    anchor_fingerprint_after TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    receipt_digest TEXT NOT NULL,
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

    @staticmethod
    def _row_to_receipt(row: sqlite3.Row) -> ProviderLifecycleOutcomeReceipt:
        try:
            return ProviderLifecycleOutcomeReceipt(
                command_id=str(row["command_id"]),
                operation=CheckpointLifecycleCommandOperation(str(row["operation"])),
                fence_token=int(row["fence_token"]),
                resource_id=str(row["resource_id"]),
                command_digest=str(row["command_digest"]),
                expected_anchor_fingerprint=str(row["expected_anchor_fingerprint"]),
                anchor_fingerprint_after=str(row["anchor_fingerprint_after"]),
                provider_id=str(row["provider_id"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.STORE_STATE_INVALID
            ) from exc

    def _verify_row_with_key(self, row: sqlite3.Row, key: bytes) -> ProviderLifecycleOutcomeReceipt:
        receipt = self._row_to_receipt(row)
        if str(row["receipt_digest"]) != receipt.digest():
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.RECEIPT_INTEGRITY_FAILED,
                command_id=receipt.command_id,
            )
        expected = hmac.new(
            key,
            self._canonical(
                {
                    "schema_version": P4O_PROVIDER_OUTCOME_RECEIPT_SCHEMA_VERSION,
                    "receipt_digest": receipt.digest(),
                }
            ),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(str(row["integrity_tag"]), expected):
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.RECEIPT_INTEGRITY_FAILED,
                command_id=receipt.command_id,
            )
        return receipt

    def _verify_all(self, key: bytes) -> None:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        try:
            rows = connection.execute(
                "SELECT * FROM provider_outcome_receipts ORDER BY command_id"
            ).fetchall()
            for row in rows:
                self._verify_row_with_key(row, key)
        except sqlite3.DatabaseError as exc:
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.STORE_STATE_INVALID
            ) from exc
        finally:
            connection.close()

    def get(self, command: CheckpointLifecycleCommand) -> ProviderLifecycleOutcomeReceipt | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM provider_outcome_receipts WHERE command_id = ?",
                (command.command_id,),
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.STORE_STATE_INVALID,
                command_id=command.command_id,
            ) from exc
        finally:
            connection.close()
        if row is None:
            return None
        receipt = self._verify_row_with_key(row, self._integrity_key)
        if receipt.command_digest != command.digest():
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.COMMAND_CONFLICT,
                command_id=command.command_id,
            )
        return receipt

    def require(self, command: CheckpointLifecycleCommand) -> ProviderLifecycleOutcomeReceipt:
        receipt = self.get(command)
        if receipt is None:
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.RECEIPT_NOT_FOUND,
                command_id=command.command_id,
            )
        return receipt

    def put(self, receipt: ProviderLifecycleOutcomeReceipt) -> ProviderLifecycleOutcomeReceipt:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM provider_outcome_receipts WHERE command_id = ?",
                (receipt.command_id,),
            ).fetchone()
            if row is not None:
                existing = self._verify_row_with_key(row, self._integrity_key)
                if existing.command_digest != receipt.command_digest:
                    raise ProviderLifecycleOutcomeError(
                        ProviderLifecycleOutcomeReason.COMMAND_CONFLICT,
                        command_id=receipt.command_id,
                    )
                connection.commit()
                return replace(existing, replayed=True)
            connection.execute(
                """
                INSERT INTO provider_outcome_receipts (
                    command_id, operation, fence_token, resource_id, command_digest,
                    expected_anchor_fingerprint, anchor_fingerprint_after, provider_id,
                    receipt_digest, integrity_tag
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.command_id,
                    receipt.operation.value,
                    receipt.fence_token,
                    receipt.resource_id,
                    receipt.command_digest,
                    receipt.expected_anchor_fingerprint,
                    receipt.anchor_fingerprint_after,
                    receipt.provider_id,
                    receipt.digest(),
                    self._tag(receipt),
                ),
            )
            connection.commit()
            return receipt
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @property
    def receipt_count(self) -> int:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM provider_outcome_receipts"
            ).fetchone()
            return int(row["count"])
        finally:
            connection.close()


class SyntheticIdempotentOutcomeReceiptLifecycleProvider:
    """Command-aware synthetic lifecycle provider with provider-owned outcome receipts."""

    provider_id = "synthetic-provider-outcome-receipt-checkpoint-lifecycle"
    synthetic_in_process = True
    operationally_external = False
    production_runtime_eligible = False
    independent_failure_domain = False
    exactly_once_execution = False
    network_operations = 0

    def __init__(self, *, lifecycle_provider: Any, outcome_database_path: Path) -> None:
        if not str(getattr(lifecycle_provider, "provider_id", "")).strip():
            raise ValueError("inner lifecycle provider id must be non-empty")
        self._inner = lifecycle_provider
        self._anchor_provider = getattr(lifecycle_provider, "bound_anchor_provider", None)
        if self._anchor_provider is None:
            raise ValueError("inner lifecycle provider must expose its bound anchor")
        self.anchor_provider_id = str(getattr(lifecycle_provider, "anchor_provider_id", ""))
        self.capabilities = frozenset(getattr(lifecycle_provider, "capabilities", frozenset()))
        self.outcome_store = SyntheticProviderOutcomeReceiptStore(
            database_path=Path(outcome_database_path)
        )
        self.command_invocations = 0
        self.provider_replay_hits = 0

    @property
    def bound_anchor_provider(self) -> Any:
        return self._anchor_provider

    @property
    def inner_provider(self) -> Any:
        return self._inner

    def _export_anchor_state(
        self,
    ) -> tuple[tuple[dict[str, object], ...], tuple[dict[str, object], ...]]:
        export_heads = getattr(self._anchor_provider, "export_heads", None)
        export_write_heads = getattr(self._anchor_provider, "export_write_heads", None)
        if not callable(export_heads) or not callable(export_write_heads):
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.STORE_STATE_INVALID
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
        return hashlib.sha256(
            json.dumps(
                {
                    "checkpoint_heads": checkpoint_heads,
                    "write_heads": write_heads,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()

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
        existing = self.outcome_store.get(command)
        if existing is not None:
            self.provider_replay_hits += 1
            return replace(existing, replayed=True)
        self._validate_arguments(
            command,
            checkpoint_destination=checkpoint_destination,
            anchor_destination=anchor_destination,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
        )
        require_lifecycle_capability(self, command.operation.capability)
        if self.anchor_fingerprint() != command.expected_anchor_fingerprint:
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.ANCHOR_PRECONDITION_MISMATCH,
                command_id=command.command_id,
            )

        self.command_invocations += 1
        if command.operation is CheckpointLifecycleCommandOperation.MIGRATION:
            self._inner.migrate_to_active_encryption_key(saver)
        elif command.operation is CheckpointLifecycleCommandOperation.SNAPSHOT:
            self._inner.snapshot_pair(
                saver,
                checkpoint_destination=Path(checkpoint_destination),
                anchor_destination=Path(anchor_destination),
            )
        elif command.operation is CheckpointLifecycleCommandOperation.RESTORE:
            self._inner.restore_pair(
                saver,
                backup_database_path=Path(backup_database_path),
                backup_anchor_path=Path(backup_anchor_path),
            )
        else:
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.OPERATION_ARGUMENTS_INVALID,
                command_id=command.command_id,
            )

        receipt = ProviderLifecycleOutcomeReceipt(
            command_id=command.command_id,
            operation=command.operation,
            fence_token=command.fence_token,
            resource_id=command.resource_id,
            command_digest=command.digest(),
            expected_anchor_fingerprint=command.expected_anchor_fingerprint,
            anchor_fingerprint_after=self.anchor_fingerprint(),
            provider_id=self.provider_id,
        )
        return self.outcome_store.put(receipt)

    def get_lifecycle_outcome_receipt(
        self, command: CheckpointLifecycleCommand
    ) -> ProviderLifecycleOutcomeReceipt:
        return self.outcome_store.require(command)

    # Compatibility methods keep the P4-I operation-provider protocol intact. P4-O
    # idempotency applies only through execute_lifecycle_command, where command
    # identity is present.
    def migrate_to_active_encryption_key(
        self, saver: KeyLifecycleConfidentialCheckpointer
    ) -> CheckpointKeyMigrationReport:
        return self._inner.migrate_to_active_encryption_key(saver)

    def snapshot_pair(
        self,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        checkpoint_destination: Path,
        anchor_destination: Path,
    ) -> None:
        self._inner.snapshot_pair(
            saver,
            checkpoint_destination=checkpoint_destination,
            anchor_destination=anchor_destination,
        )

    def restore_pair(
        self,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        backup_database_path: Path,
        backup_anchor_path: Path,
    ) -> None:
        self._inner.restore_pair(
            saver,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
        )

    def public_posture(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "anchor_provider_id": self.anchor_provider_id,
            "policy_version": P4O_PROVIDER_OUTCOME_RECEIPT_POLICY_VERSION,
            "capabilities": sorted(capability.value for capability in self.capabilities),
            "synthetic_in_process": self.synthetic_in_process,
            "operationally_external": self.operationally_external,
            "production_runtime_eligible": self.production_runtime_eligible,
            "independent_failure_domain": self.independent_failure_domain,
            "exactly_once_execution": self.exactly_once_execution,
            "network_operations": self.network_operations,
            "provider_owned_outcome_receipts": True,
            "authenticated_outcome_receipts": True,
            "receipt_count": self.outcome_store.receipt_count,
            "command_invocations": self.command_invocations,
            "provider_replay_hits": self.provider_replay_hits,
        }


class ProviderOutcomeRecoveringLifecycleCoordinator(
    DurableSyntheticCheckpointLifecycleCoordinator
):
    """P4-M coordinator that resolves ambiguity from provider-owned receipts."""

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
        execute_command = getattr(self._provider, "execute_lifecycle_command", None)
        if not callable(execute_command):
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.STORE_STATE_INVALID,
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
            raise CheckpointLifecycleJournalError(
                CheckpointLifecycleJournalReason.RECONCILIATION_UNPROVABLE,
                command_id=command.command_id,
            )

        get_receipt = getattr(self._provider, "get_lifecycle_outcome_receipt", None)
        if not callable(get_receipt):
            raise ProviderLifecycleOutcomeError(
                ProviderLifecycleOutcomeReason.RECEIPT_NOT_FOUND,
                command_id=command.command_id,
            )
        provider_receipt = get_receipt(command)
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
