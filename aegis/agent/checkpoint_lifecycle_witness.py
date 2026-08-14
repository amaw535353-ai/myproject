from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TypeVar

from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_lifecycle_fencing import (
    CheckpointLifecycleCommand,
    CheckpointLifecycleCommandOperation,
    CheckpointLifecycleCommandReceipt,
)
from aegis.agent.checkpoint_lifecycle_journal import (
    CheckpointLifecycleJournalFaultMode,
    DurableSyntheticCheckpointLifecycleCoordinator,
)


P4N_LIFECYCLE_JOURNAL_WITNESS_POLICY_VERSION = (
    "independent-local-synthetic-lifecycle-journal-witness-v1"
)
P4N_LIFECYCLE_JOURNAL_WITNESS_SCHEMA_VERSION = (
    "p4n-lifecycle-journal-witness-schema-v1"
)


class CheckpointLifecycleJournalWitnessReason(str):
    WITNESS_STATE_INVALID = "checkpoint_lifecycle_journal_witness_state_invalid"
    WITNESS_INTEGRITY_FAILED = "checkpoint_lifecycle_journal_witness_integrity_failed"
    WITNESS_REQUIRED = "checkpoint_lifecycle_journal_witness_required"
    JOURNAL_ROLLBACK_DETECTED = "checkpoint_lifecycle_journal_rollback_detected"
    JOURNAL_WITNESS_DIVERGENCE = "checkpoint_lifecycle_journal_witness_divergence"
    PATH_NOT_INDEPENDENT = "checkpoint_lifecycle_journal_witness_path_not_independent"


class CheckpointLifecycleJournalWitnessError(RuntimeError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class LifecycleJournalObservation:
    journal_fingerprint: str
    highest_issued_fence: int
    highest_committed_fence: int
    receipt_count: int
    command_count: int
    reconciliation_required_count: int

    @property
    def empty(self) -> bool:
        return bool(
            self.highest_issued_fence == 0
            and self.highest_committed_fence == 0
            and self.receipt_count == 0
            and self.command_count == 0
            and self.reconciliation_required_count == 0
        )


@dataclass(frozen=True)
class LifecycleJournalWitnessRecord:
    witness_generation: int
    observation: LifecycleJournalObservation


def _canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def observe_p4m_lifecycle_journal(journal_path: Path) -> LifecycleJournalObservation:
    """Hash the authenticated P4-M journal's structural state deterministically.

    This function intentionally hashes structural journal fields only. P4-N never
    exports checkpoint payloads, encryption keys, or journal HMAC key bytes.
    The caller is responsible for P4-M integrity verification before trusting a
    newly observed state; the witnessed coordinator does that on every guarded
    operation.
    """

    connection = sqlite3.connect(Path(journal_path), timeout=5.0)
    connection.row_factory = sqlite3.Row
    try:
        meta = connection.execute(
            """
            SELECT schema_version, highest_issued_fence,
                   highest_committed_fence, integrity_tag
            FROM journal_meta
            WHERE singleton = 1
            """
        ).fetchone()
        if meta is None:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            )
        rows = connection.execute(
            """
            SELECT command_id, operation, fence_token,
                   expected_anchor_fingerprint, resource_id, command_digest,
                   state, pre_observation_json, anchor_fingerprint_after,
                   provider_id, integrity_tag
            FROM lifecycle_commands
            ORDER BY fence_token, command_id
            """
        ).fetchall()
    except sqlite3.DatabaseError as exc:
        raise CheckpointLifecycleJournalWitnessError(
            CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
        ) from exc
    finally:
        connection.close()

    commands = [
        {
            "command_id": str(row["command_id"]),
            "operation": str(row["operation"]),
            "fence_token": int(row["fence_token"]),
            "expected_anchor_fingerprint": str(row["expected_anchor_fingerprint"]),
            "resource_id": str(row["resource_id"]),
            "command_digest": str(row["command_digest"]),
            "state": str(row["state"]),
            "pre_observation_json": str(row["pre_observation_json"]),
            "anchor_fingerprint_after": (
                None
                if row["anchor_fingerprint_after"] is None
                else str(row["anchor_fingerprint_after"])
            ),
            "provider_id": str(row["provider_id"]),
            "integrity_tag": str(row["integrity_tag"]),
        }
        for row in rows
    ]
    payload = {
        "p4n_policy_version": P4N_LIFECYCLE_JOURNAL_WITNESS_POLICY_VERSION,
        "p4m_schema_version": str(meta["schema_version"]),
        "highest_issued_fence": int(meta["highest_issued_fence"]),
        "highest_committed_fence": int(meta["highest_committed_fence"]),
        "journal_meta_integrity_tag": str(meta["integrity_tag"]),
        "commands": commands,
    }
    return LifecycleJournalObservation(
        journal_fingerprint=hashlib.sha256(_canonical_json(payload)).hexdigest(),
        highest_issued_fence=int(meta["highest_issued_fence"]),
        highest_committed_fence=int(meta["highest_committed_fence"]),
        receipt_count=sum(1 for row in rows if str(row["state"]) == "committed"),
        command_count=len(rows),
        reconciliation_required_count=sum(
            1 for row in rows if str(row["state"]) == "reconciliation_required"
        ),
    )


class LocalSyntheticLifecycleJournalWitness:
    """Independent local witness for one P4-M journal observation.

    The witness uses a different SQLite file and a different local HMAC key from
    the P4-M journal. It detects rollback only while this witness state remains
    intact. It is not a remote witness, trusted monotonic hardware, or production
    rollback-resistant storage.
    """

    synthetic_local = True
    operationally_external = False
    production_runtime_eligible = False
    rollback_resistant_against_whole_host_restore = False
    network_operations = 0

    def __init__(self, *, witness_path: Path, integrity_key_path: Path) -> None:
        self.witness_path = Path(witness_path)
        self.integrity_key_path = Path(integrity_key_path)
        if self.witness_path.resolve() == self.integrity_key_path.resolve():
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.PATH_NOT_INDEPENDENT
            )
        witness_exists = self.witness_path.exists()
        key_exists = self.integrity_key_path.exists()
        if witness_exists != key_exists:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            )
        if not witness_exists:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_REQUIRED
            )
        try:
            self._integrity_key = self.integrity_key_path.read_bytes()
        except OSError as exc:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            ) from exc
        if len(self._integrity_key) != 32:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            )
        self.current()

    @classmethod
    def create(
        cls,
        *,
        witness_path: Path,
        integrity_key_path: Path,
        observation: LifecycleJournalObservation,
    ) -> LocalSyntheticLifecycleJournalWitness:
        witness_path = Path(witness_path)
        integrity_key_path = Path(integrity_key_path)
        if witness_path.resolve() == integrity_key_path.resolve():
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.PATH_NOT_INDEPENDENT
            )
        if witness_path.exists() or integrity_key_path.exists():
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            )
        witness_path.parent.mkdir(parents=True, exist_ok=True)
        integrity_key_path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        descriptor = os.open(
            integrity_key_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            os.write(descriptor, key)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

        connection = sqlite3.connect(witness_path, timeout=5.0)
        try:
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute(
                """
                CREATE TABLE journal_witness (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version TEXT NOT NULL,
                    witness_generation INTEGER NOT NULL CHECK (witness_generation >= 1),
                    highest_issued_fence INTEGER NOT NULL CHECK (highest_issued_fence >= 0),
                    highest_committed_fence INTEGER NOT NULL CHECK (highest_committed_fence >= 0),
                    receipt_count INTEGER NOT NULL CHECK (receipt_count >= 0),
                    command_count INTEGER NOT NULL CHECK (command_count >= 0),
                    reconciliation_required_count INTEGER NOT NULL CHECK (reconciliation_required_count >= 0),
                    journal_fingerprint TEXT NOT NULL,
                    integrity_tag TEXT NOT NULL
                )
                """
            )
            tag = cls._tag_for_key(
                key,
                witness_generation=1,
                observation=observation,
            )
            connection.execute(
                """
                INSERT INTO journal_witness (
                    singleton, schema_version, witness_generation,
                    highest_issued_fence, highest_committed_fence,
                    receipt_count, command_count, reconciliation_required_count,
                    journal_fingerprint, integrity_tag
                ) VALUES (1, ?, 1, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    P4N_LIFECYCLE_JOURNAL_WITNESS_SCHEMA_VERSION,
                    observation.highest_issued_fence,
                    observation.highest_committed_fence,
                    observation.receipt_count,
                    observation.command_count,
                    observation.reconciliation_required_count,
                    observation.journal_fingerprint,
                    tag,
                ),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            try:
                witness_path.unlink()
            except OSError:
                pass
            try:
                integrity_key_path.unlink()
            except OSError:
                pass
            raise
        finally:
            connection.close()
        return cls(
            witness_path=witness_path,
            integrity_key_path=integrity_key_path,
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.witness_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @staticmethod
    def _tag_for_key(
        key: bytes,
        *,
        witness_generation: int,
        observation: LifecycleJournalObservation,
    ) -> str:
        payload = {
            "policy_version": P4N_LIFECYCLE_JOURNAL_WITNESS_POLICY_VERSION,
            "schema_version": P4N_LIFECYCLE_JOURNAL_WITNESS_SCHEMA_VERSION,
            "witness_generation": int(witness_generation),
            "highest_issued_fence": observation.highest_issued_fence,
            "highest_committed_fence": observation.highest_committed_fence,
            "receipt_count": observation.receipt_count,
            "command_count": observation.command_count,
            "reconciliation_required_count": observation.reconciliation_required_count,
            "journal_fingerprint": observation.journal_fingerprint,
        }
        return hmac.new(key, _canonical_json(payload), hashlib.sha256).hexdigest()

    def _tag(
        self,
        *,
        witness_generation: int,
        observation: LifecycleJournalObservation,
    ) -> str:
        return self._tag_for_key(
            self._integrity_key,
            witness_generation=witness_generation,
            observation=observation,
        )

    def current(self) -> LifecycleJournalWitnessRecord:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT schema_version, witness_generation,
                       highest_issued_fence, highest_committed_fence,
                       receipt_count, command_count, reconciliation_required_count,
                       journal_fingerprint, integrity_tag
                FROM journal_witness
                WHERE singleton = 1
                """
            ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            ) from exc
        finally:
            connection.close()
        if row is None or str(row["schema_version"]) != P4N_LIFECYCLE_JOURNAL_WITNESS_SCHEMA_VERSION:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            )
        observation = LifecycleJournalObservation(
            journal_fingerprint=str(row["journal_fingerprint"]),
            highest_issued_fence=int(row["highest_issued_fence"]),
            highest_committed_fence=int(row["highest_committed_fence"]),
            receipt_count=int(row["receipt_count"]),
            command_count=int(row["command_count"]),
            reconciliation_required_count=int(row["reconciliation_required_count"]),
        )
        generation = int(row["witness_generation"])
        expected = self._tag(
            witness_generation=generation,
            observation=observation,
        )
        if not hmac.compare_digest(str(row["integrity_tag"]), expected):
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_INTEGRITY_FAILED
            )
        if (
            generation < 1
            or observation.highest_committed_fence > observation.highest_issued_fence
            or observation.receipt_count > observation.command_count
            or observation.reconciliation_required_count > observation.command_count
        ):
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            )
        return LifecycleJournalWitnessRecord(
            witness_generation=generation,
            observation=observation,
        )

    @staticmethod
    def _same(a: LifecycleJournalObservation, b: LifecycleJournalObservation) -> bool:
        return a == b

    def assert_matches(self, observation: LifecycleJournalObservation) -> None:
        record = self.current()
        expected = record.observation
        if self._same(expected, observation):
            return
        if (
            observation.highest_issued_fence < expected.highest_issued_fence
            or observation.highest_committed_fence < expected.highest_committed_fence
            or observation.receipt_count < expected.receipt_count
            or observation.command_count < expected.command_count
        ):
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.JOURNAL_ROLLBACK_DETECTED
            )
        raise CheckpointLifecycleJournalWitnessError(
            CheckpointLifecycleJournalWitnessReason.JOURNAL_WITNESS_DIVERGENCE
        )

    def advance_known_state(self, observation: LifecycleJournalObservation) -> LifecycleJournalWitnessRecord:
        current = self.current()
        if self._same(current.observation, observation):
            return current
        if (
            observation.highest_issued_fence < current.observation.highest_issued_fence
            or observation.highest_committed_fence < current.observation.highest_committed_fence
            or observation.receipt_count < current.observation.receipt_count
            or observation.command_count < current.observation.command_count
        ):
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.JOURNAL_ROLLBACK_DETECTED
            )
        generation = current.witness_generation + 1
        tag = self._tag(
            witness_generation=generation,
            observation=observation,
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            locked = connection.execute(
                "SELECT witness_generation FROM journal_witness WHERE singleton = 1"
            ).fetchone()
            if locked is None or int(locked["witness_generation"]) != current.witness_generation:
                raise CheckpointLifecycleJournalWitnessError(
                    CheckpointLifecycleJournalWitnessReason.JOURNAL_WITNESS_DIVERGENCE
                )
            connection.execute(
                """
                UPDATE journal_witness
                SET witness_generation = ?,
                    highest_issued_fence = ?,
                    highest_committed_fence = ?,
                    receipt_count = ?,
                    command_count = ?,
                    reconciliation_required_count = ?,
                    journal_fingerprint = ?,
                    integrity_tag = ?
                WHERE singleton = 1
                """,
                (
                    generation,
                    observation.highest_issued_fence,
                    observation.highest_committed_fence,
                    observation.receipt_count,
                    observation.command_count,
                    observation.reconciliation_required_count,
                    observation.journal_fingerprint,
                    tag,
                ),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return LifecycleJournalWitnessRecord(
            witness_generation=generation,
            observation=observation,
        )

    def public_posture(self) -> dict[str, object]:
        current = self.current()
        return {
            "policy_version": P4N_LIFECYCLE_JOURNAL_WITNESS_POLICY_VERSION,
            "synthetic_local": self.synthetic_local,
            "operationally_external": self.operationally_external,
            "production_runtime_eligible": self.production_runtime_eligible,
            "rollback_resistant_against_whole_host_restore": self.rollback_resistant_against_whole_host_restore,
            "network_operations": self.network_operations,
            "witness_generation": current.witness_generation,
            "highest_issued_fence": current.observation.highest_issued_fence,
            "highest_committed_fence": current.observation.highest_committed_fence,
            "receipt_count": current.observation.receipt_count,
            "command_count": current.observation.command_count,
        }


_T = TypeVar("_T")


class WitnessedDurableSyntheticCheckpointLifecycleCoordinator:
    """P4-M coordinator guarded by an independent local synthetic witness.

    The witness is checked before the P4-M coordinator is allowed to recover or
    execute. Known in-process P4-M state transitions are then re-witnessed. A
    stale journal that is individually HMAC-valid is rejected when it is older
    than the intact witness. Restoring the journal, journal key, witness, and
    witness key together remains outside this local detection guarantee.
    """

    synthetic_in_process = True
    independent_local_witness = True
    distributed_fencing = False
    whole_host_corollback_resistant = False
    exactly_once_execution = False
    operationally_external = False
    production_runtime_eligible = False
    network_operations = 0

    def __init__(
        self,
        *,
        lifecycle_provider: Any,
        journal_path: Path,
        witness_path: Path,
        journal_integrity_key_path: Path | None = None,
        witness_integrity_key_path: Path | None = None,
    ) -> None:
        self.journal_path = Path(journal_path)
        self.journal_integrity_key_path = (
            Path(journal_integrity_key_path)
            if journal_integrity_key_path is not None
            else self.journal_path.with_suffix(self.journal_path.suffix + ".hmac-key")
        )
        self.witness_path = Path(witness_path)
        self.witness_integrity_key_path = (
            Path(witness_integrity_key_path)
            if witness_integrity_key_path is not None
            else self.witness_path.with_suffix(self.witness_path.suffix + ".hmac-key")
        )
        resolved = {
            path.resolve()
            for path in (
                self.journal_path,
                self.journal_integrity_key_path,
                self.witness_path,
                self.witness_integrity_key_path,
            )
        }
        if len(resolved) != 4:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.PATH_NOT_INDEPENDENT
            )

        journal_exists = self.journal_path.exists()
        journal_key_exists = self.journal_integrity_key_path.exists()
        witness_exists = self.witness_path.exists()
        witness_key_exists = self.witness_integrity_key_path.exists()
        if journal_exists != journal_key_exists:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            )
        if witness_exists != witness_key_exists:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            )

        self._witness: LocalSyntheticLifecycleJournalWitness | None = None
        if witness_exists:
            self._witness = LocalSyntheticLifecycleJournalWitness(
                witness_path=self.witness_path,
                integrity_key_path=self.witness_integrity_key_path,
            )
            if not journal_exists:
                raise CheckpointLifecycleJournalWitnessError(
                    CheckpointLifecycleJournalWitnessReason.JOURNAL_ROLLBACK_DETECTED
                )
            # Check the exact pre-reopen state before P4-M is allowed to perform
            # its deterministic PROVIDER_STARTED -> RECONCILIATION_REQUIRED recovery.
            self._witness.assert_matches(observe_p4m_lifecycle_journal(self.journal_path))

        self._coordinator = DurableSyntheticCheckpointLifecycleCoordinator(
            lifecycle_provider=lifecycle_provider,
            journal_path=self.journal_path,
            integrity_key_path=self.journal_integrity_key_path,
        )
        post_open = self._validated_observation()

        if self._witness is None:
            if not post_open.empty:
                raise CheckpointLifecycleJournalWitnessError(
                    CheckpointLifecycleJournalWitnessReason.WITNESS_REQUIRED
                )
            self._witness = LocalSyntheticLifecycleJournalWitness.create(
                witness_path=self.witness_path,
                integrity_key_path=self.witness_integrity_key_path,
                observation=post_open,
            )
        else:
            # P4-M may have performed the single documented recovery transition
            # during construction, after the pre-open state matched the witness.
            self._witness.advance_known_state(post_open)

    @property
    def witness(self) -> LocalSyntheticLifecycleJournalWitness:
        assert self._witness is not None
        return self._witness

    @property
    def inner(self) -> DurableSyntheticCheckpointLifecycleCoordinator:
        return self._coordinator

    def _validated_observation(self) -> LifecycleJournalObservation:
        # P4-N is intentionally coupled to the P4-M v1 journal schema. Re-run
        # P4-M's authenticated store verification before trusting an observation.
        self._coordinator._verify_store()
        return observe_p4m_lifecycle_journal(self.journal_path)

    def _guard(self) -> None:
        self.witness.assert_matches(self._validated_observation())

    def _synchronize_known_mutation(self) -> None:
        self.witness.advance_known_state(self._validated_observation())

    def _call_guarded(self, operation: Callable[[], _T]) -> _T:
        self._guard()
        try:
            result = operation()
        except BaseException:
            try:
                self._synchronize_known_mutation()
            except BaseException:
                # Preserve the original P4-M failure reason if the store itself
                # became unverifiable. The next guarded operation/reopen will
                # still fail closed because the witness was not advanced.
                pass
            raise
        self._synchronize_known_mutation()
        return result

    def arm_fault(self, mode: CheckpointLifecycleJournalFaultMode) -> None:
        self._coordinator.arm_fault(mode)

    def issue_command(
        self,
        *,
        command_id: str,
        operation: CheckpointLifecycleCommandOperation,
        resource_id: str,
        saver: KeyLifecycleConfidentialCheckpointer,
    ) -> CheckpointLifecycleCommand:
        return self._call_guarded(
            lambda: self._coordinator.issue_command(
                command_id=command_id,
                operation=operation,
                resource_id=resource_id,
                saver=saver,
            )
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
        return self._call_guarded(
            lambda: self._coordinator.execute(
                command,
                saver,
                checkpoint_destination=checkpoint_destination,
                anchor_destination=anchor_destination,
                backup_database_path=backup_database_path,
                backup_anchor_path=backup_anchor_path,
            )
        )

    def reconcile(
        self,
        command: CheckpointLifecycleCommand,
        saver: KeyLifecycleConfidentialCheckpointer,
    ) -> CheckpointLifecycleCommandReceipt:
        return self._call_guarded(
            lambda: self._coordinator.reconcile(command, saver)
        )

    @property
    def highest_issued_fence(self) -> int:
        self._guard()
        return self._coordinator.highest_issued_fence

    @property
    def highest_committed_fence(self) -> int:
        self._guard()
        return self._coordinator.highest_committed_fence

    @property
    def receipt_count(self) -> int:
        self._guard()
        return self._coordinator.receipt_count

    @property
    def witness_generation(self) -> int:
        return self.witness.current().witness_generation

    @property
    def provider_invocations(self) -> int:
        return self._coordinator.provider_invocations

    @property
    def replay_hits(self) -> int:
        return self._coordinator.replay_hits

    @property
    def reconciliations(self) -> int:
        return self._coordinator.reconciliations

    def public_posture(self) -> dict[str, object]:
        self._guard()
        return {
            "provider_id": self._coordinator.provider_id,
            "policy_version": P4N_LIFECYCLE_JOURNAL_WITNESS_POLICY_VERSION,
            "synthetic_in_process": self.synthetic_in_process,
            "independent_local_witness": self.independent_local_witness,
            "distributed_fencing": self.distributed_fencing,
            "whole_host_corollback_resistant": self.whole_host_corollback_resistant,
            "exactly_once_execution": self.exactly_once_execution,
            "operationally_external": self.operationally_external,
            "production_runtime_eligible": self.production_runtime_eligible,
            "network_operations": self.network_operations,
            "highest_issued_fence": self._coordinator.highest_issued_fence,
            "highest_committed_fence": self._coordinator.highest_committed_fence,
            "receipt_count": self._coordinator.receipt_count,
            "witness_generation": self.witness_generation,
            "journal_and_witness_paths_distinct": True,
            "journal_and_witness_integrity_keys_distinct": True,
        }
