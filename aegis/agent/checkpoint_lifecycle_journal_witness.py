from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_lifecycle_fencing import (
    CheckpointLifecycleCommand,
    CheckpointLifecycleCommandOperation,
    CheckpointLifecycleCommandReceipt,
)
from aegis.agent.checkpoint_lifecycle_journal import (
    P4M_DURABLE_LIFECYCLE_JOURNAL_POLICY_VERSION,
    P4M_DURABLE_LIFECYCLE_JOURNAL_SCHEMA_VERSION,
    CheckpointLifecycleJournalFaultMode,
    CheckpointLifecycleJournalState,
    DurableSyntheticCheckpointLifecycleCoordinator,
)


P4N_LIFECYCLE_JOURNAL_WITNESS_POLICY_VERSION = (
    "independent-local-synthetic-lifecycle-journal-witness-v1"
)
P4N_LIFECYCLE_JOURNAL_WITNESS_SCHEMA_VERSION = "p4n-lifecycle-journal-witness-schema-v1"


class CheckpointLifecycleJournalWitnessFaultMode(StrEnum):
    NONE = "none"
    AFTER_JOURNAL_BEFORE_WITNESS = "after_journal_before_witness"


class CheckpointLifecycleJournalWitnessReason(StrEnum):
    WITNESS_INTEGRITY_FAILED = "checkpoint_lifecycle_journal_witness_integrity_failed"
    WITNESS_STATE_INVALID = "checkpoint_lifecycle_journal_witness_state_invalid"
    WITNESS_MISSING_FOR_EXISTING_JOURNAL = (
        "checkpoint_lifecycle_journal_witness_missing_for_existing_journal"
    )
    JOURNAL_ROLLBACK_DETECTED = "checkpoint_lifecycle_journal_rollback_detected"
    JOURNAL_WITNESS_DIVERGENCE = "checkpoint_lifecycle_journal_witness_divergence"
    SYNTHETIC_CRASH = "checkpoint_lifecycle_journal_witness_synthetic_crash"


class CheckpointLifecycleJournalWitnessError(RuntimeError):
    def __init__(
        self,
        reason: CheckpointLifecycleJournalWitnessReason,
        *,
        fault_mode: CheckpointLifecycleJournalWitnessFaultMode | None = None,
    ) -> None:
        self.reason = reason
        self.fault_mode = fault_mode
        detail = reason.value
        if fault_mode is not None:
            detail = f"{detail}:{fault_mode.value}"
        super().__init__(detail)


@dataclass(frozen=True)
class LifecycleJournalCommandSummary:
    fence_token: int
    command_digest: str
    stable_identity_digest: str
    state: str
    anchor_fingerprint_after: str | None


@dataclass(frozen=True)
class LifecycleJournalAttestation:
    highest_issued_fence: int
    highest_committed_fence: int
    command_count: int
    committed_count: int
    journal_state_digest: str
    commands: tuple[LifecycleJournalCommandSummary, ...]


@dataclass(frozen=True)
class LifecycleJournalWitnessRecord:
    witness_generation: int
    attestation: LifecycleJournalAttestation


_STATE_RANK = {
    CheckpointLifecycleJournalState.PREPARED.value: 0,
    CheckpointLifecycleJournalState.PROVIDER_STARTED.value: 1,
    CheckpointLifecycleJournalState.RECONCILIATION_REQUIRED.value: 2,
    CheckpointLifecycleJournalState.COMMITTED.value: 3,
}


class WitnessedDurableSyntheticCheckpointLifecycleCoordinator:
    """P4-M coordinator guarded by a separate local synthetic rollback witness.

    The witness is stored separately from the P4-M journal and authenticated by
    separate local HMAC material. It detects a journal rollback, same-fence state
    regression, or alternate authenticated journal history while the witness
    remains newer. A current journal that is *provably* monotonic-forward from a
    stale witness can advance the witness after reopen, covering a crash between a
    durable journal mutation and the witness write.

    Both artifacts still live on the same host. Rolling back the journal, journal
    HMAC key, witness, and witness HMAC key together is outside this boundary and
    is intentionally not described as production rollback resistance.
    """

    synthetic_in_process = True
    durable_local_witness = True
    independent_local_artifact = True
    independent_failure_domain = False
    rollback_resistant_journal = False
    distributed_fencing = False
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
        self.witness_path = Path(witness_path)
        self.witness_integrity_key_path = (
            Path(witness_integrity_key_path)
            if witness_integrity_key_path is not None
            else self.witness_path.with_suffix(self.witness_path.suffix + ".hmac-key")
        )
        self._fault_mode = CheckpointLifecycleJournalWitnessFaultMode.NONE
        self.witness_forward_advances = 0
        self.rollback_rejections = 0
        self.journal = DurableSyntheticCheckpointLifecycleCoordinator(
            lifecycle_provider=lifecycle_provider,
            journal_path=self.journal_path,
            integrity_key_path=journal_integrity_key_path,
        )
        self._witness_key = self._open_or_create_witness()
        self._verify_or_advance_witness()

    @property
    def provider_id(self) -> str:
        return self.journal.provider_id

    def arm_fault(self, mode: CheckpointLifecycleJournalWitnessFaultMode) -> None:
        self._fault_mode = CheckpointLifecycleJournalWitnessFaultMode(mode)

    def arm_journal_fault(self, mode: CheckpointLifecycleJournalFaultMode) -> None:
        self.journal.arm_fault(mode)

    def _consume_fault(self) -> CheckpointLifecycleJournalWitnessFaultMode:
        mode = self._fault_mode
        self._fault_mode = CheckpointLifecycleJournalWitnessFaultMode.NONE
        return mode

    @staticmethod
    def _canonical_json(payload: object) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _state_rank(state: str) -> int:
        try:
            return _STATE_RANK[state]
        except KeyError as exc:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            ) from exc

    @classmethod
    def _stable_identity_digest(cls, record: Any) -> str:
        pre_observation_digest = hashlib.sha256(
            cls._canonical_json(record.pre_observation)
        ).hexdigest()
        payload = {
            "command_id": record.command.command_id,
            "command_digest": record.command.digest(),
            "operation": record.command.operation.value,
            "fence_token": record.command.fence_token,
            "expected_anchor_fingerprint": record.command.expected_anchor_fingerprint,
            "resource_id": record.command.resource_id,
            "provider_id": record.provider_id,
            "pre_observation_digest": pre_observation_digest,
        }
        return hashlib.sha256(cls._canonical_json(payload)).hexdigest()

    def _journal_attestation(self) -> LifecycleJournalAttestation:
        # P4-M remains the source of truth for journal authentication. P4-N uses
        # P4-M's authenticated row readers and then independently attests only
        # structural digests and monotonic lifecycle state.
        self.journal._verify_store()
        connection = self.journal._connect()
        try:
            meta = self.journal._read_meta(connection)
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
            records = [self.journal._row_to_record(row) for row in rows]
        except sqlite3.DatabaseError as exc:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            ) from exc
        finally:
            connection.close()

        commands: list[LifecycleJournalCommandSummary] = []
        digest_rows: list[dict[str, object]] = []
        committed_count = 0
        for record in records:
            state = record.state.value
            self._state_rank(state)
            if record.state is CheckpointLifecycleJournalState.COMMITTED:
                committed_count += 1
            stable_identity_digest = self._stable_identity_digest(record)
            summary = LifecycleJournalCommandSummary(
                fence_token=record.command.fence_token,
                command_digest=record.command.digest(),
                stable_identity_digest=stable_identity_digest,
                state=state,
                anchor_fingerprint_after=record.anchor_fingerprint_after,
            )
            commands.append(summary)
            digest_rows.append(
                {
                    "fence_token": summary.fence_token,
                    "command_digest": summary.command_digest,
                    "stable_identity_digest": summary.stable_identity_digest,
                    "state": summary.state,
                    "anchor_fingerprint_after": summary.anchor_fingerprint_after,
                }
            )

        issued = int(meta["highest_issued_fence"])
        committed = int(meta["highest_committed_fence"])
        digest_payload = {
            "p4m_policy_version": P4M_DURABLE_LIFECYCLE_JOURNAL_POLICY_VERSION,
            "p4m_schema_version": P4M_DURABLE_LIFECYCLE_JOURNAL_SCHEMA_VERSION,
            "provider_id": self.provider_id,
            "highest_issued_fence": issued,
            "highest_committed_fence": committed,
            "commands": digest_rows,
        }
        return LifecycleJournalAttestation(
            highest_issued_fence=issued,
            highest_committed_fence=committed,
            command_count=len(commands),
            committed_count=committed_count,
            journal_state_digest=hashlib.sha256(self._canonical_json(digest_payload)).hexdigest(),
            commands=tuple(commands),
        )

    @staticmethod
    def _attestation_payload(attestation: LifecycleJournalAttestation) -> dict[str, object]:
        return {
            "highest_issued_fence": attestation.highest_issued_fence,
            "highest_committed_fence": attestation.highest_committed_fence,
            "command_count": attestation.command_count,
            "committed_count": attestation.committed_count,
            "journal_state_digest": attestation.journal_state_digest,
            "commands": [
                {
                    "fence_token": item.fence_token,
                    "command_digest": item.command_digest,
                    "stable_identity_digest": item.stable_identity_digest,
                    "state": item.state,
                    "anchor_fingerprint_after": item.anchor_fingerprint_after,
                }
                for item in attestation.commands
            ],
        }

    def _witness_tag(self, payload_without_tag: dict[str, object]) -> str:
        return hmac.new(
            self._witness_key,
            self._canonical_json(payload_without_tag),
            hashlib.sha256,
        ).hexdigest()

    def _open_or_create_witness(self) -> bytes:
        witness_exists = self.witness_path.exists()
        key_exists = self.witness_integrity_key_path.exists()
        if witness_exists != key_exists:
            if self.journal.highest_issued_fence > 0:
                raise CheckpointLifecycleJournalWitnessError(
                    CheckpointLifecycleJournalWitnessReason.WITNESS_MISSING_FOR_EXISTING_JOURNAL
                )
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            )
        if witness_exists:
            try:
                key = self.witness_integrity_key_path.read_bytes()
            except OSError as exc:
                raise CheckpointLifecycleJournalWitnessError(
                    CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
                ) from exc
            if len(key) != 32:
                raise CheckpointLifecycleJournalWitnessError(
                    CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
                )
            return key

        if self.journal.highest_issued_fence > 0:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_MISSING_FOR_EXISTING_JOURNAL
            )
        self.witness_path.parent.mkdir(parents=True, exist_ok=True)
        self.witness_integrity_key_path.parent.mkdir(parents=True, exist_ok=True)
        key = secrets.token_bytes(32)
        descriptor = os.open(
            self.witness_integrity_key_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            os.write(descriptor, key)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._witness_key = key
        self._write_witness(
            LifecycleJournalWitnessRecord(
                witness_generation=0,
                attestation=self._journal_attestation(),
            )
        )
        return key

    def _write_witness(self, record: LifecycleJournalWitnessRecord) -> None:
        payload: dict[str, object] = {
            "schema_version": P4N_LIFECYCLE_JOURNAL_WITNESS_SCHEMA_VERSION,
            "policy_version": P4N_LIFECYCLE_JOURNAL_WITNESS_POLICY_VERSION,
            "witness_generation": record.witness_generation,
            "attestation": self._attestation_payload(record.attestation),
        }
        payload["integrity_tag"] = self._witness_tag(payload)
        temporary = self.witness_path.with_suffix(self.witness_path.suffix + ".tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            os.write(descriptor, self._canonical_json(payload))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.witness_path)
        try:
            directory_descriptor = os.open(self.witness_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError:
            pass

    def _read_witness(self) -> LifecycleJournalWitnessRecord:
        try:
            payload = json.loads(self.witness_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            ) from exc
        if not isinstance(payload, dict):
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            )
        supplied_tag = payload.pop("integrity_tag", None)
        if not isinstance(supplied_tag, str) or not hmac.compare_digest(
            supplied_tag, self._witness_tag(payload)
        ):
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_INTEGRITY_FAILED
            )
        try:
            if (
                payload["schema_version"] != P4N_LIFECYCLE_JOURNAL_WITNESS_SCHEMA_VERSION
                or payload["policy_version"] != P4N_LIFECYCLE_JOURNAL_WITNESS_POLICY_VERSION
            ):
                raise ValueError("witness version mismatch")
            generation = int(payload["witness_generation"])
            raw_attestation = payload["attestation"]
            if not isinstance(raw_attestation, dict):
                raise ValueError("attestation is not an object")
            raw_commands = raw_attestation["commands"]
            if not isinstance(raw_commands, list):
                raise ValueError("commands is not a list")
            commands = tuple(
                LifecycleJournalCommandSummary(
                    fence_token=int(item["fence_token"]),
                    command_digest=str(item["command_digest"]),
                    stable_identity_digest=str(item["stable_identity_digest"]),
                    state=str(item["state"]),
                    anchor_fingerprint_after=(
                        None
                        if item.get("anchor_fingerprint_after") is None
                        else str(item["anchor_fingerprint_after"])
                    ),
                )
                for item in raw_commands
            )
            if generation < 0 or any(item.state not in _STATE_RANK for item in commands):
                raise ValueError("invalid witness generation or command state")
            attestation = LifecycleJournalAttestation(
                highest_issued_fence=int(raw_attestation["highest_issued_fence"]),
                highest_committed_fence=int(raw_attestation["highest_committed_fence"]),
                command_count=int(raw_attestation["command_count"]),
                committed_count=int(raw_attestation["committed_count"]),
                journal_state_digest=str(raw_attestation["journal_state_digest"]),
                commands=commands,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            ) from exc
        if (
            attestation.command_count != len(attestation.commands)
            or attestation.highest_committed_fence > attestation.highest_issued_fence
        ):
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.WITNESS_STATE_INVALID
            )
        return LifecycleJournalWitnessRecord(
            witness_generation=generation,
            attestation=attestation,
        )

    def _classify_current_against_witness(
        self,
        witnessed: LifecycleJournalAttestation,
        current: LifecycleJournalAttestation,
    ) -> CheckpointLifecycleJournalWitnessReason | None:
        if (
            current.highest_issued_fence < witnessed.highest_issued_fence
            or current.highest_committed_fence < witnessed.highest_committed_fence
            or current.command_count < witnessed.command_count
            or current.committed_count < witnessed.committed_count
        ):
            return CheckpointLifecycleJournalWitnessReason.JOURNAL_ROLLBACK_DETECTED

        current_by_fence = {item.fence_token: item for item in current.commands}
        strict_progress = bool(
            current.highest_issued_fence > witnessed.highest_issued_fence
            or current.highest_committed_fence > witnessed.highest_committed_fence
            or current.command_count > witnessed.command_count
            or current.committed_count > witnessed.committed_count
        )
        for previous in witnessed.commands:
            now = current_by_fence.get(previous.fence_token)
            if now is None:
                return CheckpointLifecycleJournalWitnessReason.JOURNAL_ROLLBACK_DETECTED
            if (
                now.command_digest != previous.command_digest
                or now.stable_identity_digest != previous.stable_identity_digest
            ):
                return CheckpointLifecycleJournalWitnessReason.JOURNAL_WITNESS_DIVERGENCE
            previous_rank = self._state_rank(previous.state)
            current_rank = self._state_rank(now.state)
            if current_rank < previous_rank:
                return CheckpointLifecycleJournalWitnessReason.JOURNAL_ROLLBACK_DETECTED
            if current_rank > previous_rank:
                strict_progress = True
            if previous.state == CheckpointLifecycleJournalState.COMMITTED.value:
                if (
                    now.state != CheckpointLifecycleJournalState.COMMITTED.value
                    or now.anchor_fingerprint_after != previous.anchor_fingerprint_after
                ):
                    return CheckpointLifecycleJournalWitnessReason.JOURNAL_WITNESS_DIVERGENCE

        witnessed_fences = {item.fence_token for item in witnessed.commands}
        for item in current.commands:
            if item.fence_token not in witnessed_fences and item.fence_token <= witnessed.highest_issued_fence:
                return CheckpointLifecycleJournalWitnessReason.JOURNAL_WITNESS_DIVERGENCE

        if current.journal_state_digest == witnessed.journal_state_digest:
            return None
        if strict_progress:
            return None
        return CheckpointLifecycleJournalWitnessReason.JOURNAL_WITNESS_DIVERGENCE

    def _verify_or_advance_witness(self) -> None:
        record = self._read_witness()
        current = self._journal_attestation()
        if current.journal_state_digest == record.attestation.journal_state_digest:
            return
        reason = self._classify_current_against_witness(record.attestation, current)
        if reason is None:
            self._write_witness(
                LifecycleJournalWitnessRecord(
                    witness_generation=record.witness_generation + 1,
                    attestation=current,
                )
            )
            self.witness_forward_advances += 1
            return
        if reason is CheckpointLifecycleJournalWitnessReason.JOURNAL_ROLLBACK_DETECTED:
            self.rollback_rejections += 1
        raise CheckpointLifecycleJournalWitnessError(reason)

    def _sync_after_journal_mutation(self) -> None:
        fault = self._consume_fault()
        if fault is CheckpointLifecycleJournalWitnessFaultMode.AFTER_JOURNAL_BEFORE_WITNESS:
            raise CheckpointLifecycleJournalWitnessError(
                CheckpointLifecycleJournalWitnessReason.SYNTHETIC_CRASH,
                fault_mode=fault,
            )
        self._verify_or_advance_witness()

    def issue_command(
        self,
        *,
        command_id: str,
        operation: CheckpointLifecycleCommandOperation,
        resource_id: str,
        saver: KeyLifecycleConfidentialCheckpointer,
    ) -> CheckpointLifecycleCommand:
        self._verify_or_advance_witness()
        command = self.journal.issue_command(
            command_id=command_id,
            operation=operation,
            resource_id=resource_id,
            saver=saver,
        )
        self._sync_after_journal_mutation()
        return command

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
        self._verify_or_advance_witness()
        receipt = self.journal.execute(
            command,
            saver,
            checkpoint_destination=checkpoint_destination,
            anchor_destination=anchor_destination,
            backup_database_path=backup_database_path,
            backup_anchor_path=backup_anchor_path,
        )
        self._sync_after_journal_mutation()
        return receipt

    def reconcile(
        self,
        command: CheckpointLifecycleCommand,
        saver: KeyLifecycleConfidentialCheckpointer,
    ) -> CheckpointLifecycleCommandReceipt:
        self._verify_or_advance_witness()
        receipt = self.journal.reconcile(command, saver)
        self._sync_after_journal_mutation()
        return receipt

    @property
    def witness_generation(self) -> int:
        return self._read_witness().witness_generation

    @property
    def highest_issued_fence(self) -> int:
        self._verify_or_advance_witness()
        return self.journal.highest_issued_fence

    @property
    def highest_committed_fence(self) -> int:
        self._verify_or_advance_witness()
        return self.journal.highest_committed_fence

    @property
    def receipt_count(self) -> int:
        self._verify_or_advance_witness()
        return self.journal.receipt_count

    def public_posture(self) -> dict[str, object]:
        self._verify_or_advance_witness()
        return {
            "provider_id": self.provider_id,
            "policy_version": P4N_LIFECYCLE_JOURNAL_WITNESS_POLICY_VERSION,
            "journal_policy_version": P4M_DURABLE_LIFECYCLE_JOURNAL_POLICY_VERSION,
            "synthetic_in_process": self.synthetic_in_process,
            "durable_local_witness": self.durable_local_witness,
            "independent_local_artifact": self.independent_local_artifact,
            "independent_failure_domain": self.independent_failure_domain,
            "rollback_resistant_journal": self.rollback_resistant_journal,
            "distributed_fencing": self.distributed_fencing,
            "exactly_once_execution": self.exactly_once_execution,
            "operationally_external": self.operationally_external,
            "production_runtime_eligible": self.production_runtime_eligible,
            "network_operations": self.network_operations,
            "witness_generation": self.witness_generation,
            "highest_issued_fence": self.journal.highest_issued_fence,
            "highest_committed_fence": self.journal.highest_committed_fence,
            "receipt_count": self.journal.receipt_count,
            "witness_forward_advances": self.witness_forward_advances,
            "rollback_rejections": self.rollback_rejections,
            "production_checkpoint_lifecycle_claim": False,
            "journal_and_witness_joint_rollback_detectable": False,
        }
