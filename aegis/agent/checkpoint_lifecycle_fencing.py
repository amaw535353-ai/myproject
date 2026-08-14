from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_lifecycle_capabilities import (
    CheckpointLifecycleCapability,
    CheckpointLifecycleOperationProvider,
    require_lifecycle_capability,
)


P4L_CHECKPOINT_LIFECYCLE_FENCING_POLICY_VERSION = (
    "checkpoint-lifecycle-failure-fencing-harness-v1"
)


class CheckpointLifecycleCommandOperation(StrEnum):
    MIGRATION = "checkpoint_encryption_migration"
    SNAPSHOT = "checkpoint_backup_snapshot"
    RESTORE = "checkpoint_backup_restore"

    @property
    def capability(self) -> CheckpointLifecycleCapability:
        return CheckpointLifecycleCapability(self.value)


class CheckpointLifecycleFaultMode(StrEnum):
    NONE = "none"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    AMBIGUOUS_AFTER_COMMIT = "ambiguous_after_commit"
    PARTIAL_ANCHOR_PROGRESS = "partial_anchor_progress"


class CheckpointLifecycleFencingReason(StrEnum):
    PROVIDER_UNAVAILABLE = "checkpoint_lifecycle_provider_unavailable"
    STALE_FENCE = "checkpoint_lifecycle_stale_fence"
    COMMAND_REPLAY_CONFLICT = "checkpoint_lifecycle_command_replay_conflict"
    ANCHOR_FENCE_MISMATCH = "checkpoint_lifecycle_anchor_fence_mismatch"
    AMBIGUOUS_COMMIT_OUTCOME = "checkpoint_lifecycle_ambiguous_commit_outcome"
    PARTIAL_PROGRESS_RECONCILED = "checkpoint_lifecycle_partial_progress_reconciled"
    ANCHOR_STATE_UNAVAILABLE = "checkpoint_lifecycle_anchor_state_unavailable"
    OPERATION_ARGUMENTS_INVALID = "checkpoint_lifecycle_operation_arguments_invalid"


class CheckpointLifecycleFencingError(RuntimeError):
    def __init__(
        self,
        reason: CheckpointLifecycleFencingReason,
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
class CheckpointLifecycleCommand:
    command_id: str
    operation: CheckpointLifecycleCommandOperation
    fence_token: int
    expected_anchor_fingerprint: str
    resource_id: str

    def __post_init__(self) -> None:
        if not self.command_id.strip():
            raise ValueError("checkpoint lifecycle command id must be non-empty")
        if self.fence_token < 1:
            raise ValueError("checkpoint lifecycle fence token must be positive")
        if not self.expected_anchor_fingerprint.strip():
            raise ValueError("checkpoint lifecycle anchor fingerprint must be non-empty")
        if not self.resource_id.strip():
            raise ValueError("checkpoint lifecycle resource id must be non-empty")

    def digest(self) -> str:
        payload = json.dumps(
            {
                "command_id": self.command_id,
                "operation": self.operation.value,
                "fence_token": self.fence_token,
                "expected_anchor_fingerprint": self.expected_anchor_fingerprint,
                "resource_id": self.resource_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class CheckpointLifecycleCommandReceipt:
    command_id: str
    operation: CheckpointLifecycleCommandOperation
    fence_token: int
    command_digest: str
    anchor_fingerprint_after: str
    provider_id: str
    replayed: bool = False


class SyntheticFencedCheckpointLifecycleCoordinator:
    """Single-process P4-L failure/fencing harness for a lifecycle provider.

    The coordinator adds deterministic command identity, monotonic fencing,
    anchor-state preconditions, replay-safe receipts, and synthetic fault injection
    around a P4-I lifecycle operation provider. It is intentionally in-memory and
    single-process. It does not establish distributed consensus, durable fencing,
    provider SLAs, or production crash consistency.
    """

    synthetic_in_process = True
    operationally_external = False
    production_runtime_eligible = False
    network_operations = 0

    def __init__(self, *, lifecycle_provider: CheckpointLifecycleOperationProvider) -> None:
        self._provider = lifecycle_provider
        self._anchor_provider = getattr(lifecycle_provider, "bound_anchor_provider", None)
        self._highest_committed_fence = 0
        self._receipts: dict[str, CheckpointLifecycleCommandReceipt] = {}
        self._fault_mode = CheckpointLifecycleFaultMode.NONE
        self.provider_invocations = 0
        self.replay_hits = 0
        self.reconciliations = 0

    @property
    def provider_id(self) -> str:
        return str(getattr(self._provider, "provider_id", ""))

    @property
    def highest_committed_fence(self) -> int:
        return self._highest_committed_fence

    @property
    def receipt_count(self) -> int:
        return len(self._receipts)

    def arm_fault(self, mode: CheckpointLifecycleFaultMode) -> None:
        self._fault_mode = CheckpointLifecycleFaultMode(mode)

    def _consume_fault(self) -> CheckpointLifecycleFaultMode:
        mode = self._fault_mode
        self._fault_mode = CheckpointLifecycleFaultMode.NONE
        return mode

    def _export_anchor_state(
        self,
    ) -> tuple[tuple[dict[str, object], ...], tuple[dict[str, object], ...]]:
        export_heads = getattr(self._anchor_provider, "export_heads", None)
        export_write_heads = getattr(self._anchor_provider, "export_write_heads", None)
        if not callable(export_heads) or not callable(export_write_heads):
            raise CheckpointLifecycleFencingError(
                CheckpointLifecycleFencingReason.ANCHOR_STATE_UNAVAILABLE
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

    def issue_command(
        self,
        *,
        command_id: str,
        operation: CheckpointLifecycleCommandOperation,
        resource_id: str,
    ) -> CheckpointLifecycleCommand:
        return CheckpointLifecycleCommand(
            command_id=command_id,
            operation=CheckpointLifecycleCommandOperation(operation),
            fence_token=self._highest_committed_fence + 1,
            expected_anchor_fingerprint=self.anchor_fingerprint(),
            resource_id=resource_id,
        )

    def _replace_anchor_state(
        self,
        *,
        checkpoint_heads: tuple[dict[str, object], ...],
        write_heads: tuple[dict[str, object], ...],
    ) -> None:
        replace_state = getattr(self._anchor_provider, "replace_state", None)
        if not callable(replace_state):
            raise CheckpointLifecycleFencingError(
                CheckpointLifecycleFencingReason.ANCHOR_STATE_UNAVAILABLE
            )
        replace_state(
            checkpoint_heads=checkpoint_heads,
            write_heads=write_heads,
        )

    def _inject_partial_anchor_progress(
        self,
        checkpoint_heads: tuple[dict[str, object], ...],
        write_heads: tuple[dict[str, object], ...],
    ) -> None:
        next_heads = [dict(item) for item in checkpoint_heads]
        if next_heads:
            next_heads[0]["checkpoint_digest"] = "f" * 64
        else:
            next_heads.append(
                {
                    "thread_id": "p4l-partial-progress",
                    "checkpoint_ns": "",
                    "generation": 1,
                    "checkpoint_id": "partial-progress",
                    "checkpoint_digest": "f" * 64,
                }
            )
        self._replace_anchor_state(
            checkpoint_heads=tuple(next_heads),
            write_heads=write_heads,
        )

    def _validate_command(self, command: CheckpointLifecycleCommand) -> CheckpointLifecycleCommandReceipt | None:
        command_digest = command.digest()
        existing = self._receipts.get(command.command_id)
        if existing is not None:
            if existing.command_digest != command_digest:
                raise CheckpointLifecycleFencingError(
                    CheckpointLifecycleFencingReason.COMMAND_REPLAY_CONFLICT,
                    command_id=command.command_id,
                )
            self.replay_hits += 1
            return replace(existing, replayed=True)
        if command.fence_token <= self._highest_committed_fence:
            raise CheckpointLifecycleFencingError(
                CheckpointLifecycleFencingReason.STALE_FENCE,
                command_id=command.command_id,
            )
        if command.expected_anchor_fingerprint != self.anchor_fingerprint():
            raise CheckpointLifecycleFencingError(
                CheckpointLifecycleFencingReason.ANCHOR_FENCE_MISMATCH,
                command_id=command.command_id,
            )
        return None

    def _record_receipt(self, command: CheckpointLifecycleCommand) -> CheckpointLifecycleCommandReceipt:
        receipt = CheckpointLifecycleCommandReceipt(
            command_id=command.command_id,
            operation=command.operation,
            fence_token=command.fence_token,
            command_digest=command.digest(),
            anchor_fingerprint_after=self.anchor_fingerprint(),
            provider_id=self.provider_id,
        )
        self._receipts[command.command_id] = receipt
        self._highest_committed_fence = command.fence_token
        return receipt

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
        replay = self._validate_command(command)
        if replay is not None:
            return replay

        require_lifecycle_capability(self._provider, command.operation.capability)
        before_checkpoint_heads, before_write_heads = self._export_anchor_state()
        fault = self._consume_fault()

        if fault is CheckpointLifecycleFaultMode.PROVIDER_UNAVAILABLE:
            raise CheckpointLifecycleFencingError(
                CheckpointLifecycleFencingReason.PROVIDER_UNAVAILABLE,
                command_id=command.command_id,
            )

        if fault is CheckpointLifecycleFaultMode.PARTIAL_ANCHOR_PROGRESS:
            self._inject_partial_anchor_progress(
                before_checkpoint_heads,
                before_write_heads,
            )
            self._replace_anchor_state(
                checkpoint_heads=before_checkpoint_heads,
                write_heads=before_write_heads,
            )
            if self.anchor_fingerprint() != command.expected_anchor_fingerprint:
                raise CheckpointLifecycleFencingError(
                    CheckpointLifecycleFencingReason.ANCHOR_STATE_UNAVAILABLE,
                    command_id=command.command_id,
                )
            self.reconciliations += 1
            raise CheckpointLifecycleFencingError(
                CheckpointLifecycleFencingReason.PARTIAL_PROGRESS_RECONCILED,
                command_id=command.command_id,
            )

        self.provider_invocations += 1
        if command.operation is CheckpointLifecycleCommandOperation.MIGRATION:
            self._provider.migrate_to_active_encryption_key(saver)
        elif command.operation is CheckpointLifecycleCommandOperation.SNAPSHOT:
            if checkpoint_destination is None or anchor_destination is None:
                raise CheckpointLifecycleFencingError(
                    CheckpointLifecycleFencingReason.OPERATION_ARGUMENTS_INVALID,
                    command_id=command.command_id,
                )
            self._provider.snapshot_pair(
                saver,
                checkpoint_destination=Path(checkpoint_destination),
                anchor_destination=Path(anchor_destination),
            )
        elif command.operation is CheckpointLifecycleCommandOperation.RESTORE:
            if backup_database_path is None or backup_anchor_path is None:
                raise CheckpointLifecycleFencingError(
                    CheckpointLifecycleFencingReason.OPERATION_ARGUMENTS_INVALID,
                    command_id=command.command_id,
                )
            self._provider.restore_pair(
                saver,
                backup_database_path=Path(backup_database_path),
                backup_anchor_path=Path(backup_anchor_path),
            )
        else:
            raise CheckpointLifecycleFencingError(
                CheckpointLifecycleFencingReason.OPERATION_ARGUMENTS_INVALID,
                command_id=command.command_id,
            )

        receipt = self._record_receipt(command)
        if fault is CheckpointLifecycleFaultMode.AMBIGUOUS_AFTER_COMMIT:
            raise CheckpointLifecycleFencingError(
                CheckpointLifecycleFencingReason.AMBIGUOUS_COMMIT_OUTCOME,
                command_id=command.command_id,
            )
        return receipt

    def public_posture(self) -> dict[str, object]:
        return {
            "provider_id": self.provider_id,
            "policy_version": P4L_CHECKPOINT_LIFECYCLE_FENCING_POLICY_VERSION,
            "synthetic_in_process": self.synthetic_in_process,
            "operationally_external": self.operationally_external,
            "production_runtime_eligible": self.production_runtime_eligible,
            "network_operations": self.network_operations,
            "highest_committed_fence": self._highest_committed_fence,
            "receipt_count": len(self._receipts),
            "provider_invocations": self.provider_invocations,
            "replay_hits": self.replay_hits,
            "reconciliations": self.reconciliations,
        }
