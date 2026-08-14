from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_lifecycle_fencing import (
    CheckpointLifecycleCommand,
    CheckpointLifecycleCommandOperation,
)


class VulnerableOutcomeBlindLifecycleProvider:
    """P4-O lab baseline: retries lifecycle commands without provider-owned identity.

    It deliberately keeps no durable receipt or command binding. Replaying the same
    command, or reusing a command id with a different digest, invokes the underlying
    synthetic provider again.
    """

    provider_id = "vulnerable-outcome-blind-checkpoint-lifecycle"
    synthetic_in_process = True
    operationally_external = False
    production_runtime_eligible = False
    network_operations = 0

    def __init__(self, *, lifecycle_provider: Any) -> None:
        self._inner = lifecycle_provider
        self._anchor_provider = getattr(lifecycle_provider, "bound_anchor_provider", None)
        self.anchor_provider_id = str(getattr(lifecycle_provider, "anchor_provider_id", ""))
        self.capabilities = frozenset(getattr(lifecycle_provider, "capabilities", frozenset()))
        self.command_invocations = 0

    @property
    def bound_anchor_provider(self) -> Any:
        return self._anchor_provider

    def execute_lifecycle_command(
        self,
        command: CheckpointLifecycleCommand,
        saver: KeyLifecycleConfidentialCheckpointer,
        *,
        checkpoint_destination: Path | None = None,
        anchor_destination: Path | None = None,
        backup_database_path: Path | None = None,
        backup_anchor_path: Path | None = None,
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
        raise ValueError("unsupported synthetic lifecycle operation")
