from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis.agent.checkpoint_key_lifecycle import KeyLifecycleConfidentialCheckpointer
from aegis.agent.checkpoint_lifecycle_fencing import (
    CheckpointLifecycleCommand,
    CheckpointLifecycleCommandOperation,
)


class VulnerableProviderInternalAmbiguityLifecycleProvider:
    """P4-P lab baseline with a mutation/receipt crash gap.

    It deliberately persists no provider-owned command state before mutation.
    A synthetic crash after the underlying lifecycle operation therefore leaves no
    durable evidence that the operation started or completed; retry re-invokes the
    underlying provider and may accept different operation arguments.
    """

    provider_id = "vulnerable-provider-internal-ambiguity-checkpoint-lifecycle"
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
        self.crash_after_mutation = False

    @property
    def bound_anchor_provider(self) -> Any:
        return self._anchor_provider

    def arm_crash_after_mutation(self) -> None:
        self.crash_after_mutation = True

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
            raise ValueError("unsupported synthetic lifecycle operation")

        if self.crash_after_mutation:
            self.crash_after_mutation = False
            raise RuntimeError("synthetic provider crash after lifecycle mutation")
