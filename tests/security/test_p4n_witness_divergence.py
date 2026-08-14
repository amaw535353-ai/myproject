from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from aegis.agent.checkpoint_external_contracts import (
    build_synthetic_external_checkpoint_contract_bundle,
)
from aegis.agent.checkpoint_external_lifecycle import (
    SyntheticExternalStyleCheckpointLifecycleProvider,
)
from aegis.agent.checkpoint_external_runtime_bridge import (
    SyntheticExternalCheckpointAnchorRuntimeBridge,
)
from aegis.agent.checkpoint_lifecycle_fencing import CheckpointLifecycleCommandOperation
from aegis.agent.checkpoint_lifecycle_journal import (
    DurableSyntheticCheckpointLifecycleCoordinator,
)
from aegis.agent.checkpoint_lifecycle_journal_witness import (
    CheckpointLifecycleJournalWitnessError,
    CheckpointLifecycleJournalWitnessReason,
    WitnessedDurableSyntheticCheckpointLifecycleCoordinator,
)
from aegis.agent.checkpoint_operation_runtime import OperationProviderKeyLifecycleCheckpointer
from evals.p4e_backup_common import put


def test_p4n_rejects_authenticated_same_generation_history_divergence(tmp_path: Path) -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    bridge = SyntheticExternalCheckpointAnchorRuntimeBridge(bundle.anchor)
    lifecycle = SyntheticExternalStyleCheckpointLifecycleProvider(anchor_provider=bridge)
    root = tmp_path / "same-generation-divergence"
    journal_path = root / "lifecycle-journal.sqlite3"
    witness_path = root / "lifecycle-journal.witness.json"
    saver = OperationProviderKeyLifecycleCheckpointer(
        database_path=root / "checkpoints.sqlite3",
        anchor_database_path=root / "compatibility-anchor.sqlite3",
        key_provider=bundle.encryption,
        integrity_provider=bundle.integrity,
        anchor_provider=bridge,
        lifecycle_provider=lifecycle,
    )
    put(
        saver,
        thread_id="p4n-divergence-thread",
        checkpoint_id="00000001",
        marker="p4n-divergence-state",
    )
    coordinator = WitnessedDurableSyntheticCheckpointLifecycleCoordinator(
        lifecycle_provider=lifecycle,
        journal_path=journal_path,
        witness_path=witness_path,
    )
    command = coordinator.issue_command(
        command_id="p4n-authenticated-divergence",
        operation=CheckpointLifecycleCommandOperation.MIGRATION,
        resource_id="migration:authenticated-divergence",
        saver=saver,
    )
    coordinator.execute(command, saver)

    connection = coordinator.journal._connect()
    try:
        row = coordinator.journal._load_row(connection, command.command_id)
        assert row is not None
        record = coordinator.journal._row_to_record(row)
    finally:
        connection.close()

    divergent_observation = dict(record.pre_observation)
    divergent_observation["synthetic_divergence_marker"] = "changed-with-journal-key"
    divergent_json = json.dumps(
        divergent_observation,
        sort_keys=True,
        separators=(",", ":"),
    )
    valid_divergent_tag = coordinator.journal._command_tag(
        command=record.command,
        state=record.state,
        pre_observation_json=divergent_json,
        anchor_fingerprint_after=record.anchor_fingerprint_after,
        provider_id=record.provider_id,
    )
    connection = sqlite3.connect(journal_path)
    try:
        connection.execute(
            """
            UPDATE lifecycle_commands
            SET pre_observation_json = ?, integrity_tag = ?
            WHERE command_id = ?
            """,
            (divergent_json, valid_divergent_tag, command.command_id),
        )
        connection.commit()
    finally:
        connection.close()

    # The modified row is still valid under the P4-M journal key. P4-N's
    # separately keyed witness must reject the alternate same-generation history.
    DurableSyntheticCheckpointLifecycleCoordinator(
        lifecycle_provider=lifecycle,
        journal_path=journal_path,
    )
    with pytest.raises(CheckpointLifecycleJournalWitnessError) as raised:
        WitnessedDurableSyntheticCheckpointLifecycleCoordinator(
            lifecycle_provider=lifecycle,
            journal_path=journal_path,
            witness_path=witness_path,
        )
    assert (
        raised.value.reason
        is CheckpointLifecycleJournalWitnessReason.JOURNAL_WITNESS_DIVERGENCE
    )
