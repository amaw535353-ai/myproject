from __future__ import annotations

import inspect
import sqlite3

import pytest

import aegis.agent.checkpoint_lifecycle_provider_state_machine as provider_state_module
from aegis.agent.checkpoint_lifecycle_fencing import CheckpointLifecycleCommandOperation
from aegis.agent.checkpoint_lifecycle_provider_state_machine import (
    P4P_PROVIDER_COMMAND_STATE_POLICY_VERSION,
    ProviderCommandFaultMode,
    ProviderCommandStateError,
    ProviderCommandStateReason,
    SyntheticCrashSafeOutcomeReceiptLifecycleProvider,
)
from evals.p4p_provider_crash_safe_state import (
    _crash_safe_runtime,
    build_report,
)


def test_provider_command_argument_binding_rejects_retry_substitution(tmp_path) -> None:
    (
        _,
        _,
        inner,
        provider,
        saver,
        command_path,
        outcome_path,
        _,
        coordinator,
    ) = _crash_safe_runtime(tmp_path, "argument-binding")
    first_db = tmp_path / "first.sqlite3"
    first_anchor = tmp_path / "first-anchor.sqlite3"
    command = coordinator.issue_command(
        command_id="p4p-test-arguments",
        operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
        resource_id="snapshot:test-arguments",
        saver=saver,
    )
    provider.arm_fault(ProviderCommandFaultMode.AFTER_MUTATION_BEFORE_RECEIPT)
    with pytest.raises(Exception):
        provider.execute_lifecycle_command(
            command,
            saver,
            checkpoint_destination=first_db,
            anchor_destination=first_anchor,
        )

    reopened = SyntheticCrashSafeOutcomeReceiptLifecycleProvider(
        lifecycle_provider=inner,
        command_database_path=command_path,
        outcome_database_path=outcome_path,
    )
    with pytest.raises(ProviderCommandStateError) as raised:
        reopened.recover_lifecycle_command(
            command,
            saver,
            checkpoint_destination=tmp_path / "different.sqlite3",
            anchor_destination=tmp_path / "different-anchor.sqlite3",
        )
    assert raised.value.reason is ProviderCommandStateReason.ARGUMENT_CONFLICT
    assert inner.snapshot_calls == 1


def test_provider_command_state_tamper_is_detected_on_reopen(tmp_path) -> None:
    (
        _,
        _,
        inner,
        provider,
        saver,
        command_path,
        outcome_path,
        _,
        coordinator,
    ) = _crash_safe_runtime(tmp_path, "tamper")
    command = coordinator.issue_command(
        command_id="p4p-test-tamper",
        operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
        resource_id="snapshot:test-tamper",
        saver=saver,
    )
    provider.arm_fault(ProviderCommandFaultMode.AFTER_PREPARE_BEFORE_MUTATION)
    with pytest.raises(ProviderCommandStateError):
        provider.execute_lifecycle_command(
            command,
            saver,
            checkpoint_destination=tmp_path / "tamper.sqlite3",
            anchor_destination=tmp_path / "tamper-anchor.sqlite3",
        )

    connection = sqlite3.connect(command_path)
    try:
        connection.execute(
            "UPDATE provider_commands SET resource_id = ? WHERE command_id = ?",
            ("snapshot:tampered", command.command_id),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ProviderCommandStateError) as raised:
        SyntheticCrashSafeOutcomeReceiptLifecycleProvider(
            lifecycle_provider=inner,
            command_database_path=command_path,
            outcome_database_path=outcome_path,
        )
    assert raised.value.reason is ProviderCommandStateReason.INTEGRITY_FAILED


def test_provider_mutation_gap_fails_closed_when_snapshot_evidence_is_missing(tmp_path) -> None:
    (
        _,
        _,
        inner,
        provider,
        saver,
        command_path,
        outcome_path,
        _,
        coordinator,
    ) = _crash_safe_runtime(tmp_path, "unprovable")
    snapshot_db = tmp_path / "unprovable.sqlite3"
    snapshot_anchor = tmp_path / "unprovable-anchor.sqlite3"
    command = coordinator.issue_command(
        command_id="p4p-test-unprovable",
        operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
        resource_id="snapshot:test-unprovable",
        saver=saver,
    )
    provider.arm_fault(ProviderCommandFaultMode.AFTER_MUTATION_BEFORE_RECEIPT)
    with pytest.raises(ProviderCommandStateError):
        provider.execute_lifecycle_command(
            command,
            saver,
            checkpoint_destination=snapshot_db,
            anchor_destination=snapshot_anchor,
        )
    snapshot_db.unlink()

    reopened = SyntheticCrashSafeOutcomeReceiptLifecycleProvider(
        lifecycle_provider=inner,
        command_database_path=command_path,
        outcome_database_path=outcome_path,
    )
    with pytest.raises(ProviderCommandStateError) as raised:
        reopened.recover_lifecycle_command(
            command,
            saver,
            checkpoint_destination=snapshot_db,
            anchor_destination=snapshot_anchor,
        )
    assert raised.value.reason is ProviderCommandStateReason.RECONCILIATION_UNPROVABLE
    assert inner.snapshot_calls == 1


def test_p4p_evaluation_exact_metrics_and_security_posture() -> None:
    report = build_report()
    baseline = report["variants"]["provider_internal_ambiguity_baseline"]["metrics"]
    hardened = report["variants"]["crash_safe_provider_command_state"]["metrics"]

    assert report["passed"] is True
    assert baseline["asr"] == [3, 3]
    assert hardened["asr"] == [0, 3]
    assert hardened["fpr"] == [0, 5]
    assert hardened["safe_task_rate"] == [5, 5]
    assert report["eval_dataset_hash_sha256"] == "569afe0aa45eb5bed65e4819c5a59cbfcd388abc0e4ecf8bdda3f5fd7d387e91"
    assert report["policy_version"] == P4P_PROVIDER_COMMAND_STATE_POLICY_VERSION
    assert report["provider_owned_command_state"] is True
    assert report["authenticated_provider_command_state"] is True
    assert report["provider_argument_binding"] is True
    assert report["provider_internal_mutation_receipt_gap_recoverable"] is True
    assert report["provider_prepare_crash_safe_retry"] is True
    assert report["provider_receipt_commit_response_crash_replay"] is True
    assert report["provider_reexecution_during_mutation_gap_reconciliation"] is False
    assert report["p4k_production_rejection_preserved"] is True
    assert report["distributed_transaction_claim"] is False
    assert report["exactly_once_claim"] is False
    assert report["production_checkpoint_lifecycle_claim"] is False
    assert report["network_operations"] == 0


def test_p4p_hardened_module_does_not_import_vulnerable_baseline() -> None:
    source = inspect.getsource(provider_state_module)
    assert "aegis.vulnerable" not in source
    assert "VulnerableProviderInternalAmbiguityLifecycleProvider" not in source
