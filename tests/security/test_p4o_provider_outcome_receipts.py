from __future__ import annotations

import inspect
import sqlite3

import pytest

import aegis.agent.checkpoint_lifecycle_outcome_receipts as outcome_module
from aegis.agent.checkpoint_lifecycle_fencing import (
    CheckpointLifecycleCommand,
    CheckpointLifecycleCommandOperation,
)
from aegis.agent.checkpoint_lifecycle_outcome_receipts import (
    P4O_PROVIDER_OUTCOME_RECEIPT_POLICY_VERSION,
    ProviderLifecycleOutcomeError,
    ProviderLifecycleOutcomeReason,
    SyntheticIdempotentOutcomeReceiptLifecycleProvider,
)
from evals.p4o_provider_outcome_receipts import (
    _anchor_fingerprint,
    _receipt_runtime,
    build_report,
)


def _snapshot_command(command_id, bridge, resource_id):
    return CheckpointLifecycleCommand(
        command_id=command_id,
        operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
        fence_token=1,
        expected_anchor_fingerprint=_anchor_fingerprint(bridge),
        resource_id=resource_id,
    )


def test_exact_provider_command_replay_returns_durable_receipt_without_reexecution(tmp_path) -> None:
    _, bridge, inner, provider, saver, outcome_path, _, _ = _receipt_runtime(
        tmp_path, "replay"
    )
    command = _snapshot_command("p4o-test-replay", bridge, "snapshot:test-replay")
    first = provider.execute_lifecycle_command(
        command,
        saver,
        checkpoint_destination=tmp_path / "replay.sqlite3",
        anchor_destination=tmp_path / "replay.json",
    )
    reopened = SyntheticIdempotentOutcomeReceiptLifecycleProvider(
        lifecycle_provider=inner,
        outcome_database_path=outcome_path,
    )
    replay = reopened.execute_lifecycle_command(
        command,
        saver,
        checkpoint_destination=tmp_path / "replay.sqlite3",
        anchor_destination=tmp_path / "replay.json",
    )

    assert first.replayed is False
    assert replay.replayed is True
    assert first.digest() == replay.digest()
    assert inner.snapshot_calls == 1
    assert reopened.outcome_store.receipt_count == 1


def test_same_command_id_with_different_digest_fails_closed_before_provider(tmp_path) -> None:
    _, bridge, inner, provider, saver, _, _, _ = _receipt_runtime(tmp_path, "conflict")
    first = _snapshot_command("p4o-test-conflict", bridge, "snapshot:original")
    conflict = _snapshot_command("p4o-test-conflict", bridge, "snapshot:changed")
    provider.execute_lifecycle_command(
        first,
        saver,
        checkpoint_destination=tmp_path / "one.sqlite3",
        anchor_destination=tmp_path / "one.json",
    )

    with pytest.raises(ProviderLifecycleOutcomeError) as raised:
        provider.execute_lifecycle_command(
            conflict,
            saver,
            checkpoint_destination=tmp_path / "two.sqlite3",
            anchor_destination=tmp_path / "two.json",
        )

    assert raised.value.reason is ProviderLifecycleOutcomeReason.COMMAND_CONFLICT
    assert inner.snapshot_calls == 1


def test_provider_outcome_receipt_tamper_is_detected_on_reopen(tmp_path) -> None:
    _, bridge, inner, provider, saver, outcome_path, _, _ = _receipt_runtime(tmp_path, "tamper")
    command = _snapshot_command("p4o-test-tamper", bridge, "snapshot:tamper")
    provider.execute_lifecycle_command(
        command,
        saver,
        checkpoint_destination=tmp_path / "tamper.sqlite3",
        anchor_destination=tmp_path / "tamper.json",
    )
    connection = sqlite3.connect(outcome_path)
    try:
        connection.execute(
            "UPDATE provider_outcome_receipts SET anchor_fingerprint_after = ? WHERE command_id = ?",
            ("0" * 64, command.command_id),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ProviderLifecycleOutcomeError) as raised:
        SyntheticIdempotentOutcomeReceiptLifecycleProvider(
            lifecycle_provider=inner,
            outcome_database_path=outcome_path,
        )
    assert raised.value.reason is ProviderLifecycleOutcomeReason.RECEIPT_INTEGRITY_FAILED


def test_p4o_evaluation_exact_metrics_and_security_posture() -> None:
    report = build_report()
    baseline = report["variants"]["outcome_blind_retry_baseline"]["metrics"]
    hardened = report["variants"]["provider_owned_authenticated_outcome_receipts"]["metrics"]

    assert report["passed"] is True
    assert baseline["asr"] == [2, 2]
    assert hardened["asr"] == [0, 2]
    assert hardened["fpr"] == [0, 3]
    assert hardened["safe_task_rate"] == [3, 3]
    assert report["eval_dataset_hash_sha256"] == "478bd6c74e8ad1326002f90ff466fe574a1f805fbfe98b483481038aaeae08e3"
    assert report["policy_version"] == P4O_PROVIDER_OUTCOME_RECEIPT_POLICY_VERSION
    assert report["provider_owned_outcome_receipts"] is True
    assert report["authenticated_provider_receipts"] is True
    assert report["provider_receipt_binds_exact_command_and_post_anchor"] is True
    assert report["all_lifecycle_operations_ambiguous_local_results_recovered"] is True
    assert report["provider_reexecution_during_reconciliation"] is False
    assert report["provider_receipt_integrity_tamper_rejected"] is True
    assert report["p4k_production_rejection_preserved"] is True
    assert report["provider_internal_operation_receipt_atomicity_claim"] is False
    assert report["exactly_once_claim"] is False
    assert report["production_checkpoint_lifecycle_claim"] is False
    assert report["network_operations"] == 0


def test_p4o_hardened_module_does_not_import_vulnerable_baseline() -> None:
    source = inspect.getsource(outcome_module)
    assert "aegis.vulnerable" not in source
    assert "VulnerableOutcomeBlindLifecycleProvider" not in source
