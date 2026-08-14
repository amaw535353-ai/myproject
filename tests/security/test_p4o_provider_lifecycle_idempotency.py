from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from aegis.agent.checkpoint_lifecycle_fencing import CheckpointLifecycleCommandOperation
from aegis.agent.checkpoint_lifecycle_trust import (
    CheckpointLifecycleTrustBoundaryError,
    CheckpointLifecycleTrustReason,
    assert_checkpoint_deployment_trust,
    describe_checkpoint_lifecycle_provider,
)
from aegis.agent.checkpoint_provider_idempotency import (
    P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_POLICY_VERSION,
    CheckpointProviderLifecycleError,
    CheckpointProviderLifecycleFaultMode,
    CheckpointProviderLifecycleReason,
    SyntheticProviderIdempotentCheckpointLifecycleProvider,
)
from aegis.effects.trust_providers import TrustDeploymentProfile, TrustProviderKind
from evals.p4o_provider_lifecycle_idempotency import (
    _make,
    _migration_command,
    _reopen_provider,
    build_report,
)


EXPECTED_DATASET_HASH = "ae1a623525cae1d99c69de2c6317c943a63ec76b4bafa23f2935fd6be44df045"


def test_exact_duplicate_returns_same_authenticated_receipt_without_second_side_effect(
    tmp_path: Path,
) -> None:
    saver, delegate, provider, ledger_path, _, coordinator = _make(
        tmp_path, "duplicate-test", legacy_seed=True
    )
    command = _migration_command(coordinator, saver, "duplicate-test")
    first = provider.execute_command(command, saver)
    reopened = _reopen_provider(delegate, ledger_path)
    second = reopened.execute_command(command, saver)

    assert first.receipt_tag == second.receipt_tag
    assert second.replayed is True
    assert delegate.migration_calls == 1
    assert reopened.side_effect_invocations == 0
    assert reopened.verify_receipt(second, command) == second


def test_same_command_id_with_different_operation_arguments_is_conflict(
    tmp_path: Path,
) -> None:
    saver, _, provider, _, _, coordinator = _make(tmp_path, "argument-conflict")
    command = coordinator.issue_command(
        command_id="p4o-argument-conflict",
        operation=CheckpointLifecycleCommandOperation.SNAPSHOT,
        resource_id="snapshot:argument-conflict",
        saver=saver,
    )
    provider.execute_command(
        command,
        saver,
        checkpoint_destination=tmp_path / "first-checkpoint.sqlite3",
        anchor_destination=tmp_path / "first-anchor.sqlite3",
    )

    with pytest.raises(CheckpointProviderLifecycleError) as exc_info:
        provider.execute_command(
            command,
            saver,
            checkpoint_destination=tmp_path / "second-checkpoint.sqlite3",
            anchor_destination=tmp_path / "second-anchor.sqlite3",
        )

    assert exc_info.value.reason is CheckpointProviderLifecycleReason.COMMAND_CONFLICT


def test_accepted_before_side_effect_can_retry_only_before_any_side_effect(
    tmp_path: Path,
) -> None:
    saver, delegate, provider, ledger_path, _, coordinator = _make(
        tmp_path, "accepted-retry"
    )
    command = _migration_command(coordinator, saver, "accepted-retry")
    provider.arm_fault(
        CheckpointProviderLifecycleFaultMode.AFTER_ACCEPTED_BEFORE_SIDE_EFFECT
    )
    with pytest.raises(CheckpointProviderLifecycleError) as exc_info:
        provider.execute_command(command, saver)
    assert exc_info.value.reason is CheckpointProviderLifecycleReason.SYNTHETIC_CRASH
    assert delegate.migration_calls == 0

    reopened = _reopen_provider(delegate, ledger_path)
    receipt = reopened.execute_command(command, saver)
    assert receipt.replayed is False
    assert delegate.migration_calls == 1


def test_started_ambiguous_outcome_survives_reopen_and_never_blindly_reexecutes(
    tmp_path: Path,
) -> None:
    saver, delegate, provider, ledger_path, _, coordinator = _make(
        tmp_path, "started-unknown", legacy_seed=True
    )
    command = _migration_command(coordinator, saver, "started-unknown")
    provider.arm_fault(
        CheckpointProviderLifecycleFaultMode.AFTER_SIDE_EFFECT_BEFORE_APPLIED
    )
    with pytest.raises(CheckpointProviderLifecycleError):
        provider.execute_command(command, saver)
    assert delegate.migration_calls == 1

    reopened = _reopen_provider(delegate, ledger_path)
    with pytest.raises(CheckpointProviderLifecycleError) as query_exc:
        reopened.query_outcome(command)
    assert query_exc.value.reason is CheckpointProviderLifecycleReason.OUTCOME_UNKNOWN
    with pytest.raises(CheckpointProviderLifecycleError) as retry_exc:
        reopened.execute_command(command, saver)
    assert retry_exc.value.reason is CheckpointProviderLifecycleReason.OUTCOME_UNKNOWN
    assert delegate.migration_calls == 1


def test_provider_ledger_row_tamper_fails_closed_on_reopen(tmp_path: Path) -> None:
    saver, delegate, provider, ledger_path, _, coordinator = _make(tmp_path, "tamper")
    command = _migration_command(coordinator, saver, "tamper")
    provider.execute_command(command, saver)

    connection = sqlite3.connect(ledger_path)
    try:
        connection.execute(
            "UPDATE provider_commands SET result_digest = ? WHERE command_id = ?",
            ("0" * 64, command.command_id),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(CheckpointProviderLifecycleError) as exc_info:
        _reopen_provider(delegate, ledger_path)
    assert exc_info.value.reason is CheckpointProviderLifecycleReason.LEDGER_INTEGRITY_FAILED


def test_provider_receipt_is_bound_to_command_and_payload(tmp_path: Path) -> None:
    saver, _, provider, _, _, coordinator = _make(tmp_path, "receipt-binding")
    command = _migration_command(coordinator, saver, "receipt-binding")
    receipt = provider.execute_command(command, saver)

    with pytest.raises(CheckpointProviderLifecycleError) as tamper_exc:
        provider.verify_receipt(replace(receipt, result_digest="f" * 64), command)
    assert tamper_exc.value.reason is CheckpointProviderLifecycleReason.RECEIPT_INVALID

    with pytest.raises(CheckpointProviderLifecycleError) as splice_exc:
        provider.verify_receipt(replace(receipt, command_id="different-command"), command)
    assert (
        splice_exc.value.reason
        is CheckpointProviderLifecycleReason.RECEIPT_COMMAND_MISMATCH
    )


def test_provider_remains_rejected_by_p4k_production_trust(tmp_path: Path) -> None:
    saver, _, provider, _, _, _ = _make(tmp_path, "production-rejection")
    del saver
    from aegis.agent.checkpoint_external_contracts import (
        build_synthetic_external_checkpoint_contract_bundle,
    )

    manifest = build_synthetic_external_checkpoint_contract_bundle().manifest
    descriptor = describe_checkpoint_lifecycle_provider(
        provider,
        kind=TrustProviderKind.EXTERNAL,
        independent_failure_domain=False,
    )
    with pytest.raises(CheckpointLifecycleTrustBoundaryError) as exc_info:
        assert_checkpoint_deployment_trust(
            checkpoint_manifest=manifest,
            lifecycle_descriptor=descriptor,
            profile=TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED,
        )
    assert exc_info.value.reason in {
        CheckpointLifecycleTrustReason.INDEPENDENT_FAILURE_DOMAIN_REQUIRED,
        CheckpointLifecycleTrustReason.SYNTHETIC_PROVIDER_IN_PRODUCTION,
    }


def test_p4j_compatibility_anchor_path_remains_unused(tmp_path: Path) -> None:
    saver, delegate, provider, _, _, coordinator = _make(tmp_path, "compatibility-path")
    command = _migration_command(coordinator, saver, "compatibility-path")
    provider.execute_command(command, saver)
    assert delegate.compatibility_anchor_path_accesses == 0


def test_p4o_eval_hash_metrics_and_nonproduction_claims() -> None:
    report = build_report()
    assert report["policy_version"] == P4O_PROVIDER_LIFECYCLE_IDEMPOTENCY_POLICY_VERSION
    assert report["eval_dataset_hash_sha256"] == EXPECTED_DATASET_HASH
    assert report["variants"]["local_only_outcome_tracking_baseline"]["metrics"]["asr"] == [5, 5]
    hardened = report["variants"]["provider_owned_idempotency_receipt_contract"]["metrics"]
    assert hardened["asr"] == [0, 5]
    assert hardened["fpr"] == [0, 3]
    assert hardened["safe_task_rate"] == [3, 3]
    assert report["provider_owned_durable_idempotency_ledger"] is True
    assert report["provider_outcome_receipt_authenticated"] is True
    assert report["unknown_provider_outcome_fails_closed"] is True
    assert report["snapshot_and_restore_operations_exercised"] is True
    assert report["exactly_once_claim"] is False
    assert report["distributed_transaction_claim"] is False
    assert report["production_provider_claim"] is False
    assert report["network_operations"] == 0
    assert report["passed"] is True
