from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.agent.checkpoint_external_contracts import (
    P4G_CHECKPOINT_EXTERNAL_CONTRACT_POLICY_VERSION,
    CheckpointExternalContractError,
    CheckpointExternalContractReason,
    RecoveryAuthorizationRequest,
    SyntheticExternalStyleCheckpointEncryptionAdapter,
    build_synthetic_external_checkpoint_contract_bundle,
)
from aegis.effects.trust_providers import TrustDeploymentProfile
from evals.p4g_checkpoint_external_contract_harness import build_report


def test_synthetic_external_contract_bundle_exercises_p4f_production_profile_without_runtime_claim() -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle()

    bundle.assert_contract_profile(TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED)
    assert bundle.policy_version == P4G_CHECKPOINT_EXTERNAL_CONTRACT_POLICY_VERSION
    assert bundle.production_runtime_eligible() is False
    assert all(item["synthetic_in_process"] is True for item in bundle.public_posture())
    assert all(item["operationally_external"] is False for item in bundle.public_posture())


def test_external_style_crypto_contract_uses_operations_without_raw_key_export_api() -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    aad = b"synthetic-p4g-test-aad"
    plaintext = b"synthetic-p4g-test-payload"

    ciphertext = bundle.encryption.encrypt(plaintext, aad=aad)
    assert ciphertext != plaintext
    assert bundle.encryption.decrypt(ciphertext, aad=aad) == plaintext
    authenticator = bundle.integrity.authenticate(ciphertext)
    assert bundle.integrity.verify(ciphertext, authenticator) is True
    assert hasattr(bundle.encryption, "key") is False
    assert hasattr(bundle.encryption, "export_key") is False
    assert hasattr(bundle.integrity, "key") is False
    assert hasattr(bundle.backup_authentication, "key") is False


def test_adapter_provider_id_mismatch_fails_closed() -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    mismatched = replace(
        bundle,
        encryption=SyntheticExternalStyleCheckpointEncryptionAdapter(
            provider_id="synthetic-external-contract-wrong-encryption"
        ),
    )

    with pytest.raises(CheckpointExternalContractError) as raised:
        mismatched.assert_contract_profile(
            TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED
        )

    assert raised.value.reason is CheckpointExternalContractReason.ADAPTER_PROVIDER_ID_MISMATCH


def test_key_custody_capability_mismatch_fails_closed() -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle(
        encryption_external_key_custody=False
    )

    with pytest.raises(CheckpointExternalContractError) as raised:
        bundle.assert_contract_profile(TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED)

    assert raised.value.reason is CheckpointExternalContractReason.EXTERNAL_KEY_CUSTODY_REQUIRED


def test_monotonic_anchor_rejects_rollback_and_allows_forward_progress() -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    bundle.anchor.advance(
        "thread-one",
        generation=1,
        checkpoint_id="checkpoint-one",
        checkpoint_digest="digest-one",
        expected_generation=None,
    )
    head = bundle.anchor.advance(
        "thread-one",
        generation=2,
        checkpoint_id="checkpoint-two",
        checkpoint_digest="digest-two",
        expected_generation=1,
    )
    assert head.generation == 2

    with pytest.raises(CheckpointExternalContractError) as raised:
        bundle.anchor.advance(
            "thread-one",
            generation=1,
            checkpoint_id="checkpoint-rollback",
            checkpoint_digest="digest-rollback",
            expected_generation=2,
        )

    assert raised.value.reason is CheckpointExternalContractReason.ANCHOR_ROLLBACK_REJECTED
    assert bundle.anchor.current_head("thread-one") == head


def test_backup_authentication_and_recovery_authority_fail_closed() -> None:
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    payload = b"synthetic-backup-manifest"
    authenticator = bundle.backup_authentication.authenticate(payload)
    bundle.backup_authentication.verify_or_raise(payload, authenticator)

    with pytest.raises(CheckpointExternalContractError) as tampered:
        bundle.backup_authentication.verify_or_raise(
            b"synthetic-backup-manifest-tampered",
            authenticator,
        )
    assert tampered.value.reason is CheckpointExternalContractReason.BACKUP_AUTHENTICATION_FAILED

    with pytest.raises(CheckpointExternalContractError) as bypass:
        bundle.recovery_authority.authorize_restore(
            RecoveryAuthorizationRequest(
                request_id="synthetic-bypass",
                operator_id="synthetic-recovery-operator",
                backup_authenticated=False,
                monotonic_anchor_verified=True,
            )
        )
    assert bypass.value.reason is CheckpointExternalContractReason.RECOVERY_AUTHORIZATION_DENIED

    bundle.recovery_authority.authorize_restore(
        RecoveryAuthorizationRequest(
            request_id="synthetic-authorized",
            operator_id="synthetic-recovery-operator",
            backup_authenticated=True,
            monotonic_anchor_verified=True,
        )
    )


def test_p4g_evaluation_exact_metrics_and_evidence_hygiene() -> None:
    report = build_report()
    assert report["passed"] is True
    baseline = report["variants"]["manifest_only_external_contract_baseline"]["metrics"]
    hardened = report["variants"]["operation_bearing_adapter_contract_harness"]["metrics"]
    assert baseline["asr"] == [5, 5]
    assert hardened["asr"] == [0, 5]
    assert hardened["fpr"] == [0, 3]
    assert hardened["safe_task_rate"] == [3, 3]
    assert report["p4f_production_profile_contract_accepted"] is True
    assert report["production_runtime_eligible"] is False
    assert report["production_external_adapter_implementation_included"] is False
    assert report["raw_key_export_api_present"] is False
    assert report["raw_key_bytes_in_report"] is False
    assert report["real_external_trust_operations"] is False
    assert report["network_operations"] == 0
    assert report["production_checkpoint_runtime_claim"] is False
