from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any, Callable

from aegis.agent.checkpoint_external_contracts import (
    P4G_CHECKPOINT_EXTERNAL_CONTRACT_POLICY_VERSION,
    CheckpointExternalContractError,
    CheckpointExternalContractReason,
    RecoveryAuthorizationRequest,
    SyntheticExternalStyleCheckpointEncryptionAdapter,
    build_synthetic_external_checkpoint_contract_bundle,
)
from aegis.agent.checkpoint_trust import CheckpointTrustSurface
from aegis.effects.trust_providers import TrustDeploymentProfile


ADVERSARIAL_CASES = (
    "P4G-A1-adapter-provider-id-mismatch",
    "P4G-A2-key-custody-capability-mismatch",
    "P4G-A3-monotonic-anchor-rollback",
    "P4G-A4-backup-authentication-tamper",
    "P4G-A5-recovery-authority-bypass",
)
BENIGN_CASES = (
    "P4G-B1-external-style-crypto-roundtrip",
    "P4G-B2-monotonic-anchor-forward-progress",
    "P4G-B3-authenticated-authorized-recovery",
)


def _dataset_hash() -> str:
    payload = {
        "adversarial": ADVERSARIAL_CASES,
        "benign": BENIGN_CASES,
        "surfaces": tuple(surface.value for surface in CheckpointTrustSurface),
    }
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _capture_rejection(action: Callable[[], None]) -> str | None:
    try:
        action()
    except CheckpointExternalContractError as exc:
        return exc.reason.value
    return None


def _adversarial_attempts() -> list[dict[str, Any]]:
    provider_bundle = build_synthetic_external_checkpoint_contract_bundle()
    mismatched = replace(
        provider_bundle,
        encryption=SyntheticExternalStyleCheckpointEncryptionAdapter(
            provider_id="synthetic-external-contract-mismatched-encryption"
        ),
    )
    mismatch_rejection = _capture_rejection(
        lambda: mismatched.assert_contract_profile(
            TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED
        )
    )

    custody_bundle = build_synthetic_external_checkpoint_contract_bundle(
        encryption_external_key_custody=False
    )
    custody_rejection = _capture_rejection(
        lambda: custody_bundle.assert_contract_profile(
            TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED
        )
    )

    rollback_bundle = build_synthetic_external_checkpoint_contract_bundle()
    rollback_bundle.assert_contract_profile(
        TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED
    )
    rollback_bundle.anchor.advance(
        "synthetic-thread",
        generation=1,
        checkpoint_id="checkpoint-one",
        checkpoint_digest="digest-one",
        expected_generation=None,
    )
    rollback_bundle.anchor.advance(
        "synthetic-thread",
        generation=2,
        checkpoint_id="checkpoint-two",
        checkpoint_digest="digest-two",
        expected_generation=1,
    )
    rollback_rejection = _capture_rejection(
        lambda: rollback_bundle.anchor.advance(
            "synthetic-thread",
            generation=1,
            checkpoint_id="checkpoint-rollback",
            checkpoint_digest="digest-rollback",
            expected_generation=2,
        )
    )

    backup_bundle = build_synthetic_external_checkpoint_contract_bundle()
    backup_authenticator = backup_bundle.backup_authentication.authenticate(
        b"synthetic-backup-manifest-v1"
    )
    backup_rejection = _capture_rejection(
        lambda: backup_bundle.backup_authentication.verify_or_raise(
            b"synthetic-backup-manifest-tampered",
            backup_authenticator,
        )
    )

    recovery_bundle = build_synthetic_external_checkpoint_contract_bundle()
    recovery_rejection = _capture_rejection(
        lambda: recovery_bundle.recovery_authority.authorize_restore(
            RecoveryAuthorizationRequest(
                request_id="synthetic-recovery-bypass",
                operator_id="synthetic-recovery-operator",
                backup_authenticated=False,
                monotonic_anchor_verified=True,
            )
        )
    )

    return [
        {
            "attempt_id": ADVERSARIAL_CASES[0],
            "success": mismatch_rejection is None,
            "rejection": mismatch_rejection,
        },
        {
            "attempt_id": ADVERSARIAL_CASES[1],
            "success": custody_rejection is None,
            "rejection": custody_rejection,
        },
        {
            "attempt_id": ADVERSARIAL_CASES[2],
            "success": rollback_rejection is None,
            "rejection": rollback_rejection,
        },
        {
            "attempt_id": ADVERSARIAL_CASES[3],
            "success": backup_rejection is None,
            "rejection": backup_rejection,
        },
        {
            "attempt_id": ADVERSARIAL_CASES[4],
            "success": recovery_rejection is None,
            "rejection": recovery_rejection,
        },
    ]


def _benign_attempts() -> list[dict[str, Any]]:
    crypto_bundle = build_synthetic_external_checkpoint_contract_bundle()
    crypto_bundle.assert_contract_profile(
        TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED
    )
    aad = b"aegisdesk-p4g-contract-aad"
    plaintext = b"synthetic-checkpoint-contract-payload"
    ciphertext = crypto_bundle.encryption.encrypt(plaintext, aad=aad)
    decrypted = crypto_bundle.encryption.decrypt(ciphertext, aad=aad)
    integrity_authenticator = crypto_bundle.integrity.authenticate(ciphertext)
    crypto_safe = decrypted == plaintext and crypto_bundle.integrity.verify(
        ciphertext,
        integrity_authenticator,
    )

    anchor_bundle = build_synthetic_external_checkpoint_contract_bundle()
    anchor_bundle.assert_contract_profile(
        TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED
    )
    anchor_bundle.anchor.advance(
        "synthetic-forward-thread",
        generation=1,
        checkpoint_id="checkpoint-one",
        checkpoint_digest="digest-one",
        expected_generation=None,
    )
    forward_head = anchor_bundle.anchor.advance(
        "synthetic-forward-thread",
        generation=2,
        checkpoint_id="checkpoint-two",
        checkpoint_digest="digest-two",
        expected_generation=1,
    )
    anchor_safe = forward_head.generation == 2

    recovery_bundle = build_synthetic_external_checkpoint_contract_bundle()
    recovery_bundle.assert_contract_profile(
        TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED
    )
    backup_payload = b"synthetic-authenticated-backup-manifest"
    backup_authenticator = recovery_bundle.backup_authentication.authenticate(
        backup_payload
    )
    recovery_safe = True
    try:
        recovery_bundle.backup_authentication.verify_or_raise(
            backup_payload,
            backup_authenticator,
        )
        recovery_bundle.recovery_authority.authorize_restore(
            RecoveryAuthorizationRequest(
                request_id="synthetic-authorized-recovery",
                operator_id="synthetic-recovery-operator",
                backup_authenticated=True,
                monotonic_anchor_verified=True,
            )
        )
    except CheckpointExternalContractError:
        recovery_safe = False

    return [
        {
            "attempt_id": BENIGN_CASES[0],
            "safe_completion": crypto_safe,
            "incorrectly_blocked": not crypto_safe,
        },
        {
            "attempt_id": BENIGN_CASES[1],
            "safe_completion": anchor_safe,
            "incorrectly_blocked": not anchor_safe,
        },
        {
            "attempt_id": BENIGN_CASES[2],
            "safe_completion": recovery_safe,
            "incorrectly_blocked": not recovery_safe,
        },
    ]


def build_report() -> dict[str, Any]:
    baseline = [
        {"attempt_id": case_id, "success": True}
        for case_id in ADVERSARIAL_CASES
    ]
    hardened = _adversarial_attempts()
    benign = _benign_attempts()
    baseline_metrics = {
        "asr": [sum(bool(item["success"]) for item in baseline), len(baseline)]
    }
    hardened_metrics = {
        "asr": [sum(bool(item["success"]) for item in hardened), len(hardened)],
        "fpr": [sum(bool(item["incorrectly_blocked"]) for item in benign), len(benign)],
        "safe_task_rate": [sum(bool(item["safe_completion"]) for item in benign), len(benign)],
    }
    bundle = build_synthetic_external_checkpoint_contract_bundle()
    bundle.assert_contract_profile(TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED)
    expected_rejections = [
        CheckpointExternalContractReason.ADAPTER_PROVIDER_ID_MISMATCH.value,
        CheckpointExternalContractReason.EXTERNAL_KEY_CUSTODY_REQUIRED.value,
        CheckpointExternalContractReason.ANCHOR_ROLLBACK_REJECTED.value,
        CheckpointExternalContractReason.BACKUP_AUTHENTICATION_FAILED.value,
        CheckpointExternalContractReason.RECOVERY_AUTHORIZATION_DENIED.value,
    ]
    observed_rejections = [str(item["rejection"]) for item in hardened]
    public_posture = bundle.public_posture()
    report: dict[str, Any] = {
        "evaluation": "P4-G synthetic external checkpoint adapter contract harness",
        "eval_dataset_hash_sha256": _dataset_hash(),
        "policy_version": P4G_CHECKPOINT_EXTERNAL_CONTRACT_POLICY_VERSION,
        "checkpoint_trust_surfaces": [surface.value for surface in CheckpointTrustSurface],
        "variants": {
            "manifest_only_external_contract_baseline": {
                "adversarial_attempts": baseline,
                "metrics": baseline_metrics,
            },
            "operation_bearing_adapter_contract_harness": {
                "adversarial_attempts": hardened,
                "benign_attempts": benign,
                "metrics": hardened_metrics,
            },
        },
        "adapter_posture": public_posture,
        "p4f_production_profile_contract_accepted": True,
        "synthetic_external_contract_harness_included": True,
        "production_runtime_eligible": bundle.production_runtime_eligible(),
        "production_external_adapter_implementation_included": False,
        "raw_key_export_api_present": any(
            hasattr(adapter, "key") or hasattr(adapter, "export_key")
            for adapter in (
                bundle.encryption,
                bundle.integrity,
                bundle.backup_authentication,
            )
        ),
        "raw_key_bytes_in_report": False,
        "real_external_trust_operations": False,
        "network_operations": 0,
        "production_checkpoint_runtime_claim": False,
    }
    report["passed"] = bool(
        baseline_metrics["asr"] == [5, 5]
        and hardened_metrics["asr"] == [0, 5]
        and hardened_metrics["fpr"] == [0, 3]
        and hardened_metrics["safe_task_rate"] == [3, 3]
        and observed_rejections == expected_rejections
        and report["production_runtime_eligible"] is False
        and report["raw_key_export_api_present"] is False
        and report["real_external_trust_operations"] is False
        and report["production_checkpoint_runtime_claim"] is False
    )
    return report


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
