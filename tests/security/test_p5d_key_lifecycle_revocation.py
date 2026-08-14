from __future__ import annotations

import pytest

from aegis.model_supply_chain.key_lifecycle import (
    KeyLifecycleRejected,
    KeyLifecycleRejectReason,
    LifecycleRestrictedModelPackageLoader,
)
from evals.p5d_key_lifecycle_revocation import (
    BENIGN_ATTEMPTS,
    _attack_case,
    _benign_case,
    _policy,
    dataset_sha256,
    fixture_sha256,
    run_evaluation,
)


EXPECTED_DATASET_SHA256 = "3cb29e261f27df97b468e2878752d33104dc475d237c7481e8c72e42890772f9"
EXPECTED_FIXTURE_SHA256 = "d263c288db5c83789eaa7898f78a819873e0c4fa36f2bc7d638e8526f47b8726"


def _reject_reason(scenario: str) -> KeyLifecycleRejectReason:
    request, manifest, package_signature, artifacts = _attack_case(scenario)
    with pytest.raises(KeyLifecycleRejected) as caught:
        LifecycleRestrictedModelPackageLoader(_policy()).load(
            request=request,
            manifest=manifest,
            package_signature=package_signature,
            artifacts=artifacts,
        )
    return caught.value.reason


def test_all_benign_rotation_states_accept_with_nonexecuting_verified_handle() -> None:
    loader = LifecycleRestrictedModelPackageLoader(_policy())
    for attempt in BENIGN_ATTEMPTS:
        request, manifest, package_signature, artifacts = _benign_case(attempt.scenario)
        handle = loader.load(
            request=request,
            manifest=manifest,
            package_signature=package_signature,
            artifacts=artifacts,
        )
        assert handle.key_lifecycle_verified is True
        assert handle.current_key_policy_verified is True
        assert handle.revocation_checked is True
        assert handle.deserialized is False
        assert handle.code_execution_capable is False
        assert handle.network_operations == 0


def test_expired_artifact_key_rejected_even_when_signature_was_created_in_window() -> None:
    assert _reject_reason("expired_artifact_key") is KeyLifecycleRejectReason.KEY_EXPIRED


def test_revoked_artifact_key_rejected_even_for_pre_revocation_signature() -> None:
    assert _reject_reason("revoked_artifact_key") is KeyLifecycleRejectReason.KEY_REVOKED


def test_retired_artifact_predecessor_rejected_after_rotation_cutover() -> None:
    assert _reject_reason("retired_artifact_key") is KeyLifecycleRejectReason.KEY_RETIRED


def test_future_artifact_key_rejected_before_activation() -> None:
    assert _reject_reason("future_artifact_key") is KeyLifecycleRejectReason.KEY_NOT_YET_VALID


def test_revoked_and_retired_package_keys_rejected() -> None:
    assert _reject_reason("revoked_package_key") is KeyLifecycleRejectReason.KEY_REVOKED
    assert _reject_reason("retired_package_key") is KeyLifecycleRejectReason.KEY_RETIRED


def test_unknown_key_and_untrusted_issuer_rejected() -> None:
    assert _reject_reason("unknown_package_key") is KeyLifecycleRejectReason.KEY_UNKNOWN
    assert _reject_reason("untrusted_issuer") is KeyLifecycleRejectReason.ISSUER_UNTRUSTED


def test_usage_scoping_prevents_artifact_key_from_signing_package() -> None:
    assert _reject_reason("package_usage_confusion") is KeyLifecycleRejectReason.USAGE_MISMATCH


def test_publisher_binding_is_enforced() -> None:
    assert _reject_reason("publisher_binding_mismatch") is KeyLifecycleRejectReason.PUBLISHER_MISMATCH


def test_key_id_metadata_is_cryptographically_bound() -> None:
    assert _reject_reason("key_id_substitution") is KeyLifecycleRejectReason.SIGNATURE_INVALID


def test_subject_digest_is_cryptographically_bound() -> None:
    assert _reject_reason("subject_binding_mismatch") is KeyLifecycleRejectReason.SUBJECT_MISMATCH


def test_deterministic_security_delta_and_evidence_hashes_are_stable() -> None:
    report = run_evaluation()
    assert report["metrics"] == {
        "vulnerable_asr": "12/12",
        "hardened_asr": "0/12",
        "hardened_fpr": "0/3",
        "safe_task_rate": "3/3",
    }
    assert dataset_sha256() == EXPECTED_DATASET_SHA256
    assert fixture_sha256() == EXPECTED_FIXTURE_SHA256
    assert report["dataset_sha256"] == EXPECTED_DATASET_SHA256
    assert report["fixture_sha256"] == EXPECTED_FIXTURE_SHA256
    assert report["evidence_hygiene"]["network_operations"] == 0
    assert report["evidence_hygiene"]["fixture_payloads_inert"] is True
