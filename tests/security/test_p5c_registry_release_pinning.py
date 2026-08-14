from __future__ import annotations

import pytest

from aegis.model_supply_chain.registry_acquisition import (
    ImmutableModelRegistryAcquirer,
    RegistryAcquisitionRejected,
    RegistryAcquisitionRejectReason,
    RegistryReleaseCache,
    registry_release_digest,
)
from evals.p5c_registry_release_pinning import (
    _attack_cases,
    _benign_cases,
    _package_loader,
    _release_envelope,
)


def _acquire(case):
    return ImmutableModelRegistryAcquirer(
        policy=case["policy"],
        package_loader=_package_loader(),
        cache=case["cache"],
    ).acquire(pin=case["pin"], transport=case["transport"])


def test_release_digest_is_deterministic_and_content_addressed() -> None:
    first = _release_envelope()
    second = _release_envelope()
    assert registry_release_digest(first) == registry_release_digest(second)
    assert len(registry_release_digest(first)) == 64


def test_exact_pinned_release_is_accepted() -> None:
    case = _benign_cases()[0]
    result = _acquire(case)
    assert result.release_digest == case["pin"].release_digest
    assert result.package.package_id == case["pin"].package_id
    assert result.digest_addressed is True
    assert result.code_execution_capable is False


@pytest.mark.parametrize(
    ("index", "reason"),
    [
        (0, RegistryAcquisitionRejectReason.TAG_DRIFT),
        (1, RegistryAcquisitionRejectReason.CHANNEL_UNPINNED),
        (2, RegistryAcquisitionRejectReason.REGISTRY_UNTRUSTED),
        (3, RegistryAcquisitionRejectReason.SOURCE_UNTRUSTED),
        (4, RegistryAcquisitionRejectReason.REDIRECT_UNTRUSTED),
        (5, RegistryAcquisitionRejectReason.RELEASE_DIGEST_MISMATCH),
        (6, RegistryAcquisitionRejectReason.CACHE_DIGEST_MISMATCH),
        (7, RegistryAcquisitionRejectReason.RELEASE_IDENTITY_MISMATCH),
    ],
)
def test_registry_acquisition_attacks_fail_closed(
    index: int,
    reason: RegistryAcquisitionRejectReason,
) -> None:
    case = _attack_cases()[index]
    with pytest.raises(RegistryAcquisitionRejected) as exc:
        _acquire(case)
    assert exc.value.reason is reason


def test_trusted_redirect_is_accepted_only_when_policy_allows_it() -> None:
    case = _benign_cases()[1]
    result = _acquire(case)
    assert result.redirect_count == 1
    assert result.source.startswith("registry://aegis-model-mirror/immutable/")


def test_verified_warm_cache_is_rehashed_and_avoids_fetch() -> None:
    case = _benign_cases()[2]
    result = _acquire(case)
    assert result.cache_verified is True
    assert case["transport"].fetch_calls == 0


def test_cache_substitution_is_detected_before_package_handoff() -> None:
    case = _attack_cases()[6]
    assert isinstance(case["cache"], RegistryReleaseCache)
    with pytest.raises(RegistryAcquisitionRejected) as exc:
        _acquire(case)
    assert exc.value.reason is RegistryAcquisitionRejectReason.CACHE_DIGEST_MISMATCH
