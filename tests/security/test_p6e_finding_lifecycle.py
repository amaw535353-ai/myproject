from dataclasses import replace

import pytest

from aegis.assurance.finding_lifecycle import (
    AdversarialFindingLifecycleGate,
    FindingLifecycleRejected,
    FindingState,
    canonical_finding_bytes,
    canonical_retest_bytes,
    finding_digest,
    retest_digest,
)
from evals.p6e_finding_lifecycle import (
    adversarial_cases,
    benign_cases,
    default_fixture,
)


@pytest.mark.parametrize("name,expected_reason,overrides", adversarial_cases())
def test_adversarial_finding_lifecycle_cases_fail_closed(name, expected_reason, overrides):
    base = default_fixture()
    corpus = overrides.get("corpus", base["corpus"])
    registry = overrides.get("registry", base["registry"])
    policy = overrides.get("policy", base["policy"])
    previous = overrides.get("previous", base["previous"])
    proposed = overrides.get("proposed", base["proposed"])
    retest = overrides.get("retest", base["retest"])
    request = overrides.get("request", base["request"])

    with pytest.raises(FindingLifecycleRejected) as exc:
        AdversarialFindingLifecycleGate(
            corpus=corpus,
            invariant_registry=registry,
            policy=policy,
        ).evaluate(
            request=request,
            previous=previous,
            proposed=proposed,
            retest=retest,
        )
    assert exc.value.reason == expected_reason


@pytest.mark.parametrize("name,overrides", benign_cases())
def test_benign_finding_lifecycle_transitions_pass(name, overrides):
    base = default_fixture()
    verified = AdversarialFindingLifecycleGate(
        corpus=base["corpus"],
        invariant_registry=base["registry"],
        policy=base["policy"],
    ).evaluate(
        request=overrides["request"],
        previous=overrides["previous"],
        proposed=overrides["proposed"],
        retest=overrides["retest"],
    )
    assert verified.current_version == verified.previous_version + 1
    assert verified.caller_declared_closed_trusted is False
    assert verified.production_ticket_integration is False
    assert verified.production_patch_deployment is False
    assert verified.exhaustive_finding_discovery is False
    assert verified.network_operations == 0
    if verified.current_state == FindingState.CLOSED:
        assert verified.closure_verified is True
        assert verified.retest_evidence_sha256 is not None
    else:
        assert verified.closure_verified is False
        assert verified.retest_evidence_sha256 is None


def test_finding_canonicalization_is_stable():
    finding = default_fixture()["previous"]
    assert canonical_finding_bytes(finding) == canonical_finding_bytes(finding)
    assert len(finding_digest(finding)) == 64


def test_retest_canonicalization_is_order_independent():
    retest = default_fixture()["retest"]
    reordered = replace(retest, results=tuple(reversed(retest.results)))
    assert canonical_retest_bytes(retest) == canonical_retest_bytes(reordered)
    assert retest_digest(retest) == retest_digest(reordered)
