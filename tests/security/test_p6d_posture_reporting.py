from dataclasses import replace

import pytest

from aegis.assurance.posture_reporting import (
    AISecurityPostureReporter,
    PostureRating,
    SecurityPostureRejected,
    canonical_control_catalog_bytes,
    control_catalog_digest,
)
from evals.p6d_posture_reporting import (
    adversarial_cases,
    benign_cases,
    build_catalog,
    default_fixture,
)


@pytest.mark.parametrize("name,expected_reason,overrides", adversarial_cases())
def test_adversarial_cases_fail_closed(name, expected_reason, overrides):
    base = default_fixture()
    corpus = overrides.get("corpus", base["corpus"])
    catalog = overrides.get("catalog", base["catalog"])
    policy = overrides.get("policy", base["policy"])
    request = overrides.get("request", base["request"])
    waiver = overrides.get("waiver", base["waiver"])
    evolution = overrides.get("evolution", base["evolution"])

    with pytest.raises(SecurityPostureRejected) as exc:
        AISecurityPostureReporter(catalog=catalog, policy=policy).evaluate(
            request=request,
            corpus=corpus,
            waiver_governance=waiver,
            corpus_evolution=evolution,
        )
    assert exc.value.reason == expected_reason


@pytest.mark.parametrize("name,overrides", benign_cases())
def test_benign_cases_remain_green(name, overrides):
    base = default_fixture()
    corpus = overrides.get("corpus", base["corpus"])
    catalog = overrides.get("catalog", base["catalog"])
    policy = overrides.get("policy", base["policy"])
    request = overrides.get("request", base["request"])
    waiver = overrides.get("waiver", base["waiver"])
    evolution = overrides.get("evolution", base["evolution"])

    verified = AISecurityPostureReporter(catalog=catalog, policy=policy).evaluate(
        request=request,
        corpus=corpus,
        waiver_governance=waiver,
        corpus_evolution=evolution,
    )
    assert verified.overall_rating == PostureRating.GREEN
    assert verified.caller_declared_green_trusted is False
    assert verified.regulatory_certification is False
    assert verified.production_grc_integration is False
    assert verified.network_operations == 0


def test_catalog_digest_is_order_independent():
    catalog = build_catalog()
    reordered = replace(catalog, controls=tuple(reversed(catalog.controls)))
    assert control_catalog_digest(catalog) == control_catalog_digest(reordered)


def test_catalog_canonical_bytes_are_stable():
    catalog = build_catalog()
    first = canonical_control_catalog_bytes(catalog)
    second = canonical_control_catalog_bytes(catalog)
    assert first == second
    assert len(control_catalog_digest(catalog)) == 64
