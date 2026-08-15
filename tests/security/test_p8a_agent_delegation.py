from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.agentic.delegation_security import (
    DelegationDecision,
    DelegationRejectReason,
    DelegationRisk,
    DelegationSecurityRejected,
    MultiAgentDelegationSecurityAnalyzer,
    agent_delegation_manifest_digest,
)
from evals.p8a_agent_delegation import (
    ADVERSARIAL_CASES,
    EXPECTED_ADVERSARIAL_CASES,
    _clone,
    _hardened_attack_succeeds,
    benign_contexts,
    run,
)
from evals.p8a_fixture import (
    AGENT_RETRIEVAL_A,
    CAP_TOOL_WRITE,
    NOW,
    build_fixture,
    make_upstreams,
    replace_manifest_item,
    truthful_request_for_context,
)


def evaluate(ctx):
    return MultiAgentDelegationSecurityAnalyzer(ctx["policy"]).evaluate(
        ctx["request"], ctx["manifest"], ctx["p7b"], ctx["p7h"], ctx["p7i"]
    )


def test_baseline_all_delegations_allowed():
    result = evaluate(build_fixture())
    assert result.delegation_count == 7
    assert result.allowed_delegation_count == 7
    assert result.denied_delegation_count == 0
    assert result.cross_tenant_denial_count == 0
    assert result.confused_deputy_denial_count == 0
    assert result.capability_laundering_denial_count == 0
    assert result.scope_amplification_denial_count == 0
    assert result.network_operations == 0


def test_graph_digest_is_deterministic():
    ctx = build_fixture()
    assert agent_delegation_manifest_digest(ctx["manifest"]) == ctx["request"].graph_sha256
    assert ctx["request"].graph_sha256 == "874a38e5df60b79c2a04ba451e6785b3712afe1e353951d3f0572f074f157b71"


def test_all_adversarial_cases_fail_closed():
    assert len(ADVERSARIAL_CASES) == EXPECTED_ADVERSARIAL_CASES == 90
    failures = [case_id for case_id, mutation in ADVERSARIAL_CASES if _hardened_attack_succeeds(mutation(_clone()))]
    assert failures == []


def test_evaluator_metrics_and_hashes_are_exact():
    result = run()
    assert result["adversarial_cases"] == 90
    assert result["vulnerable_asr"] == "90/90"
    assert result["hardened_asr"] == "0/90"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
    assert result["graph_sha256"] == "874a38e5df60b79c2a04ba451e6785b3712afe1e353951d3f0572f074f157b71"
    assert result["dataset_sha256"] == "a389f31f79d1b2754a0689aa6acb0ea7ed125fe42679ddc0dd51ecaae87e1d11"
    assert result["fixture_sha256"] == "9a095c128f9f24a2df963bdcd6077c72e2ab7953792f8183f4436d620c8e7e07"


def test_truthful_cross_tenant_handoff_is_processed_and_denied():
    ctx = dict(benign_contexts()[1][1])
    result = evaluate(ctx)
    assert result.denied_delegation_count == 1
    fact = next(item for item in result.delegations if item.delegation_id == "delegation-retrieval")
    assert fact.decision == DelegationDecision.DENY
    assert fact.risks == (DelegationRisk.CROSS_TENANT,)
    assert result.cross_tenant_denial_count == 1


def test_truthful_capability_laundering_is_processed_and_denied():
    ctx = dict(benign_contexts()[2][1])
    result = evaluate(ctx)
    assert result.denied_delegation_count == 1
    fact = next(item for item in result.delegations if item.delegation_id == "delegation-tool-child")
    assert fact.decision == DelegationDecision.DENY
    assert fact.risks == (DelegationRisk.CAPABILITY_LAUNDERING,)
    assert fact.chain_depth == 2
    assert result.capability_laundering_denial_count == 1


def test_original_principal_authority_prevents_confused_deputy():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(
        ctx["manifest"],
        "delegations",
        "delegation-retrieval",
        original_principal_id="user-limited",
        task_class="tool_lookup",
        requested_capability_ids=(CAP_TOOL_WRITE,),
    )
    digest = agent_delegation_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    with pytest.raises(DelegationSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == DelegationRejectReason.DECLARED_DECISION_MISMATCH


def test_exposed_p7h_route_blocks_privileged_release_delegation():
    ctx = build_fixture()
    ctx.update(make_upstreams(exposed_p7h_routes=frozenset({"route-release-promote"})))
    with pytest.raises(DelegationSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == DelegationRejectReason.DECLARED_DECISION_MISMATCH


def test_unsafe_p7i_invariant_blocks_delegation():
    ctx = build_fixture()
    ctx.update(make_upstreams(unsafe_p7i_invariants=frozenset({"INV-ADMIN-NON-SELF-BYPASS"})))
    with pytest.raises(DelegationSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == DelegationRejectReason.DECLARED_DECISION_MISMATCH


def test_expired_delegation_is_not_silently_allowed():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "delegations", "delegation-retrieval", expires_at_epoch=NOW - 1)
    digest = agent_delegation_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    with pytest.raises(DelegationSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == DelegationRejectReason.DECLARED_DECISION_MISMATCH


def test_delegatee_must_accept_delegation_even_if_graph_is_re_pinned():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "agents", AGENT_RETRIEVAL_A, accepts_delegation=False)
    accepts = dict(ctx["policy"].expected_agent_accepts_delegation)
    accepts[AGENT_RETRIEVAL_A] = False
    digest = agent_delegation_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_agent_accepts_delegation=accepts, expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    with pytest.raises(DelegationSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == DelegationRejectReason.DECLARED_DECISION_MISMATCH


def test_caller_risk_map_must_cover_every_delegation():
    ctx = build_fixture()
    risk_map = dict(ctx["request"].declared_risk_ids_by_delegation)
    risk_map.pop("delegation-retrieval")
    ctx["request"] = replace(ctx["request"], declared_risk_ids_by_delegation=risk_map)
    with pytest.raises(DelegationSecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == DelegationRejectReason.DECLARED_RISK_MISMATCH


def test_claim_boundary_flags_are_explicit():
    result = evaluate(build_fixture())
    assert result.caller_declared_delegation_authorization_trusted is False
    assert result.production_agent_identity_attestation is False
    assert result.production_multi_agent_protocol_enforcement is False
    assert result.production_iam_enforcement is False
    assert result.cryptographic_delegation_tokens is False
    assert result.exhaustive_agent_behavior_coverage is False
    assert result.formal_delegation_proof is False
