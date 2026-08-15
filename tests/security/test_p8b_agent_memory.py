from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.agentic.memory_security import (
    AgentMemoryContextSecurityAnalyzer,
    MemoryDecision,
    MemoryRejectReason,
    MemoryRisk,
    MemorySecurityRejected,
    MemoryTrust,
    agent_memory_manifest_digest,
)
from evals.p8b_agent_memory import (
    ADVERSARIAL_CASES,
    _clone,
    _hardened_attack_succeeds,
    benign_contexts,
    run,
)
from evals.p8b_fixture import (
    DELEGATION_RETRIEVAL,
    INV_TENANT,
    MEM_CURRENT_PROFILE,
    MEM_RETRIEVAL_SUMMARY,
    MEM_SESSION_QUERY,
    NOW,
    P7C_PATH_TENANT,
    RETRIEVE_PROFILE,
    RETRIEVE_SESSION,
    RETRIEVE_SUMMARY,
    WRITE_RETRIEVAL_SUMMARY,
    build_fixture,
    make_upstreams,
    replace_manifest_item,
    truthful_request_for_context,
)


def evaluate(ctx):
    return AgentMemoryContextSecurityAnalyzer(ctx["policy"]).evaluate(
        ctx["request"], ctx["manifest"], ctx["p8a"], ctx["p7c"], ctx["p7i"]
    )


def repin(ctx):
    digest = agent_memory_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    return ctx


def test_baseline_memory_graph_is_allowed():
    result = evaluate(build_fixture())
    assert result.write_count == 6
    assert result.allowed_write_count == 6
    assert result.denied_write_count == 0
    assert result.retrieval_count == 4
    assert result.allowed_retrieval_count == 4
    assert result.denied_retrieval_count == 0
    assert result.network_operations == 0


def test_memory_graph_digest_is_deterministic():
    ctx = build_fixture()
    assert agent_memory_manifest_digest(ctx["manifest"]) == ctx["request"].graph_sha256
    assert ctx["request"].graph_sha256 == "7bb96cd8d40a57419bd2ec4bf31fcbdd38db05d512f2eadff410f522886b54ff"


def test_evaluator_metrics_and_hashes_are_exact():
    result = run()
    assert result["adversarial_cases"] == 126
    assert result["vulnerable_asr"] == "126/126"
    assert result["hardened_asr"] == "0/126"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
    assert result["graph_sha256"] == "7bb96cd8d40a57419bd2ec4bf31fcbdd38db05d512f2eadff410f522886b54ff"
    assert result["dataset_sha256"] == "f047bce2916ff0d745c0258b61db9205597afbfae80416a4f4bd01dc80b983fb"
    assert result["fixture_sha256"] == "a151395b84d35ff3ac40755372478bbfbcfb9a1a7e2754a0db3966104a930d9b"


def test_all_adversarial_cases_fail_closed():
    failures = [case_id for case_id, mutation in ADVERSARIAL_CASES if _hardened_attack_succeeds(mutation(_clone()))]
    assert failures == []


def test_truthful_memory_laundering_is_processed_and_denied():
    ctx = dict(benign_contexts()[1][1])
    result = evaluate(ctx)
    assert result.denied_write_count == 1
    fact = next(item for item in result.writes if item.write_id == "write-tenant-tool-note")
    assert fact.decision == MemoryDecision.DENY
    assert fact.risks == (
        MemoryRisk.MEMORY_LAUNDERING,
        MemoryRisk.TRUST_UPGRADE,
        MemoryRisk.CLASSIFICATION_DOWNGRADE,
    )
    assert result.memory_laundering_denial_count == 1


def test_truthful_revoked_memory_is_processed_and_denied():
    ctx = dict(benign_contexts()[2][1])
    result = evaluate(ctx)
    assert result.denied_retrieval_count == 1
    fact = next(item for item in result.retrievals if item.retrieval_id == RETRIEVE_PROFILE)
    assert fact.decision == MemoryDecision.DENY
    assert fact.risks == (MemoryRisk.REVOKED_MEMORY,)
    assert result.revoked_or_superseded_denial_count == 1


def test_cross_session_retrieval_cannot_be_hidden():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "retrievals", RETRIEVE_SESSION, session_id="session-a-2")
    repin(ctx)
    with pytest.raises(MemorySecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == MemoryRejectReason.DECLARED_DECISION_MISMATCH


def test_denied_p8a_delegation_blocks_delegated_memory_write():
    ctx = build_fixture()
    ctx.update(make_upstreams(denied_delegations=frozenset({DELEGATION_RETRIEVAL})))
    with pytest.raises(MemorySecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == MemoryRejectReason.DECLARED_DECISION_MISMATCH


def test_exposed_p7c_path_blocks_memory_use():
    ctx = build_fixture()
    ctx.update(make_upstreams(exposed_p7c_paths=frozenset({P7C_PATH_TENANT})))
    with pytest.raises(MemorySecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == MemoryRejectReason.DECLARED_DECISION_MISMATCH


def test_unsafe_p7i_invariant_blocks_memory_use():
    ctx = build_fixture()
    ctx.update(make_upstreams(unsafe_p7i_invariants=frozenset({INV_TENANT})))
    with pytest.raises(MemorySecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == MemoryRejectReason.DECLARED_DECISION_MISMATCH


def test_retrieval_trust_label_is_derived_not_caller_owned():
    ctx = build_fixture()
    retrieval = next(item for item in ctx["manifest"].retrievals if item.retrieval_id == RETRIEVE_SUMMARY)
    forged = dict(retrieval.declared_trust_by_memory)
    forged[MEM_RETRIEVAL_SUMMARY] = MemoryTrust.VERIFIED_SYSTEM
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "retrievals", RETRIEVE_SUMMARY, declared_trust_by_memory=forged)
    repin(ctx)
    with pytest.raises(MemorySecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == MemoryRejectReason.DECLARED_DECISION_MISMATCH


def test_superseded_memory_retrieval_is_denied_when_truthfully_declared():
    ctx = build_fixture()
    old_id = "memory-tenant-old-profile"
    old = next(item for item in ctx["manifest"].memories if item.memory_id == old_id)
    ctx["manifest"] = replace_manifest_item(
        ctx["manifest"],
        "retrievals",
        RETRIEVE_PROFILE,
        memory_ids=(old_id,),
        declared_trust_by_memory={old_id: old.trust_label},
        declared_classification_by_memory={old_id: old.classification},
    )
    repin(ctx)
    ctx["request"] = truthful_request_for_context(
        ctx,
        retrieval_risks={RETRIEVE_PROFILE: (MemoryRisk.SUPERSEDED_MEMORY,)},
    )
    result = evaluate(ctx)
    fact = next(item for item in result.retrievals if item.retrieval_id == RETRIEVE_PROFILE)
    assert fact.risks == (MemoryRisk.SUPERSEDED_MEMORY,)


def test_safe_sanitized_trust_upgrade_is_allowed():
    result = evaluate(build_fixture())
    fact = next(item for item in result.writes if item.write_id == WRITE_RETRIEVAL_SUMMARY)
    assert fact.decision == MemoryDecision.ALLOW
    assert fact.trust_label == MemoryTrust.DELEGATED
    assert fact.parent_memory_ids == (MEM_SESSION_QUERY,)


def test_expired_memory_retrieval_is_denied():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "memories", MEM_CURRENT_PROFILE, expires_at_epoch=NOW - 1)
    repin(ctx)
    with pytest.raises(MemorySecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == MemoryRejectReason.DECLARED_DECISION_MISMATCH


def test_unknown_memory_parent_fails_before_risk_derivation():
    ctx = build_fixture()
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "memories", MEM_RETRIEVAL_SUMMARY, parent_memory_ids=("memory-unknown",))
    repin(ctx)
    with pytest.raises(MemorySecurityRejected) as exc:
        evaluate(ctx)
    assert exc.value.reason == MemoryRejectReason.MEMORY_REFERENCE_UNKNOWN


def test_claim_boundary_flags_are_explicit():
    result = evaluate(build_fixture())
    assert result.caller_declared_memory_safety_trusted is False
    assert result.production_vector_database_enforcement is False
    assert result.production_memory_provider_integration is False
    assert result.cryptographic_memory_attestation is False
    assert result.formal_noninterference_proof is False
    assert result.exhaustive_poisoning_coverage is False
