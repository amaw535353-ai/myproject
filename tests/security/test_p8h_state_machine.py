from __future__ import annotations

from dataclasses import replace

from aegis.agentic.state_machine_security import (
    AgentStateMachineSecurityAnalyzer,
    TransitionDecision,
    TransitionIntent,
    TransitionRisk,
    agent_state_transition_manifest_digest,
)
from evals.p8h_fixture import NOW, build_fixture, clone_context, rebind, replace_item, sha, truthful_request
from evals.p8h_state_machine import CASES, EXPECTED_ADVERSARIAL_CASES, benign_contexts, hardened_attack_succeeds, run


def evaluate(ctx):
    return AgentStateMachineSecurityAnalyzer(ctx["policy"]).evaluate(
        ctx["request"], ctx["manifest"], ctx["p8d"], ctx["p8f"], ctx["p8g"]
    )


def test_clean_fixture_applies_all_transitions():
    result = evaluate(build_fixture())
    assert result.transition_count == 8
    assert result.allowed_transition_count == 8
    assert result.denied_transition_count == 0
    assert result.final_versions == {
        "state-ticket": 12,
        "state-release": 43,
        "state-telemetry": 8,
        "state-policy": 13,
        "state-task": 4,
        "state-memory": 6,
    }
    assert result.network_operations == 0


def test_two_sequential_ticket_writes_are_version_safe():
    result = evaluate(build_fixture())
    first = next(f for f in result.transitions if f.transition_id == "transition-ticket-1")
    second = next(f for f in result.transitions if f.transition_id == "transition-ticket-2")
    assert first.derived_pre_version == 10
    assert first.applied_version == 11
    assert second.derived_pre_version == 11
    assert second.applied_version == 12


def test_stale_compare_and_swap_is_denied():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "transitions", "transition-memory", expected_version=4)
    rebind(ctx, truthful=True)
    result = evaluate(ctx)
    fact = next(f for f in result.transitions if f.transition_id == "transition-memory")
    assert fact.decision == TransitionDecision.DENY
    assert TransitionRisk.STALE_EXPECTED_VERSION in fact.risks
    assert TransitionRisk.LOST_UPDATE in fact.risks


def test_same_expected_version_writers_are_conflicting():
    ctx = clone_context()
    ctx["manifest"] = replace_item(
        ctx["manifest"],
        "transitions",
        "transition-ticket-2",
        expected_version=10,
        expected_state_sha256=sha("ticket-v10"),
        proposed_version=11,
        proposed_state_sha256=sha("ticket-alt-v11"),
    )
    rebind(ctx, truthful=True)
    result = evaluate(ctx)
    facts = [f for f in result.transitions if f.object_id == "state-ticket"]
    assert all(TransitionRisk.CONCURRENT_CONFLICT in f.risks for f in facts)


def test_idempotency_key_reuse_with_different_payload_is_denied():
    ctx = clone_context()
    ctx["manifest"] = replace_item(
        ctx["manifest"],
        "transitions",
        "transition-ticket-2",
        idempotency_key="idem-ticket-1",
        payload_sha256=sha("different-payload"),
    )
    rebind(ctx, truthful=True)
    result = evaluate(ctx)
    fact = next(f for f in result.transitions if f.transition_id == "transition-ticket-2")
    assert TransitionRisk.IDEMPOTENCY_REUSE_MISMATCH in fact.risks


def test_irreversible_release_requires_idempotency_key():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "transitions", "transition-release", idempotency_key=None)
    rebind(ctx, truthful=True)
    result = evaluate(ctx)
    fact = next(f for f in result.transitions if f.transition_id == "transition-release")
    assert TransitionRisk.CONTROL_MISMATCH in fact.risks


def test_telemetry_lease_owner_and_expiry_are_enforced():
    ctx = clone_context()
    ctx["manifest"] = replace_item(
        ctx["manifest"],
        "leases",
        "lease-telemetry",
        owner_agent_id="agent-other",
        expires_at_epoch=NOW - 50,
    )
    rebind(ctx, truthful=True)
    result = evaluate(ctx)
    fact = next(f for f in result.transitions if f.transition_id == "transition-telemetry")
    assert TransitionRisk.LEASE_OWNER_MISMATCH in fact.risks
    assert TransitionRisk.LEASE_EXPIRED in fact.risks


def test_cancelled_task_cannot_execute_after_cancel():
    ctx = clone_context()
    intents = dict(ctx["policy"].allowed_intents_by_object)
    intents["state-task"] = frozenset(set(intents["state-task"]) | {TransitionIntent.MUTATE})
    ctx["policy"] = replace(ctx["policy"], allowed_intents_by_object=intents)
    ctx["manifest"] = replace_item(
        ctx["manifest"],
        "transitions",
        "transition-task-read",
        intent=TransitionIntent.MUTATE,
        expected_version=4,
        expected_state_sha256=sha("task-cancelled-v4"),
        proposed_version=5,
        proposed_state_sha256=sha("task-executed-after-cancel-v5"),
        idempotency_key="idem-task-after-cancel",
        issued_at_epoch=NOW - 5,
        commit_at_epoch=NOW - 4,
    )
    rebind(ctx, truthful=True)
    result = evaluate(ctx)
    fact = next(f for f in result.transitions if f.transition_id == "transition-task-read")
    assert TransitionRisk.CANCEL_EXECUTE_RACE in fact.risks


def test_approval_is_bound_to_state_at_use_time():
    ctx = clone_context()
    ctx["manifest"] = replace_item(
        ctx["manifest"],
        "transitions",
        "transition-ticket-2",
        approval_bound_version=10,
        approval_bound_state_sha256=sha("ticket-v10"),
    )
    rebind(ctx, truthful=True)
    result = evaluate(ctx)
    fact = next(f for f in result.transitions if f.transition_id == "transition-ticket-2")
    assert TransitionRisk.APPROVAL_TO_USE_RACE in fact.risks


def test_same_observation_cannot_authorize_two_side_effect_transitions():
    ctx = clone_context()
    ctx["manifest"] = replace_item(
        ctx["manifest"],
        "transitions",
        "transition-ticket-2",
        observation_id="obs-ticket-1",
    )
    rebind(ctx, truthful=True)
    result = evaluate(ctx)
    affected = [f for f in result.transitions if TransitionRisk.DUPLICATE_SIDE_EFFECT in f.risks]
    assert {f.transition_id for f in affected} == {"transition-ticket-1", "transition-ticket-2"}


def test_upstream_message_denial_blocks_state_transition():
    from types import SimpleNamespace

    ctx = clone_context()
    messages = tuple(
        SimpleNamespace(**{**vars(m), "decision": "deny"})
        if m.message_id == "msg-policy"
        else m
        for m in ctx["p8g"].messages
    )
    ctx["p8g"] = SimpleNamespace(**{**vars(ctx["p8g"]), "messages": messages})
    ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    fact = next(f for f in result.transitions if f.transition_id == "transition-policy")
    assert TransitionRisk.UPSTREAM_MESSAGE_UNSAFE in fact.risks


def test_truthful_denial_states_are_accepted():
    contexts = benign_contexts()
    assert evaluate(contexts[1][1]).denied_transition_count >= 1
    assert evaluate(contexts[2][1]).denied_transition_count >= 1


def test_all_adversarial_cases_fail_closed():
    assert EXPECTED_ADVERSARIAL_CASES == 104
    failures = [
        case_id
        for case_id, mutation in CASES
        if hardened_attack_succeeds(mutation(clone_context()))
    ]
    assert failures == []


def test_evaluator_metrics_and_hashes_are_exact():
    result = run()
    assert result["adversarial_cases"] == 104
    assert result["vulnerable_asr"] == "104/104"
    assert result["hardened_asr"] == "0/104"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
    assert result["graph_sha256"] == "6c6c6a3666e178b92d2ee9a28a1e55cb69f42c7eed5b828cc9efd7a10f1f3ee0"
    assert result["dataset_sha256"] == "e796e8104400697c37c82614ea36ffe00810ef9cfd84b23d59d965b125b188e1"
    assert result["fixture_sha256"] == "e659799632a94f7028d9b0a8d20b8ade5c283e1cbe1806bd0df328498ae4a01b"
    assert result["clean_assessment_sha256"] == "43aa4d80e2b9d7aa885b4650e5669712c70c7b0858e2322c413c25a8afb4e9e0"


def test_manifest_digest_and_claim_boundary_are_explicit():
    ctx = build_fixture()
    assert agent_state_transition_manifest_digest(ctx["manifest"]) == ctx["request"].graph_sha256
    result = evaluate(ctx)
    assert result.caller_declared_state_safety_trusted is False
    assert result.production_transaction_enforcement is False
    assert result.production_distributed_lock_enforcement is False
    assert result.production_exactly_once_execution is False
    assert result.formal_serializability_proof is False
    assert result.exhaustive_race_coverage is False
