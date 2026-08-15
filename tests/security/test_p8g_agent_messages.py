from __future__ import annotations

from dataclasses import replace
import pytest

from aegis.agentic.message_security import (
    AgentMessageProtocolSecurityAnalyzer,
    AgentMessageSecurityRejected,
    MessageDecision,
    MessageIntent,
    MessageRisk,
    MessageTrust,
    agent_message_manifest_digest,
)
from evals.p8g_agent_messages import CASES, EXPECTED_ADVERSARIAL_CASES, benign_contexts, hardened_attack_succeeds, run
from evals.p8g_fixture import (
    NOW,
    build_fixture,
    clone_context,
    rebind,
    replace_item,
    truthful_request,
)


def evaluate(ctx):
    return AgentMessageProtocolSecurityAnalyzer(ctx["policy"]).evaluate(
        ctx["request"], ctx["manifest"], ctx["p8a"], ctx["p8c"], ctx["p8f"]
    )


def test_clean_fixture_allows_all_messages():
    result = evaluate(build_fixture())
    assert result.message_count == 7
    assert result.allowed_message_count == 7
    assert result.denied_message_count == 0
    assert result.maximum_risk_score == 0
    assert result.network_operations == 0


def test_external_advisory_is_authenticated_but_not_verified_authority():
    result = evaluate(build_fixture())
    fact = next(f for f in result.messages if f.message_id == "msg-external-advisory")
    assert fact.decision == MessageDecision.ALLOW
    assert fact.derived_trust == MessageTrust.AUTHENTICATED
    assert fact.intent == MessageIntent.INFORMATION


def test_safe_two_hop_tool_chain_preserves_delegation_provenance():
    result = evaluate(build_fixture())
    fact = next(f for f in result.messages if f.message_id == "msg-tool-child")
    assert fact.decision == MessageDecision.ALLOW
    assert fact.parent_message_id == "msg-tool-root"
    assert fact.risks == ()


def test_external_message_cannot_be_promoted_to_command():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "channels", "channel-external-advisory", allowed_intents=(MessageIntent.INFORMATION, MessageIntent.COMMAND))
    profiles = dict(ctx["policy"].expected_channel_profiles)
    c = next(c for c in ctx["manifest"].channels if c.channel_id == "channel-external-advisory")
    profiles[c.channel_id] = (c.channel_type, tuple(c.allowed_sender_ids), tuple(c.allowed_receiver_ids), tuple(c.allowed_intents), c.tenant_scope, c.required_schema_version, c.protocol_version, tuple(c.allowed_capability_ids), c.command_requires_approval, c.required_approval_action_id, c.max_message_age_seconds)
    ctx["policy"] = replace(ctx["policy"], expected_channel_profiles=profiles)
    ctx["manifest"] = replace_item(ctx["manifest"], "messages", "msg-external-advisory", intent=MessageIntent.COMMAND)
    rebind(ctx)
    ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    fact = next(f for f in result.messages if f.message_id == "msg-external-advisory")
    assert fact.decision == MessageDecision.DENY
    assert MessageRisk.EXTERNAL_COMMAND_ESCALATION in fact.risks


def test_command_laundering_from_external_parent_is_detected():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "messages", "msg-policy", parent_message_id="msg-external-advisory")
    rebind(ctx)
    ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    fact = next(f for f in result.messages if f.message_id == "msg-policy")
    assert MessageRisk.COMMAND_LAUNDERING in fact.risks


def test_duplicate_nonce_is_replay():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "messages", "msg-retrieval", nonce="nonce-policy")
    rebind(ctx)
    ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    assert result.replay_or_freshness_denial_count >= 2


def test_protocol_downgrade_is_denied():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "messages", "msg-retrieval", protocol_version=1)
    rebind(ctx)
    ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    fact = next(f for f in result.messages if f.message_id == "msg-retrieval")
    assert MessageRisk.PROTOCOL_DOWNGRADE in fact.risks


def test_capability_cannot_exceed_delegated_authority():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "messages", "msg-retrieval", capability_ids=("model.deploy",))
    rebind(ctx)
    ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    fact = next(f for f in result.messages if f.message_id == "msg-retrieval")
    assert MessageRisk.CAPABILITY_ESCALATION in fact.risks


def test_release_command_must_bind_exact_approval_action():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "messages", "msg-release", approval_action_id="action-telemetry")
    rebind(ctx)
    ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    fact = next(f for f in result.messages if f.message_id == "msg-release")
    assert MessageRisk.REQUIRED_APPROVAL_MISSING in fact.risks


def test_upstream_denied_plan_step_blocks_message():
    from types import SimpleNamespace
    ctx = clone_context()
    steps = tuple(
        SimpleNamespace(**{**vars(s), "decision": "deny"}) if getattr(s, "step_id", "") == "step-policy" else s
        for s in ctx["p8c"].steps
    )
    ctx["p8c"] = type(ctx["p8c"])(**{**vars(ctx["p8c"]), "steps": steps})
    ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    fact = next(f for f in result.messages if f.message_id == "msg-policy")
    assert MessageRisk.UPSTREAM_PLAN_UNSAFE in fact.risks


def test_sender_identity_digest_is_policy_pinned():
    ctx = clone_context()
    ctx["manifest"] = replace_item(ctx["manifest"], "messages", "msg-retrieval", sender_identity_sha256="f" * 64)
    rebind(ctx)
    ctx["request"] = truthful_request(ctx)
    result = evaluate(ctx)
    fact = next(f for f in result.messages if f.message_id == "msg-retrieval")
    assert MessageRisk.SENDER_IDENTITY_MISMATCH in fact.risks
    assert fact.derived_trust == MessageTrust.UNTRUSTED


def test_all_adversarial_cases_fail_closed():
    assert EXPECTED_ADVERSARIAL_CASES == 103
    failures = [case_id for case_id, mutation in CASES if hardened_attack_succeeds(mutation(clone_context()))]
    assert failures == []


def test_truthful_denial_contexts_are_accepted_evidence_states():
    contexts = benign_contexts()
    assert evaluate(contexts[1][1]).denied_message_count >= 1
    assert evaluate(contexts[2][1]).denied_message_count >= 1


def test_evaluator_metrics_and_hashes_are_exact():
    result = run()
    assert result["adversarial_cases"] == 103
    assert result["vulnerable_asr"] == "103/103"
    assert result["hardened_asr"] == "0/103"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
    assert result["graph_sha256"] == "2afd5ddd030144a9983d34353771d2445276b47793cc57c68db464e5d7a9ba2e"
    assert result["dataset_sha256"] == "9602be70877a2fabb55b1c567466ec53340a18b9cad09c5b6e9ac4ee7d089a15"
    assert result["fixture_sha256"] == "e67cf7dbb2da2b219db9c52f48e53137f40eeeae221f53a2cc6bd6e4a1285ce6"
    assert result["clean_assessment_sha256"] == "f670e1a9e736e47c341543c29d11b4ed00dc5e23ea818be4e27090d47829cf69"


def test_manifest_digest_is_deterministic_and_claim_boundary_explicit():
    ctx = build_fixture()
    assert agent_message_manifest_digest(ctx["manifest"]) == ctx["request"].graph_sha256
    result = evaluate(ctx)
    assert result.caller_declared_message_safety_trusted is False
    assert result.production_message_broker_enforcement is False
    assert result.production_workload_identity_attestation is False
    assert result.cryptographic_message_signature_verification is False
    assert result.production_mtls_enforcement is False
    assert result.exhaustive_protocol_semantics_proof is False
