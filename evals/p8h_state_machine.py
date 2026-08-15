from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Callable

from aegis.agentic.state_machine_security import (
    AgentStateMachineSecurityAnalyzer,
    AgentStateSecurityRejected,
    ConcurrencyControl,
    TransitionIntent,
    TransitionRisk,
)
from aegis.vulnerable.state_machine_security import VulnerableDeclaredStateSafety
from evals.p8h_fixture import (
    LEASE_IDS,
    NOW,
    OBJECT_IDS,
    TRANSITION_IDS,
    build_fixture,
    clone_context,
    make_upstreams,
    rebind,
    replace_item,
    sha,
    truthful_request,
)

Mutation = Callable[[dict[str, object]], dict[str, object]]


def _request(field: str, value: object) -> Mutation:
    def mutate(ctx):
        ctx["request"] = replace(ctx["request"], **{field: value})
        return ctx
    return mutate


def _manifest(field: str, value: object) -> Mutation:
    def mutate(ctx):
        ctx["manifest"] = replace(ctx["manifest"], **{field: value})
        return ctx
    return mutate


def _transition(transition_id: str, **changes) -> Mutation:
    def mutate(ctx):
        ctx["manifest"] = replace_item(ctx["manifest"], "transitions", transition_id, **changes)
        return rebind(ctx)
    return mutate


def _object(object_id: str, **changes) -> Mutation:
    def mutate(ctx):
        ctx["manifest"] = replace_item(ctx["manifest"], "objects", object_id, **changes)
        return rebind(ctx)
    return mutate


def _lease(lease_id: str, **changes) -> Mutation:
    def mutate(ctx):
        ctx["manifest"] = replace_item(ctx["manifest"], "leases", lease_id, **changes)
        return rebind(ctx)
    return mutate


def _drop(collection: str, attr: str, item_id: str) -> Mutation:
    def mutate(ctx):
        ctx["manifest"] = replace(
            ctx["manifest"],
            **{collection: tuple(x for x in getattr(ctx["manifest"], collection) if getattr(x, attr) != item_id)},
        )
        return rebind(ctx)
    return mutate


def _duplicate(collection: str, attr: str, item_id: str) -> Mutation:
    def mutate(ctx):
        values = list(getattr(ctx["manifest"], collection))
        values.append(next(x for x in values if getattr(x, attr) == item_id))
        ctx["manifest"] = replace(ctx["manifest"], **{collection: tuple(values)})
        return rebind(ctx)
    return mutate


def _policy(field: str, value: object) -> Mutation:
    def mutate(ctx):
        ctx["policy"] = replace(ctx["policy"], **{field: value})
        return ctx
    return mutate


def _remove_policy_map(field: str, key: str) -> Mutation:
    def mutate(ctx):
        mp = dict(getattr(ctx["policy"], field))
        mp.pop(key)
        ctx["policy"] = replace(ctx["policy"], **{field: mp})
        return ctx
    return mutate


def _upstream(kind: str, **changes) -> Mutation:
    def mutate(ctx):
        ctx[kind] = SimpleNamespace(**{**vars(ctx[kind]), **changes})
        return ctx
    return mutate


def _replace_upstreams(**kwargs) -> Mutation:
    def mutate(ctx):
        ctx.update(make_upstreams(**kwargs))
        return ctx
    return mutate


def _truthful_after(mutation: Mutation) -> Mutation:
    def mutate(ctx):
        ctx = mutation(ctx)
        try:
            ctx["request"] = truthful_request(ctx)
        except AgentStateSecurityRejected:
            pass
        return ctx
    return mutate


def _coherent_object_profile(object_id: str, **changes) -> Mutation:
    def mutate(ctx):
        ctx["manifest"] = replace_item(ctx["manifest"], "objects", object_id, **changes)
        profiles = dict(ctx["policy"].expected_object_profiles)
        obj = next(o for o in ctx["manifest"].objects if o.object_id == object_id)
        profiles[object_id] = (obj.object_type, obj.tenant_id, obj.version, obj.state_sha256)
        ctx["policy"] = replace(ctx["policy"], expected_object_profiles=profiles)
        return rebind(ctx)
    return mutate


def _coherent_allowed_intent(object_id: str, intent: TransitionIntent) -> Mutation:
    def mutate(ctx):
        mapping = dict(ctx["policy"].allowed_intents_by_object)
        mapping[object_id] = frozenset(set(mapping[object_id]) | {intent})
        ctx["policy"] = replace(ctx["policy"], allowed_intents_by_object=mapping)
        return ctx
    return mutate


def _coherent_allowed_control(object_id: str, control: ConcurrencyControl) -> Mutation:
    def mutate(ctx):
        mapping = dict(ctx["policy"].allowed_controls_by_object)
        mapping[object_id] = frozenset(set(mapping[object_id]) | {control})
        ctx["policy"] = replace(ctx["policy"], allowed_controls_by_object=mapping)
        return ctx
    return mutate


def _compose(*mutations: Mutation) -> Mutation:
    def mutate(ctx):
        for item in mutations:
            ctx = item(ctx)
        return ctx
    return mutate


def _drop_required_lease(ctx):
    ctx["manifest"] = replace(ctx["manifest"], leases=())
    ctx["policy"] = replace(ctx["policy"], required_lease_ids=frozenset())
    return rebind(ctx)


def _duplicate_release_semantics(ctx):
    release = next(t for t in ctx["manifest"].transitions if t.transition_id == "transition-release")
    ctx["manifest"] = replace_item(
        ctx["manifest"],
        "transitions",
        "transition-memory",
        object_id=release.object_id,
        message_id=release.message_id,
        approval_action_id=release.approval_action_id,
        observation_id=release.observation_id,
        actor_agent_id=release.actor_agent_id,
        original_principal_id=release.original_principal_id,
        tenant_id=release.tenant_id,
        intent=release.intent,
        concurrency_control=release.concurrency_control,
        expected_version=release.expected_version,
        expected_state_sha256=release.expected_state_sha256,
        proposed_version=release.proposed_version,
        proposed_state_sha256=release.proposed_state_sha256,
        idempotency_key=release.idempotency_key,
        lease_id=release.lease_id,
        approval_bound_version=release.approval_bound_version,
        approval_bound_state_sha256=release.approval_bound_state_sha256,
        payload_sha256=release.payload_sha256,
        irreversible=True,
        issued_at_epoch=release.issued_at_epoch + 1,
        commit_at_epoch=release.commit_at_epoch + 1,
    )
    return rebind(ctx)


def _same_idem_different_payload(ctx):
    ctx["manifest"] = replace_item(
        ctx["manifest"],
        "transitions",
        "transition-ticket-2",
        idempotency_key="idem-ticket-1",
        payload_sha256=sha("different-payload"),
    )
    return rebind(ctx)


def _cancel_then_execute(ctx):
    mapping = dict(ctx["policy"].allowed_intents_by_object)
    mapping["state-task"] = frozenset(set(mapping["state-task"]) | {TransitionIntent.MUTATE})
    ctx["policy"] = replace(ctx["policy"], allowed_intents_by_object=mapping)
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
    return rebind(ctx)


def _rollback_race(ctx):
    ctx["manifest"] = replace_item(
        ctx["manifest"],
        "transitions",
        "transition-task-read",
        intent=TransitionIntent.ROLLBACK,
        expected_version=3,
        expected_state_sha256=sha("task-v3"),
        proposed_version=4,
        proposed_state_sha256=sha("task-rollback-v4"),
        idempotency_key="idem-task-rollback",
        issued_at_epoch=NOW - 11,
        commit_at_epoch=NOW - 9,
    )
    return rebind(ctx)


def _wrong_lease_object_coherent(ctx):
    ctx["manifest"] = replace_item(ctx["manifest"], "leases", "lease-telemetry", object_id="state-policy")
    return rebind(ctx)


def _message_sender_mismatch(ctx):
    messages = tuple(
        SimpleNamespace(**{**vars(m), "sender_agent_id": "agent-other"})
        if m.message_id == "msg-policy"
        else m
        for m in ctx["p8g"].messages
    )
    ctx["p8g"] = SimpleNamespace(**{**vars(ctx["p8g"]), "messages": messages})
    return ctx


def _message_tenant_mismatch(ctx):
    messages = tuple(
        SimpleNamespace(**{**vars(m), "tenant_id": "tenant-B"})
        if m.message_id == "msg-ticket-1"
        else m
        for m in ctx["p8g"].messages
    )
    ctx["p8g"] = SimpleNamespace(**{**vars(ctx["p8g"]), "messages": messages})
    return ctx


CASES: list[tuple[str, Mutation]] = []

CASES += [
    ("request-graph-id", _request("graph_id", "evil")),
    ("request-version", _request("graph_version", "evil")),
    ("request-graph-sha", _request("graph_sha256", "1" * 64)),
    ("request-p8d-sha", _request("p8d_assessment_evidence_sha256", "2" * 64)),
    ("request-p8f-sha", _request("p8f_assessment_evidence_sha256", "3" * 64)),
    ("request-p8g-sha", _request("p8g_assessment_evidence_sha256", "4" * 64)),
    ("request-transition-omission", _request("transition_ids", TRANSITION_IDS[:-1])),
    ("request-transition-duplicate", _request("transition_ids", TRANSITION_IDS + (TRANSITION_IDS[0],))),
    ("manifest-schema", _manifest("schema_version", "evil")),
    ("manifest-id", _manifest("graph_id", "evil")),
    ("manifest-version", _manifest("version", "evil")),
    ("manifest-stale", _manifest("created_at_epoch", NOW - 100_000)),
    ("manifest-future", _manifest("created_at_epoch", NOW + 100)),
]
CASES += [
    ("p8d-digest", _upstream("p8d", assessment_evidence_sha256="5" * 64)),
    ("p8d-unverified", _upstream("p8d", exact_tool_observation_graph_binding_verified=False)),
    ("p8d-caller-trusted", _upstream("p8d", caller_declared_tool_observation_safety_trusted=True)),
    ("p8f-digest", _upstream("p8f", assessment_evidence_sha256="6" * 64)),
    ("p8f-unverified", _upstream("p8f", exact_human_approval_graph_binding_verified=False)),
    ("p8f-caller-trusted", _upstream("p8f", caller_declared_approval_safety_trusted=True)),
    ("p8g-digest", _upstream("p8g", assessment_evidence_sha256="7" * 64)),
    ("p8g-unverified", _upstream("p8g", exact_agent_message_graph_binding_verified=False)),
    ("p8g-caller-trusted", _upstream("p8g", caller_declared_message_safety_trusted=True)),
    ("manifest-p8d-digest", _manifest("p8d_assessment_evidence_sha256", "8" * 64)),
    ("manifest-p8f-digest", _manifest("p8f_assessment_evidence_sha256", "9" * 64)),
    ("manifest-p8g-digest", _manifest("p8g_assessment_evidence_sha256", "a" * 64)),
]
CASES += [
    ("object-omission", _drop("objects", "object_id", "state-memory")),
    ("object-duplicate", _duplicate("objects", "object_id", "state-memory")),
    ("lease-omission", _drop("leases", "lease_id", "lease-telemetry")),
    ("lease-duplicate", _duplicate("leases", "lease_id", "lease-telemetry")),
    ("transition-omission", _drop("transitions", "transition_id", "transition-memory")),
    ("transition-duplicate", _duplicate("transitions", "transition_id", "transition-memory")),
    ("object-owner-untrusted", _object("state-memory", owner_id="attacker")),
    ("lease-owner-untrusted", _lease("lease-telemetry", owner_id="attacker")),
    ("transition-owner-untrusted", _transition("transition-memory", owner_id="attacker")),
    ("transition-object-unknown", _transition("transition-memory", object_id="state-unknown")),
    ("transition-message-empty", _transition("transition-memory", message_id="")),
    ("transition-expected-hash-invalid", _transition("transition-memory", expected_state_sha256="bad")),
    ("transition-proposed-hash-invalid", _transition("transition-memory", proposed_state_sha256="bad")),
    ("transition-payload-hash-invalid", _transition("transition-memory", payload_sha256="bad")),
    ("transition-partial-approval-binding", _transition("transition-ticket-1", approval_bound_state_sha256=None)),
]
CASES += [
    ("object-type-drift", _object("state-memory", object_type="release")),
    ("object-tenant-drift", _object("state-memory", tenant_id="tenant-B")),
    ("object-version-drift", _object("state-memory", version=6)),
    ("object-state-drift", _object("state-memory", state_sha256=sha("evil-state"))),
    ("policy-object-profile-omit", _remove_policy_map("expected_object_profiles", "state-memory")),
    ("policy-intent-map-omit", _remove_policy_map("allowed_intents_by_object", "state-memory")),
    ("policy-control-map-omit", _remove_policy_map("allowed_controls_by_object", "state-memory")),
    ("policy-owner-empty", _policy("trusted_owner_ids", frozenset())),
    ("policy-age-zero", _policy("max_manifest_age_seconds", 0)),
    ("policy-skew-negative", _policy("max_future_skew_seconds", -1)),
]

SEMANTIC = [
    ("duplicate-release-execution", _duplicate_release_semantics),
    ("idempotency-key-reuse-different-payload", _same_idem_different_payload),
    ("ticket-1-stale-version", _transition("transition-ticket-1", expected_version=9)),
    ("ticket-2-stale-version", _transition("transition-ticket-2", expected_version=10)),
    ("policy-stale-version", _transition("transition-policy", expected_version=11)),
    ("memory-stale-version", _transition("transition-memory", expected_version=4)),
    ("ticket-1-expected-state-mismatch", _transition("transition-ticket-1", expected_state_sha256=sha("other-ticket"))),
    ("ticket-2-expected-state-mismatch", _transition("transition-ticket-2", expected_state_sha256=sha("other-ticket-2"))),
    ("release-expected-state-mismatch", _transition("transition-release", expected_state_sha256=sha("other-release"))),
    ("policy-expected-state-mismatch", _transition("transition-policy", expected_state_sha256=sha("other-policy"))),
    ("ticket-nonmonotonic-version", _transition("transition-ticket-1", proposed_version=10)),
    ("release-version-skip", _transition("transition-release", proposed_version=44)),
    ("memory-version-skip", _transition("transition-memory", proposed_version=8)),
    ("ticket-concurrent-writers", _transition("transition-ticket-2", expected_version=10, expected_state_sha256=sha("ticket-v10"), proposed_version=11, proposed_state_sha256=sha("ticket-alt-v11"))),
    ("release-concurrent-writer", _duplicate_release_semantics),
    ("lease-missing", _transition("transition-telemetry", lease_id=None)),
    ("lease-expired", _lease("lease-telemetry", expires_at_epoch=NOW - 50)),
    ("lease-future", _lease("lease-telemetry", issued_at_epoch=NOW - 20, expires_at_epoch=NOW + 100)),
    ("lease-owner-mismatch", _lease("lease-telemetry", owner_agent_id="agent-other")),
    ("lease-object-mismatch", _wrong_lease_object_coherent),
    ("cancel-then-execute", _cancel_then_execute),
    ("rollback-forward-race", _rollback_race),
    ("approval-to-use-version-race", _transition("transition-ticket-2", approval_bound_version=10, approval_bound_state_sha256=sha("ticket-v10"))),
    ("approval-to-use-hash-race", _transition("transition-policy", approval_bound_state_sha256=sha("old-policy"))),
    ("duplicate-side-effect-observation", _transition("transition-ticket-2", observation_id="obs-ticket-1")),
    ("release-without-idempotency-key", _transition("transition-release", idempotency_key=None)),
    ("wrong-control-ticket", _transition("transition-ticket-1", concurrency_control=ConcurrencyControl.NONE)),
    ("unauthorized-intent-task", _transition("transition-task-cancel", intent=TransitionIntent.COMMIT)),
    ("transition-tenant-mismatch", _transition("transition-ticket-1", tenant_id="tenant-B")),
    ("message-sender-actor-mismatch", _message_sender_mismatch),
    ("message-tenant-mismatch", _message_tenant_mismatch),
    ("upstream-message-denied", _replace_upstreams(denied_messages=frozenset({"msg-policy"}))),
    ("upstream-approval-denied", _replace_upstreams(denied_actions=frozenset({"action-release"}))),
    ("upstream-observation-denied", _replace_upstreams(denied_observations=frozenset({"obs-telemetry"}))),
]
CASES += [(case_id, _truthful_after(mutation)) for case_id, mutation in SEMANTIC]

CASES += [
    ("policy-graph-sha-invalid", _policy("expected_graph_sha256", "bad")),
    ("policy-p8d-sha-invalid", _policy("expected_p8d_assessment_evidence_sha256", "bad")),
    ("policy-p8f-sha-invalid", _policy("expected_p8f_assessment_evidence_sha256", "bad")),
    ("policy-p8g-sha-invalid", _policy("expected_p8g_assessment_evidence_sha256", "bad")),
    ("policy-approval-object-unknown", _policy("approval_required_object_ids", frozenset({"state-unknown"}))),
    ("policy-observation-object-unknown", _policy("observation_required_object_ids", frozenset({"state-unknown"}))),
    ("policy-lease-object-unknown", _policy("lease_required_object_ids", frozenset({"state-unknown"}))),
    ("policy-irreversible-object-unknown", _policy("irreversible_object_ids", frozenset({"state-unknown"}))),
    ("lease-time-invalid", _lease("lease-telemetry", issued_at_epoch=NOW + 10, expires_at_epoch=NOW)),
    ("transition-time-invalid", _transition("transition-memory", issued_at_epoch=NOW, commit_at_epoch=NOW - 1)),
]

base_versions = {
    "state-ticket": 12,
    "state-release": 43,
    "state-telemetry": 8,
    "state-policy": 13,
    "state-task": 4,
    "state-memory": 6,
}
CASES += [
    ("caller-fake-denial", _request("declared_denied_transition_ids", ("transition-memory",))),
    ("caller-denial-duplicate", _request("declared_denied_transition_ids", ("transition-memory", "transition-memory"))),
    ("caller-risk-map-empty", _request("declared_risks_by_transition", {})),
    ("caller-risk-map-omit", _request("declared_risks_by_transition", {tid: () for tid in TRANSITION_IDS if tid != "transition-memory"})),
    ("caller-fake-risk", _request("declared_risks_by_transition", {tid: ((TransitionRisk.DUPLICATE_EXECUTION,) if tid == "transition-memory" else ()) for tid in TRANSITION_IDS})),
    ("caller-fake-stale-risk", _request("declared_risks_by_transition", {tid: ((TransitionRisk.STALE_EXPECTED_VERSION,) if tid == "transition-ticket-1" else ()) for tid in TRANSITION_IDS})),
    ("caller-final-ticket-version", _request("declared_final_versions", {**base_versions, "state-ticket": 999})),
    ("caller-final-release-version", _request("declared_final_versions", {**base_versions, "state-release": 999})),
    ("caller-final-version-omit", _request("declared_final_versions", {k: v for k, v in base_versions.items() if k != "state-memory"})),
    ("caller-final-version-extra", _request("declared_final_versions", {**base_versions, "state-extra": 1})),
]

EXPECTED_ADVERSARIAL_CASES = len(CASES)
assert EXPECTED_ADVERSARIAL_CASES == 104, EXPECTED_ADVERSARIAL_CASES


def hardened_attack_succeeds(ctx) -> bool:
    try:
        result = AgentStateMachineSecurityAnalyzer(ctx["policy"]).evaluate(
            ctx["request"], ctx["manifest"], ctx["p8d"], ctx["p8f"], ctx["p8g"]
        )
    except AgentStateSecurityRejected:
        return False
    return result.denied_transition_count == 0


def benign_contexts():
    clean = clone_context()

    stale = _transition("transition-memory", expected_version=4)(clone_context())
    stale["request"] = truthful_request(stale)

    lease = _lease("lease-telemetry", expires_at_epoch=NOW - 50)(clone_context())
    lease["request"] = truthful_request(lease)

    return (
        ("clean", clean),
        ("truthful-stale-version-denial", stale),
        ("truthful-expired-lease-denial", lease),
    )


def run():
    weak = VulnerableDeclaredStateSafety()
    vulnerable_successes = 0
    hardened_successes = 0
    rows = []
    for case_id, mutation in CASES:
        ctx = mutation(clone_context())
        vulnerable = weak.evaluate(
            declared_single_execution=True,
            declared_state_fresh=True,
            declared_no_races=True,
            declared_final_version=999,
            declared_conflict_count=0,
        ).accepted
        hardened = hardened_attack_succeeds(ctx)
        vulnerable_successes += int(vulnerable)
        hardened_successes += int(hardened)
        rows.append({"case_id": case_id, "vulnerable_success": vulnerable, "hardened_success": hardened})

    false_positives = 0
    safe_successes = 0
    benign = []
    for case_id, ctx in benign_contexts():
        ok = True
        try:
            AgentStateMachineSecurityAnalyzer(ctx["policy"]).evaluate(
                ctx["request"], ctx["manifest"], ctx["p8d"], ctx["p8f"], ctx["p8g"]
            )
        except AgentStateSecurityRejected:
            ok = False
        false_positives += int(not ok)
        safe_successes += int(ok)
        benign.append({"case_id": case_id, "accepted": ok})

    fixture = build_fixture()
    dataset_sha = hashlib.sha256(
        json.dumps([case_id for case_id, _ in CASES], separators=(",", ":")).encode()
    ).hexdigest()
    fixture_doc = {
        "graph_sha256": fixture["request"].graph_sha256,
        "object_ids": sorted(OBJECT_IDS),
        "lease_ids": sorted(LEASE_IDS),
        "transition_ids": list(fixture["request"].transition_ids),
    }
    fixture_sha = hashlib.sha256(
        json.dumps(fixture_doc, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    clean = AgentStateMachineSecurityAnalyzer(fixture["policy"]).evaluate(
        fixture["request"], fixture["manifest"], fixture["p8d"], fixture["p8f"], fixture["p8g"]
    )
    return {
        "adversarial_cases": len(CASES),
        "vulnerable_asr": f"{vulnerable_successes}/{len(CASES)}",
        "hardened_asr": f"{hardened_successes}/{len(CASES)}",
        "hardened_fpr": f"{false_positives}/3",
        "safe_task_rate": f"{safe_successes}/3",
        "graph_sha256": fixture["request"].graph_sha256,
        "dataset_sha256": dataset_sha,
        "fixture_sha256": fixture_sha,
        "clean_assessment_sha256": clean.assessment_evidence_sha256,
        "cases": rows,
        "benign": benign,
    }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2, sort_keys=True))
    assert result["vulnerable_asr"] == f"{EXPECTED_ADVERSARIAL_CASES}/{EXPECTED_ADVERSARIAL_CASES}"
    assert result["hardened_asr"] == f"0/{EXPECTED_ADVERSARIAL_CASES}"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
