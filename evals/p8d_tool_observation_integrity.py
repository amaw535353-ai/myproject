from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Callable

from aegis.agentic.tool_observation_security import (
    AgentToolObservationIntegrityAnalyzer,
    ObservationTrust,
    ToolEffect,
    ToolObservationSecurityRejected,
)
from aegis.vulnerable.tool_observation_security import VulnerableDeclaredToolObservationSafety
from evals.p8d_fixture import (
    NOW,
    build_fixture,
    clone_context,
    make_upstreams,
    rebind,
    replace_manifest_item,
    sha,
    truthful_unsafe_contexts,
)

Mutation = Callable[[dict], dict]
ADVERSARIAL_CASES: list[tuple[str, Mutation]] = []


def case(name: str):
    def decorate(fn: Mutation):
        ADVERSARIAL_CASES.append((name, fn))
        return fn
    return decorate


def _clone():
    return clone_context(build_fixture())


def _replace_request(ctx, **changes):
    ctx["request"] = replace(ctx["request"], **changes)
    return ctx


def _replace_policy(ctx, **changes):
    ctx["policy"] = replace(ctx["policy"], **changes)
    return ctx


def _semantic(ctx, collection: str, item_id: str, **changes):
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], collection, item_id, **changes)
    return rebind(ctx)


def replace_upstream(obj, **changes):
    data = vars(obj).copy()
    data.update(changes)
    return SimpleNamespace(**data)


for name, changes in [
    ("request_graph_id_substitution", {"graph_id": "evil-graph"}),
    ("request_graph_version_substitution", {"graph_version": "999"}),
    ("request_graph_digest_substitution", {"graph_sha256": "0" * 64}),
    ("request_p8a_digest_substitution", {"p8a_assessment_evidence_sha256": "1" * 64}),
    ("request_p8c_digest_substitution", {"p8c_assessment_evidence_sha256": "2" * 64}),
    ("request_p7i_digest_substitution", {"p7i_assessment_evidence_sha256": "3" * 64}),
    ("request_observation_omission", {"observation_ids": ("obs-search", "obs-ticket", "obs-release")}),
    ("request_observation_duplicate", {"observation_ids": ("obs-search", "obs-ticket", "obs-release", "obs-release")}),
    ("request_false_denial_summary", {"declared_denied_observation_ids": ("obs-search",)}),
    ("request_risk_map_omission", {"declared_risks_by_observation": {"obs-search": ()}}),
]:
    case(name)(lambda ctx, changes=changes: _replace_request(ctx, **changes))


@case("request_risk_forgery")
def _(ctx):
    risks = dict(ctx["request"].declared_risks_by_observation)
    risks["obs-search"] = ()
    risks.pop("obs-ticket")
    return _replace_request(ctx, declared_risks_by_observation=risks)


@case("manifest_schema_substitution")
def _(ctx):
    ctx["manifest"] = replace(ctx["manifest"], schema_version="evil-schema")
    return ctx

@case("manifest_graph_id_substitution")
def _(ctx):
    ctx["manifest"] = replace(ctx["manifest"], graph_id="evil-graph")
    return ctx

@case("manifest_version_substitution")
def _(ctx):
    ctx["manifest"] = replace(ctx["manifest"], version="999")
    return ctx

@case("manifest_future_timestamp")
def _(ctx):
    ctx["manifest"] = replace(ctx["manifest"], created_at_epoch=NOW + 1000)
    return rebind(ctx)

@case("manifest_stale_timestamp")
def _(ctx):
    ctx["manifest"] = replace(ctx["manifest"], created_at_epoch=NOW - 200000)
    return rebind(ctx)

@case("manifest_p8a_substitution")
def _(ctx):
    ctx["manifest"] = replace(ctx["manifest"], p8a_assessment_evidence_sha256="a" * 64)
    return rebind(ctx)

@case("manifest_p8c_substitution")
def _(ctx):
    ctx["manifest"] = replace(ctx["manifest"], p8c_assessment_evidence_sha256="b" * 64)
    return rebind(ctx)

@case("manifest_p7i_substitution")
def _(ctx):
    ctx["manifest"] = replace(ctx["manifest"], p7i_assessment_evidence_sha256="c" * 64)
    return rebind(ctx)


@case("p8a_digest_substitution")
def _(ctx):
    ctx["p8a"] = replace_upstream(ctx["p8a"], assessment_evidence_sha256="d" * 64)
    return ctx

@case("p8a_binding_flag_downgrade")
def _(ctx):
    ctx["p8a"] = replace_upstream(ctx["p8a"], exact_agent_delegation_graph_binding_verified=False)
    return ctx

@case("p8a_caller_summary_trusted")
def _(ctx):
    ctx["p8a"] = replace_upstream(ctx["p8a"], caller_declared_delegation_authorization_trusted=True)
    return ctx

@case("p8a_related_delegation_denied")
def _(ctx):
    ctx.update(make_upstreams(denied_delegations=frozenset({"delegation-tool-child"})))
    return ctx

@case("p8c_digest_substitution")
def _(ctx):
    ctx["p8c"] = replace_upstream(ctx["p8c"], assessment_evidence_sha256="e" * 64)
    return ctx

@case("p8c_binding_flag_downgrade")
def _(ctx):
    ctx["p8c"] = replace_upstream(ctx["p8c"], exact_goal_plan_graph_binding_verified=False)
    return ctx

@case("p8c_caller_summary_trusted")
def _(ctx):
    ctx["p8c"] = replace_upstream(ctx["p8c"], caller_declared_goal_plan_safety_trusted=True)
    return ctx

@case("p8c_related_step_denied")
def _(ctx):
    ctx.update(make_upstreams(denied_steps=frozenset({"step-release"})))
    return ctx

@case("p7i_digest_substitution")
def _(ctx):
    ctx["p7i"] = replace_upstream(ctx["p7i"], assessment_evidence_sha256="f" * 64)
    return ctx

@case("p7i_binding_flag_downgrade")
def _(ctx):
    ctx["p7i"] = replace_upstream(ctx["p7i"], exact_architecture_binding_verified=False)
    return ctx

@case("p7i_caller_summary_trusted")
def _(ctx):
    ctx["p7i"] = replace_upstream(ctx["p7i"], caller_declared_architecture_safety_trusted=True)
    return ctx

@case("p7i_required_invariant_unsafe")
def _(ctx):
    ctx.update(make_upstreams(unsafe_invariants=frozenset({"INV-TOOL-AUTHORIZATION"})))
    return ctx


@case("policy_empty_trusted_owners")
def _(ctx): return _replace_policy(ctx, trusted_owner_ids=frozenset())
@case("policy_invalid_graph_digest")
def _(ctx): return _replace_policy(ctx, expected_graph_sha256="bad")
@case("policy_invalid_p8a_digest")
def _(ctx): return _replace_policy(ctx, expected_p8a_assessment_evidence_sha256="bad")
@case("policy_invalid_p8c_digest")
def _(ctx): return _replace_policy(ctx, expected_p8c_assessment_evidence_sha256="bad")
@case("policy_invalid_p7i_digest")
def _(ctx): return _replace_policy(ctx, expected_p7i_assessment_evidence_sha256="bad")
@case("policy_zero_manifest_age")
def _(ctx): return _replace_policy(ctx, max_manifest_age_seconds=0)
@case("policy_negative_future_skew")
def _(ctx): return _replace_policy(ctx, max_future_skew_seconds=-1)
@case("policy_contract_coverage_omission")
def _(ctx): return _replace_policy(ctx, required_contract_ids=frozenset({"tool-search", "tool-ticket", "tool-release"}))
@case("policy_result_coverage_omission")
def _(ctx): return _replace_policy(ctx, required_result_ids=frozenset({"result-search", "result-ticket", "result-release"}))
@case("policy_observation_coverage_omission")
def _(ctx): return _replace_policy(ctx, required_observation_ids=frozenset({"obs-search", "obs-ticket", "obs-release"}))


for tool in ("tool-search", "tool-ticket", "tool-release", "tool-telemetry"):
    case(f"contract_{tool}_owner_substitution")(lambda ctx, tool=tool: _semantic(ctx, "contracts", tool, owner_id="attacker"))
    case(f"contract_{tool}_tenant_scope_substitution")(lambda ctx, tool=tool: _semantic(ctx, "contracts", tool, tenant_scope="attacker-tenant"))
    case(f"contract_{tool}_effect_substitution")(lambda ctx, tool=tool: _semantic(ctx, "contracts", tool, effect=ToolEffect.READ_ONLY if tool != "tool-search" else ToolEffect.MUTATING))
    case(f"contract_{tool}_authority_substitution")(lambda ctx, tool=tool: _semantic(ctx, "contracts", tool, authoritative_result=not next(x for x in ctx["manifest"].contracts if x.tool_id == tool).authoritative_result))
    case(f"contract_{tool}_freshness_widening")(lambda ctx, tool=tool: _semantic(ctx, "contracts", tool, max_result_age_seconds=999999))
    case(f"contract_{tool}_invariant_omission")(lambda ctx, tool=tool: _semantic(ctx, "contracts", tool, required_p7i_invariant_ids=()))


for sid in ("snap-tenant-v10", "snap-tenant-v11", "snap-release-v42", "snap-release-v43", "snap-security-v7", "snap-security-v8"):
    case(f"snapshot_{sid}_owner_substitution")(lambda ctx, sid=sid: _semantic(ctx, "snapshots", sid, owner_id="attacker"))
    case(f"snapshot_{sid}_tenant_substitution")(lambda ctx, sid=sid: _semantic(ctx, "snapshots", sid, tenant_id="attacker-tenant"))
    case(f"snapshot_{sid}_state_digest_substitution")(lambda ctx, sid=sid: _semantic(ctx, "snapshots", sid, state_sha256=sha(f"spoof-{sid}")))


for iid in ("invoke-search", "invoke-ticket", "invoke-release", "invoke-telemetry"):
    case(f"invocation_{iid}_owner_substitution")(lambda ctx, iid=iid: _semantic(ctx, "invocations", iid, owner_id="attacker"))
    case(f"invocation_{iid}_tool_substitution")(lambda ctx, iid=iid: _semantic(ctx, "invocations", iid, tool_id="tool-search" if iid != "invoke-search" else "tool-ticket"))
    case(f"invocation_{iid}_tenant_substitution")(lambda ctx, iid=iid: _semantic(ctx, "invocations", iid, tenant_id="attacker-tenant"))
    case(f"invocation_{iid}_principal_substitution")(lambda ctx, iid=iid: _semantic(ctx, "invocations", iid, original_principal_id="attacker"))
    case(f"invocation_{iid}_task_substitution")(lambda ctx, iid=iid: _semantic(ctx, "invocations", iid, task_id="attacker-task"))
    case(f"invocation_{iid}_goal_substitution")(lambda ctx, iid=iid: _semantic(ctx, "invocations", iid, goal_id="attacker-goal"))
    case(f"invocation_{iid}_step_substitution")(lambda ctx, iid=iid: _semantic(ctx, "invocations", iid, step_id="attacker-step"))
    case(f"invocation_{iid}_args_substitution")(lambda ctx, iid=iid: _semantic(ctx, "invocations", iid, args_sha256=sha(f"attacker-args-{iid}")))


for rid in ("result-search", "result-ticket", "result-release", "result-telemetry"):
    case(f"result_{rid}_owner_substitution")(lambda ctx, rid=rid: _semantic(ctx, "results", rid, owner_id="attacker"))
    case(f"result_{rid}_invocation_substitution")(lambda ctx, rid=rid: _semantic(ctx, "results", rid, invocation_id="invoke-search" if rid != "result-search" else "invoke-ticket"))
    case(f"result_{rid}_tool_substitution")(lambda ctx, rid=rid: _semantic(ctx, "results", rid, tool_id="tool-search" if rid != "result-search" else "tool-ticket"))
    case(f"result_{rid}_args_substitution")(lambda ctx, rid=rid: _semantic(ctx, "results", rid, args_sha256=sha(f"bad-args-{rid}")))
    case(f"result_{rid}_nonce_replay")(lambda ctx, rid=rid: _semantic(ctx, "results", rid, result_nonce="nonce-search" if rid != "result-search" else "nonce-ticket"))
    case(f"result_{rid}_future_produced_time")(lambda ctx, rid=rid: _semantic(ctx, "results", rid, produced_at_epoch=NOW + 100))
    case(f"result_{rid}_expired")(lambda ctx, rid=rid: _semantic(ctx, "results", rid, expires_at_epoch=NOW - 1))
    case(f"result_{rid}_environment_version_regression")(lambda ctx, rid=rid: _semantic(ctx, "results", rid, observed_environment_version=0))
    case(f"result_{rid}_environment_state_spoof")(lambda ctx, rid=rid: _semantic(ctx, "results", rid, observed_environment_state_sha256=sha(f"spoof-result-{rid}")))

for rid in ("result-ticket", "result-release", "result-telemetry"):
    case(f"result_{rid}_missing_side_effect_ack")(lambda ctx, rid=rid: _semantic(ctx, "results", rid, side_effect_ack_sha256=None))
    case(f"result_{rid}_forged_side_effect_ack")(lambda ctx, rid=rid: _semantic(ctx, "results", rid, side_effect_ack_sha256="a" * 64))
    case(f"result_{rid}_attestation_removed")(lambda ctx, rid=rid: _semantic(ctx, "results", rid, attestation_sha256=None))
    case(f"result_{rid}_attestation_substitution")(lambda ctx, rid=rid: _semantic(ctx, "results", rid, attestation_sha256=sha(f"forged-attestation-{rid}")))


for oid in ("obs-search", "obs-ticket", "obs-release", "obs-telemetry"):
    case(f"observation_{oid}_owner_substitution")(lambda ctx, oid=oid: _semantic(ctx, "observations", oid, owner_id="attacker"))
    case(f"observation_{oid}_result_substitution")(lambda ctx, oid=oid: _semantic(ctx, "observations", oid, result_id="result-search" if oid != "obs-search" else "result-ticket"))
    case(f"observation_{oid}_invocation_substitution")(lambda ctx, oid=oid: _semantic(ctx, "observations", oid, invocation_id="invoke-search" if oid != "obs-search" else "invoke-ticket"))
    case(f"observation_{oid}_tool_substitution")(lambda ctx, oid=oid: _semantic(ctx, "observations", oid, tool_id="tool-search" if oid != "obs-search" else "tool-ticket"))
    case(f"observation_{oid}_principal_substitution")(lambda ctx, oid=oid: _semantic(ctx, "observations", oid, original_principal_id="attacker"))
    case(f"observation_{oid}_tenant_substitution")(lambda ctx, oid=oid: _semantic(ctx, "observations", oid, tenant_id="attacker-tenant"))
    case(f"observation_{oid}_task_substitution")(lambda ctx, oid=oid: _semantic(ctx, "observations", oid, task_id="attacker-task"))
    case(f"observation_{oid}_goal_substitution")(lambda ctx, oid=oid: _semantic(ctx, "observations", oid, goal_id="attacker-goal"))
    case(f"observation_{oid}_step_substitution")(lambda ctx, oid=oid: _semantic(ctx, "observations", oid, step_id="attacker-step"))
    case(f"observation_{oid}_environment_version_regression")(lambda ctx, oid=oid: _semantic(ctx, "observations", oid, environment_version=0))
    case(f"observation_{oid}_environment_state_spoof")(lambda ctx, oid=oid: _semantic(ctx, "observations", oid, environment_state_sha256=sha(f"spoof-observation-{oid}")))

@case("observation_search_authority_laundering")
def _(ctx): return _semantic(ctx, "observations", "obs-search", claimed_trust=ObservationTrust.VERIFIED)

EXPECTED_ADVERSARIAL_CASES = len(ADVERSARIAL_CASES)


def _hardened_attack_succeeds(ctx: dict) -> bool:
    try:
        result = AgentToolObservationIntegrityAnalyzer(ctx["policy"]).evaluate(ctx["request"], ctx["manifest"], ctx["p8a"], ctx["p8c"], ctx["p7i"])
    except (ToolObservationSecurityRejected, ValueError, KeyError, TypeError):
        return False
    return result.denied_observation_count == 0


def _vulnerable_attack_succeeds(_: dict) -> bool:
    report = VulnerableDeclaredToolObservationSafety().evaluate(
        declared_tool_success=True,
        declared_observation_authoritative=True,
        declared_denied_observation_count=0,
        declared_maximum_risk_score=0,
    )
    return report.accepted


def benign_contexts():
    unsafe = truthful_unsafe_contexts()
    return (
        ("clean", build_fixture()),
        ("truthful_replay_denial", unsafe["replay"]),
        ("truthful_environment_spoof_denial", unsafe["environment"]),
    )


def dataset_sha256() -> str:
    payload = json.dumps([case_id for case_id, _ in ADVERSARIAL_CASES], separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def fixture_sha256() -> str:
    ctx = build_fixture()
    payload = {
        "graph_sha256": ctx["request"].graph_sha256,
        "p8a": ctx["request"].p8a_assessment_evidence_sha256,
        "p8c": ctx["request"].p8c_assessment_evidence_sha256,
        "p7i": ctx["request"].p7i_assessment_evidence_sha256,
        "observations": list(ctx["request"].observation_ids),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run() -> dict[str, object]:
    vulnerable_successes = 0
    hardened_successes = 0
    for _, mutation in ADVERSARIAL_CASES:
        ctx = mutation(_clone())
        vulnerable_successes += int(_vulnerable_attack_succeeds(ctx))
        hardened_successes += int(_hardened_attack_succeeds(ctx))

    benign_failures = 0
    safe_tasks = 0
    for _, ctx in benign_contexts():
        try:
            AgentToolObservationIntegrityAnalyzer(ctx["policy"]).evaluate(ctx["request"], ctx["manifest"], ctx["p8a"], ctx["p8c"], ctx["p7i"])
            safe_tasks += 1
        except Exception:
            benign_failures += 1

    base = build_fixture()
    result = {
        "adversarial_cases": EXPECTED_ADVERSARIAL_CASES,
        "vulnerable_asr": f"{vulnerable_successes}/{EXPECTED_ADVERSARIAL_CASES}",
        "hardened_asr": f"{hardened_successes}/{EXPECTED_ADVERSARIAL_CASES}",
        "hardened_fpr": f"{benign_failures}/3",
        "safe_task_rate": f"{safe_tasks}/3",
        "graph_sha256": base["request"].graph_sha256,
        "dataset_sha256": dataset_sha256(),
        "fixture_sha256": fixture_sha256(),
    }
    print(json.dumps(result, sort_keys=True))
    return result


if __name__ == "__main__":
    run()
