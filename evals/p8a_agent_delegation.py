from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Callable

from aegis.agentic.delegation_security import (
    AgentRole,
    DelegationDecision,
    DelegationRisk,
    DelegationSecurityRejected,
    MultiAgentDelegationSecurityAnalyzer,
    TenantScope,
    agent_delegation_manifest_digest,
)
from aegis.vulnerable.agent_delegation import VulnerableDeclaredDelegationAuthorization
from evals.p8a_fixture import (
    AGENT_OBSERVABILITY,
    AGENT_ORCH_A,
    AGENT_RETRIEVAL_A,
    AGENT_RELEASE,
    AGENT_SECURITY,
    AGENT_TOOL_BROKER_A,
    AGENT_TOOL_EXECUTOR_A,
    CAP_MODEL_DEPLOY,
    CAP_SEARCH_READ,
    CAP_TENANT_RETRIEVE,
    CAP_TOOL_READ,
    CAP_TOOL_WRITE,
    DELEGATION_IDS,
    NOW,
    P7B_SHA,
    P7H_SHA,
    P7I_SHA,
    build_fixture,
    make_upstreams,
    replace_manifest_item,
    truthful_request_for_context,
)

Mutation = Callable[[dict[str, object]], dict[str, object]]


def _clone() -> dict[str, object]:
    return dict(build_fixture())


def _repin(ctx: dict[str, object]) -> dict[str, object]:
    digest = agent_delegation_manifest_digest(ctx["manifest"])
    ctx["policy"] = replace(ctx["policy"], expected_graph_sha256=digest)
    ctx["request"] = replace(ctx["request"], graph_sha256=digest)
    return ctx


def _request(field: str, value: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["request"] = replace(ctx["request"], **{field: value})
        return ctx
    return mutate


def _manifest(field: str, value: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["manifest"] = replace(ctx["manifest"], **{field: value})
        return ctx
    return mutate


def _item(collection: str, item_id: str, **changes: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx["manifest"] = replace_manifest_item(ctx["manifest"], collection, item_id, **changes)
        return _repin(ctx)
    return mutate


def _drop(collection: str, key: str, item_id: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        values = tuple(item for item in getattr(ctx["manifest"], collection) if getattr(item, key) != item_id)
        ctx["manifest"] = replace(ctx["manifest"], **{collection: values})
        return _repin(ctx)
    return mutate


def _duplicate(collection: str, key: str, item_id: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        values = list(getattr(ctx["manifest"], collection))
        item = next(item for item in values if getattr(item, key) == item_id)
        values.append(item)
        ctx["manifest"] = replace(ctx["manifest"], **{collection: tuple(values)})
        return _repin(ctx)
    return mutate


def _upstream(source: str, **changes: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx[source] = SimpleNamespace(**{**vars(ctx[source]), **changes})
        return ctx
    return mutate


def _duplicate_upstream(source: str, collection: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        values = tuple(getattr(ctx[source], collection))
        ctx[source] = SimpleNamespace(**{**vars(ctx[source]), collection: values + (values[0],)})
        return ctx
    return mutate


def _policy_map_omit(field: str, key: str) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        mapping = dict(getattr(ctx["policy"], field))
        mapping.pop(key)
        ctx["policy"] = replace(ctx["policy"], **{field: mapping})
        return ctx
    return mutate


def _policy_principal_map_mismatch(ctx: dict[str, object]) -> dict[str, object]:
    mapping = dict(ctx["policy"].original_principal_allowed_task_classes)
    mapping.pop("user-limited")
    ctx["policy"] = replace(ctx["policy"], original_principal_allowed_task_classes=mapping)
    return ctx


def _policy_agent_depth_over_global(ctx: dict[str, object]) -> dict[str, object]:
    mapping = dict(ctx["policy"].expected_agent_max_depth)
    mapping[AGENT_ORCH_A] = 4
    ctx["policy"] = replace(ctx["policy"], expected_agent_max_depth=mapping)
    return ctx


def _policy_principal_no_tasks(ctx: dict[str, object]) -> dict[str, object]:
    mapping = dict(ctx["policy"].original_principal_allowed_task_classes)
    mapping["user-a"] = frozenset()
    ctx["policy"] = replace(ctx["policy"], original_principal_allowed_task_classes=mapping)
    return ctx


def _cycle(ctx: dict[str, object]) -> dict[str, object]:
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "delegations", "delegation-tool-root", parent_delegation_id="delegation-tool-child")
    return _repin(ctx)


def _coherent_agent_flag(agent_id: str, *, accepts_delegation: bool | None = None, max_depth: int | None = None) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        changes: dict[str, object] = {}
        policy_changes: dict[str, object] = {}
        if accepts_delegation is not None:
            changes["accepts_delegation"] = accepts_delegation
            mapping = dict(ctx["policy"].expected_agent_accepts_delegation)
            mapping[agent_id] = accepts_delegation
            policy_changes["expected_agent_accepts_delegation"] = mapping
        if max_depth is not None:
            changes["max_delegation_depth"] = max_depth
            mapping = dict(ctx["policy"].expected_agent_max_depth)
            mapping[agent_id] = max_depth
            policy_changes["expected_agent_max_depth"] = mapping
        ctx["manifest"] = replace_manifest_item(ctx["manifest"], "agents", agent_id, **changes)
        ctx["policy"] = replace(ctx["policy"], **policy_changes)
        return _repin(ctx)
    return mutate


def _coherent_capability_no_invariant(ctx: dict[str, object]) -> dict[str, object]:
    capability_id = CAP_MODEL_DEPLOY
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "capabilities", capability_id, required_p7i_invariant_ids=())
    mapping = dict(ctx["policy"].expected_capability_p7i_invariant_ids)
    mapping[capability_id] = frozenset()
    ctx["policy"] = replace(ctx["policy"], expected_capability_p7i_invariant_ids=mapping)
    return _repin(ctx)


def _unsafe_upstream(*, p7b: frozenset[str] = frozenset(), p7h: frozenset[str] = frozenset(), p7i: frozenset[str] = frozenset()) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        upstreams = make_upstreams(exposed_p7b_paths=p7b, exposed_p7h_routes=p7h, unsafe_p7i_invariants=p7i)
        ctx.update(upstreams)
        return ctx
    return mutate


# 13 request/manifest substitution cases.
REQUEST_MANIFEST_CASES: tuple[tuple[str, Mutation], ...] = (
    ("request-graph-id-substitution", _request("graph_id", "evil-graph")),
    ("request-version-substitution", _request("graph_version", "evil-version")),
    ("request-graph-digest-substitution", _request("graph_sha256", "1" * 64)),
    ("request-p7b-digest-substitution", _request("p7b_assessment_evidence_sha256", "2" * 64)),
    ("request-p7h-digest-substitution", _request("p7h_assessment_evidence_sha256", "3" * 64)),
    ("request-p7i-digest-substitution", _request("p7i_assessment_evidence_sha256", "4" * 64)),
    ("request-delegation-omission", _request("delegation_ids", tuple(sorted(set(DELEGATION_IDS) - {"delegation-retrieval"})))),
    ("request-delegation-duplicate", _request("delegation_ids", tuple(DELEGATION_IDS) + ("delegation-retrieval",))),
    ("manifest-schema-substitution", _manifest("schema_version", "evil-schema")),
    ("manifest-id-substitution", _manifest("graph_id", "evil-graph")),
    ("manifest-version-substitution", _manifest("version", "evil-version")),
    ("manifest-stale", _manifest("created_at_epoch", NOW - 90_000)),
    ("manifest-future", _manifest("created_at_epoch", NOW + 100)),
)

# 12 upstream evidence cases.
UPSTREAM_CASES: tuple[tuple[str, Mutation], ...] = (
    ("p7b-identity-binding-unverified", _upstream("p7b", exact_identity_graph_binding_verified=False)),
    ("p7b-authority-derivation-unverified", _upstream("p7b", privilege_amplification_derived_from_evidence=False)),
    ("p7b-digest-mismatch", _upstream("p7b", assessment_evidence_sha256="5" * 64)),
    ("p7b-duplicate-path", _duplicate_upstream("p7b", "paths")),
    ("p7h-control-plane-unverified", _upstream("p7h", exact_control_plane_binding_verified=False)),
    ("p7h-sod-unverified", _upstream("p7h", separation_of_duties_enforced=False)),
    ("p7h-digest-mismatch", _upstream("p7h", assessment_evidence_sha256="6" * 64)),
    ("p7h-duplicate-route", _duplicate_upstream("p7h", "routes")),
    ("p7i-catalog-unverified", _upstream("p7i", exact_catalog_binding_verified=False)),
    ("p7i-blast-radius-unverified", _upstream("p7i", blast_radius_derived_from_evidence=False)),
    ("p7i-digest-mismatch", _upstream("p7i", assessment_evidence_sha256="7" * 64)),
    ("p7i-duplicate-invariant", _duplicate_upstream("p7i", "invariants")),
)

# 14 agent-definition cases.
AGENT_CASES: tuple[tuple[str, Mutation], ...] = (
    ("agent-omission", _drop("agents", "agent_id", AGENT_OBSERVABILITY)),
    ("agent-duplicate", _duplicate("agents", "agent_id", AGENT_OBSERVABILITY)),
    ("agent-owner-untrusted", _item("agents", AGENT_OBSERVABILITY, owner_id="attacker")),
    ("agent-trust-domain-untrusted", _item("agents", AGENT_OBSERVABILITY, trust_domain="attacker-domain")),
    ("agent-role-drift", _item("agents", AGENT_OBSERVABILITY, role=AgentRole.RELEASE_AGENT)),
    ("agent-tenant-drift", _item("agents", AGENT_OBSERVABILITY, tenant_id="tenant-b")),
    ("agent-trust-domain-drift", _item("agents", AGENT_RELEASE, trust_domain="security-control")),
    ("agent-capability-drift", _item("agents", AGENT_TOOL_BROKER_A, maximum_capability_ids=(CAP_TOOL_READ,))),
    ("agent-p7b-path-drift", _item("agents", AGENT_TOOL_BROKER_A, p7b_path_ids=("path-tool-executor-a",))),
    ("agent-p7b-path-unknown", _item("agents", AGENT_TOOL_BROKER_A, p7b_path_ids=("path-unknown",))),
    ("agent-p7h-route-drift", _item("agents", AGENT_RELEASE, p7h_route_ids=())),
    ("agent-p7h-route-unknown", _item("agents", AGENT_RELEASE, p7h_route_ids=("route-unknown",))),
    ("agent-accepts-delegation-drift", _item("agents", AGENT_RELEASE, accepts_delegation=False)),
    ("agent-depth-drift", _item("agents", AGENT_RELEASE, max_delegation_depth=1)),
)

# 10 capability-definition cases.
CAPABILITY_CASES: tuple[tuple[str, Mutation], ...] = (
    ("capability-omission", _drop("capabilities", "capability_id", CAP_MODEL_DEPLOY)),
    ("capability-duplicate", _duplicate("capabilities", "capability_id", CAP_MODEL_DEPLOY)),
    ("capability-family-drift", _item("capabilities", CAP_MODEL_DEPLOY, family="policy")),
    ("capability-level-drift", _item("capabilities", CAP_MODEL_DEPLOY, privilege_level=1)),
    ("capability-scope-drift", _item("capabilities", CAP_MODEL_DEPLOY, tenant_scope=TenantScope.TENANT_BOUND)),
    ("capability-privileged-drift", _item("capabilities", CAP_MODEL_DEPLOY, privileged=False)),
    ("capability-route-drift", _item("capabilities", CAP_MODEL_DEPLOY, required_p7h_route_ids=())),
    ("capability-invariant-drift", _item("capabilities", CAP_MODEL_DEPLOY, required_p7i_invariant_ids=())),
    ("capability-route-unknown", _item("capabilities", CAP_MODEL_DEPLOY, required_p7h_route_ids=("route-unknown",))),
    ("capability-invariant-unknown", _item("capabilities", CAP_MODEL_DEPLOY, required_p7i_invariant_ids=("INV-UNKNOWN",))),
)

# 6 malformed-policy cases.
POLICY_CASES: tuple[tuple[str, Mutation], ...] = (
    ("policy-agent-map-coverage-omission", _policy_map_omit("expected_agent_role", AGENT_OBSERVABILITY)),
    ("policy-capability-map-coverage-omission", _policy_map_omit("expected_capability_family", CAP_MODEL_DEPLOY)),
    ("policy-original-principal-map-mismatch", _policy_principal_map_mismatch),
    ("policy-max-chain-depth-zero", lambda ctx: {**ctx, "policy": replace(ctx["policy"], max_chain_depth=0)}),
    ("policy-agent-depth-over-global", _policy_agent_depth_over_global),
    ("policy-principal-without-tasks", _policy_principal_no_tasks),
)

# 14 malformed delegation-record cases.
DELEGATION_STRUCTURE_CASES: tuple[tuple[str, Mutation], ...] = (
    ("delegation-omission", _drop("delegations", "delegation_id", "delegation-retrieval")),
    ("delegation-duplicate", _duplicate("delegations", "delegation_id", "delegation-retrieval")),
    ("delegation-owner-untrusted", _item("delegations", "delegation-retrieval", owner_id="attacker")),
    ("delegator-agent-unknown", _item("delegations", "delegation-retrieval", delegator_agent_id="agent-unknown")),
    ("delegatee-agent-unknown", _item("delegations", "delegation-retrieval", delegatee_agent_id="agent-unknown")),
    ("original-principal-unknown", _item("delegations", "delegation-retrieval", original_principal_id="principal-unknown")),
    ("delegation-capability-empty", _item("delegations", "delegation-retrieval", requested_capability_ids=())),
    ("delegation-capability-duplicate", _item("delegations", "delegation-retrieval", requested_capability_ids=(CAP_SEARCH_READ, CAP_SEARCH_READ))),
    ("delegation-capability-unknown", _item("delegations", "delegation-retrieval", requested_capability_ids=("capability.unknown",))),
    ("delegation-parent-unknown", _item("delegations", "delegation-retrieval", parent_delegation_id="delegation-unknown")),
    ("delegation-provenance-hash-invalid", _item("delegations", "delegation-retrieval", original_request_sha256="not-a-hash")),
    ("delegation-issued-future", _item("delegations", "delegation-retrieval", issued_at_epoch=NOW + 100)),
    ("delegation-expiry-before-issue", _item("delegations", "delegation-retrieval", expires_at_epoch=NOW - 200)),
    ("delegation-cycle", _cycle),
)

# 18 semantically valid-but-unsafe delegation cases. Each graph is coherently re-pinned.
SEMANTIC_CASES: tuple[tuple[str, Mutation], ...] = (
    ("cross-tenant-handoff", _item("delegations", "delegation-retrieval", tenant_id="tenant-b")),
    ("confused-deputy-tool-write", _item("delegations", "delegation-tool-root", original_principal_id="user-limited", requested_capability_ids=(CAP_TOOL_WRITE,))),
    ("capability-laundering-child-write", _item("delegations", "delegation-tool-child", requested_capability_ids=(CAP_TOOL_WRITE,))),
    ("chain-discontinuity", _item("delegations", "delegation-tool-child", delegator_agent_id=AGENT_ORCH_A)),
    ("identity-continuity-principal-swap", _item("delegations", "delegation-tool-child", original_principal_id="user-limited")),
    ("provenance-digest-substitution", _item("delegations", "delegation-tool-child", original_request_sha256=hashlib.sha256(b"substituted").hexdigest())),
    ("child-expiry-extends-parent", _item("delegations", "delegation-tool-child", expires_at_epoch=NOW + 1900)),
    ("expired-delegation", _item("delegations", "delegation-retrieval", expires_at_epoch=NOW - 1)),
    ("delegatee-not-accepting", _coherent_agent_flag(AGENT_RETRIEVAL_A, accepts_delegation=False)),
    ("exposed-p7b-authority-path", _unsafe_upstream(p7b=frozenset({"path-release-agent"}))),
    ("exposed-p7h-control-route", _unsafe_upstream(p7h=frozenset({"route-release-promote"}))),
    ("violated-p7i-release-invariant", _unsafe_upstream(p7i=frozenset({"INV-MODEL-RELEASE-INTEGRITY"}))),
    ("chain-depth-exceeds-agent-bound", _coherent_agent_flag(AGENT_TOOL_EXECUTOR_A, max_depth=1)),
    ("task-class-not-authorized", _item("delegations", "delegation-retrieval", task_class="model_release")),
    ("scope-amplification-to-system-capability", _item("delegations", "delegation-retrieval", requested_capability_ids=(CAP_MODEL_DEPLOY,))),
    ("system-capability-on-tenant-handoff", _item("delegations", "delegation-tool-root", requested_capability_ids=(CAP_MODEL_DEPLOY,))),
    ("tenant-capability-on-system-handoff", _item("delegations", "delegation-release-inspect", requested_capability_ids=(CAP_TENANT_RETRIEVE,))),
    ("privileged-capability-without-invariant", _coherent_capability_no_invariant),
)

# 3 caller-owned summary forgery cases.
CALLER_CASES: tuple[tuple[str, Mutation], ...] = (
    ("caller-declares-fake-denial", _request("declared_denied_delegation_ids", ("delegation-retrieval",))),
    ("caller-declares-fake-risk", _request("declared_risk_ids_by_delegation", {delegation_id: ((DelegationRisk.CROSS_TENANT,) if delegation_id == "delegation-retrieval" else ()) for delegation_id in DELEGATION_IDS})),
    ("caller-risk-map-omits-delegation", _request("declared_risk_ids_by_delegation", {delegation_id: () for delegation_id in DELEGATION_IDS if delegation_id != "delegation-retrieval"})),
)

ADVERSARIAL_CASES = (
    REQUEST_MANIFEST_CASES
    + UPSTREAM_CASES
    + AGENT_CASES
    + CAPABILITY_CASES
    + POLICY_CASES
    + DELEGATION_STRUCTURE_CASES
    + SEMANTIC_CASES
    + CALLER_CASES
)
EXPECTED_ADVERSARIAL_CASES = 90
assert len(ADVERSARIAL_CASES) == EXPECTED_ADVERSARIAL_CASES


def _hardened_attack_succeeds(ctx: dict[str, object]) -> bool:
    try:
        result = MultiAgentDelegationSecurityAnalyzer(ctx["policy"]).evaluate(ctx["request"], ctx["manifest"], ctx["p7b"], ctx["p7h"], ctx["p7i"])
    except DelegationSecurityRejected:
        return False
    return result.denied_delegation_count == 0


def _truthful_cross_tenant() -> dict[str, object]:
    ctx = _item("delegations", "delegation-retrieval", tenant_id="tenant-b")(_clone())
    ctx["request"] = truthful_request_for_context(ctx, {"delegation-retrieval": (DelegationRisk.CROSS_TENANT,)})
    return ctx


def _truthful_laundering() -> dict[str, object]:
    ctx = _item("delegations", "delegation-tool-child", requested_capability_ids=(CAP_TOOL_WRITE,))(_clone())
    ctx["request"] = truthful_request_for_context(ctx, {"delegation-tool-child": (DelegationRisk.CAPABILITY_LAUNDERING,)})
    return ctx


def benign_contexts() -> tuple[tuple[str, dict[str, object]], ...]:
    return (
        ("safe-delegation-graph", _clone()),
        ("truthful-cross-tenant-denial", _truthful_cross_tenant()),
        ("truthful-capability-laundering-denial", _truthful_laundering()),
    )


def run() -> dict[str, object]:
    weak = VulnerableDeclaredDelegationAuthorization()
    vulnerable_successes = 0
    hardened_successes = 0
    cases: list[dict[str, object]] = []
    for case_id, mutation in ADVERSARIAL_CASES:
        ctx = mutation(_clone())
        vulnerable = weak.evaluate(
            declared_delegation_authorized=True,
            declared_identity_continuity=True,
            declared_tenant_continuity=True,
            declared_denied_count=0,
            declared_escalation_count=0,
        ).accepted
        hardened = _hardened_attack_succeeds(ctx)
        vulnerable_successes += int(vulnerable)
        hardened_successes += int(hardened)
        cases.append({"case_id": case_id, "vulnerable_success": vulnerable, "hardened_success": hardened})

    benign_results: list[dict[str, object]] = []
    false_positives = 0
    safe_successes = 0
    for case_id, ctx in benign_contexts():
        accepted = True
        try:
            MultiAgentDelegationSecurityAnalyzer(ctx["policy"]).evaluate(ctx["request"], ctx["manifest"], ctx["p7b"], ctx["p7h"], ctx["p7i"])
        except DelegationSecurityRejected:
            accepted = False
        false_positives += int(not accepted)
        safe_successes += int(accepted)
        benign_results.append({"case_id": case_id, "accepted": accepted})

    fixture = build_fixture()
    dataset_sha = hashlib.sha256(json.dumps([case_id for case_id, _ in ADVERSARIAL_CASES], separators=(",", ":")).encode()).hexdigest()
    fixture_document = {
        "delegation_ids": list(fixture["request"].delegation_ids),
        "graph_sha256": fixture["request"].graph_sha256,
        "p7b_sha256": P7B_SHA,
        "p7h_sha256": P7H_SHA,
        "p7i_sha256": P7I_SHA,
    }
    fixture_sha = hashlib.sha256(json.dumps(fixture_document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "adversarial_cases": len(ADVERSARIAL_CASES),
        "vulnerable_asr": f"{vulnerable_successes}/{len(ADVERSARIAL_CASES)}",
        "hardened_asr": f"{hardened_successes}/{len(ADVERSARIAL_CASES)}",
        "hardened_fpr": f"{false_positives}/{len(benign_results)}",
        "safe_task_rate": f"{safe_successes}/{len(benign_results)}",
        "graph_sha256": fixture["request"].graph_sha256,
        "dataset_sha256": dataset_sha,
        "fixture_sha256": fixture_sha,
        "cases": cases,
        "benign": benign_results,
    }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2, sort_keys=True))
    assert result["adversarial_cases"] == EXPECTED_ADVERSARIAL_CASES
    assert result["vulnerable_asr"] == "90/90"
    assert result["hardened_asr"] == "0/90"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
