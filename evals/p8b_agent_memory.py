from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace
from typing import Callable

from aegis.agentic.memory_security import (
    AgentMemoryContextSecurityAnalyzer,
    MemoryClassification,
    MemoryRisk,
    MemoryScope,
    MemorySecurityRejected,
    MemoryTrust,
    agent_memory_manifest_digest,
)
from aegis.vulnerable.agent_memory import VulnerableDeclaredMemorySafety
from evals.p8b_fixture import (
    AGENT_OBSERVABILITY,
    AGENT_ORCH,
    AGENT_RETRIEVAL,
    AGENT_SECURITY,
    AGENT_TOOL_BROKER,
    AGENT_TOOL_EXECUTOR,
    DELEGATION_RETRIEVAL,
    INV_ADMIN,
    INV_TENANT,
    MEM_CURRENT_PROFILE,
    MEM_OLD_PROFILE,
    MEM_RETRIEVAL_SUMMARY,
    MEM_SECURITY_BASELINE,
    MEM_SESSION_QUERY,
    MEM_TOOL_NOTE,
    MEMORY_IDS,
    NOW,
    P7C_PATH_TENANT,
    RETRIEVAL_IDS,
    RETRIEVE_PROFILE,
    RETRIEVE_SECURITY,
    RETRIEVE_SESSION,
    RETRIEVE_SUMMARY,
    SANITIZE_SHA,
    STORE_SESSION,
    STORE_SYSTEM,
    STORE_TENANT,
    WRITE_IDS,
    WRITE_RETRIEVAL_SUMMARY,
    WRITE_SESSION_QUERY,
    WRITE_TOOL_NOTE,
    build_fixture,
    make_upstreams,
    replace_manifest_item,
    truthful_request_for_context,
)

Mutation = Callable[[dict[str, object]], dict[str, object]]


def _clone() -> dict[str, object]:
    return dict(build_fixture())


def _repin(ctx: dict[str, object]) -> dict[str, object]:
    digest = agent_memory_manifest_digest(ctx["manifest"])
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


def _cycle(ctx: dict[str, object]) -> dict[str, object]:
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "memories", MEM_SESSION_QUERY, parent_memory_ids=(MEM_RETRIEVAL_SUMMARY,))
    return _repin(ctx)


def _store_unknown_agent(ctx: dict[str, object]) -> dict[str, object]:
    store = next(item for item in ctx["manifest"].stores if item.store_id == STORE_TENANT)
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "stores", STORE_TENANT, allowed_writer_agent_ids=store.allowed_writer_agent_ids + ("agent-unknown",))
    mapping = dict(ctx["policy"].expected_store_writer_ids)
    mapping[STORE_TENANT] = frozenset(ctx["manifest"].stores[1].allowed_writer_agent_ids)
    ctx["policy"] = replace(ctx["policy"], expected_store_writer_ids=mapping)
    return _repin(ctx)


def _coherent_store_session_flag(ctx: dict[str, object]) -> dict[str, object]:
    ctx["manifest"] = replace_manifest_item(ctx["manifest"], "stores", STORE_TENANT, session_binding_required=True)
    mapping = dict(ctx["policy"].expected_store_session_binding)
    mapping[STORE_TENANT] = True
    ctx["policy"] = replace(ctx["policy"], expected_store_session_binding=mapping)
    return _repin(ctx)


def _coherent_writer_trust(agent_id: str, trust: MemoryTrust) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        mapping = dict(ctx["policy"].writer_max_trust)
        mapping[agent_id] = trust
        ctx["policy"] = replace(ctx["policy"], writer_max_trust=mapping)
        return ctx
    return mutate


def _unsafe_upstreams(*, denied: frozenset[str] = frozenset(), p7c: frozenset[str] = frozenset(), p7i: frozenset[str] = frozenset()) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        ctx.update(make_upstreams(denied_delegations=denied, exposed_p7c_paths=p7c, unsafe_p7i_invariants=p7i))
        return ctx
    return mutate


def _retrieval_value(retrieval_id: str, field: str, memory_id: str, value: object) -> Mutation:
    def mutate(ctx: dict[str, object]) -> dict[str, object]:
        retrieval = next(item for item in ctx["manifest"].retrievals if item.retrieval_id == retrieval_id)
        mapping = dict(getattr(retrieval, field))
        mapping[memory_id] = value
        ctx["manifest"] = replace_manifest_item(ctx["manifest"], "retrievals", retrieval_id, **{field: mapping})
        return _repin(ctx)
    return mutate


REQUEST_MANIFEST_CASES: tuple[tuple[str, Mutation], ...] = (
    ("request-graph-id-substitution", _request("graph_id", "evil-graph")),
    ("request-version-substitution", _request("graph_version", "evil-version")),
    ("request-graph-digest-substitution", _request("graph_sha256", "1" * 64)),
    ("request-p8a-digest-substitution", _request("p8a_assessment_evidence_sha256", "2" * 64)),
    ("request-p7c-digest-substitution", _request("p7c_assessment_evidence_sha256", "3" * 64)),
    ("request-p7i-digest-substitution", _request("p7i_assessment_evidence_sha256", "4" * 64)),
    ("request-write-omission", _request("write_ids", tuple(sorted(set(WRITE_IDS) - {WRITE_TOOL_NOTE})))),
    ("request-write-duplicate", _request("write_ids", tuple(WRITE_IDS) + (WRITE_TOOL_NOTE,))),
    ("request-retrieval-omission", _request("retrieval_ids", tuple(sorted(set(RETRIEVAL_IDS) - {RETRIEVE_SUMMARY})))),
    ("request-retrieval-duplicate", _request("retrieval_ids", tuple(RETRIEVAL_IDS) + (RETRIEVE_SUMMARY,))),
    ("manifest-schema-substitution", _manifest("schema_version", "evil-schema")),
    ("manifest-id-substitution", _manifest("graph_id", "evil-graph")),
    ("manifest-version-substitution", _manifest("version", "evil-version")),
    ("manifest-stale", _manifest("created_at_epoch", NOW - 90_000)),
    ("manifest-future", _manifest("created_at_epoch", NOW + 100)),
)

UPSTREAM_CASES: tuple[tuple[str, Mutation], ...] = (
    ("p8a-graph-binding-unverified", _upstream("p8a", exact_delegation_graph_binding_verified=False)),
    ("p8a-identity-continuity-unverified", _upstream("p8a", agent_identity_continuity_verified=False)),
    ("p8a-tenant-continuity-unverified", _upstream("p8a", tenant_continuity_verified=False)),
    ("p8a-authority-non-amplification-unverified", _upstream("p8a", authority_non_amplification_verified=False)),
    ("p8a-digest-mismatch", _upstream("p8a", assessment_evidence_sha256="5" * 64)),
    ("p8a-duplicate-delegation", _duplicate_upstream("p8a", "delegations")),
    ("p7c-data-binding-unverified", _upstream("p7c", exact_data_graph_binding_verified=False)),
    ("p7c-exfiltration-derivation-unverified", _upstream("p7c", exfiltration_derived_from_evidence=False)),
    ("p7c-digest-mismatch", _upstream("p7c", assessment_evidence_sha256="6" * 64)),
    ("p7c-duplicate-path", _duplicate_upstream("p7c", "paths")),
    ("p7i-catalog-binding-unverified", _upstream("p7i", exact_catalog_binding_verified=False)),
    ("p7i-blast-radius-unverified", _upstream("p7i", blast_radius_derived_from_evidence=False)),
    ("p7i-counterevidence-unverified", _upstream("p7i", counterevidence_preserved=False)),
    ("p7i-digest-mismatch", _upstream("p7i", assessment_evidence_sha256="7" * 64)),
    ("p7i-duplicate-invariant", _duplicate_upstream("p7i", "invariants")),
)

STORE_CASES: tuple[tuple[str, Mutation], ...] = (
    ("store-omission", _drop("stores", "store_id", STORE_SYSTEM)),
    ("store-duplicate", _duplicate("stores", "store_id", STORE_TENANT)),
    ("store-owner-untrusted", _item("stores", STORE_TENANT, owner_id="attacker")),
    ("store-scope-drift", _item("stores", STORE_TENANT, scope=MemoryScope.SYSTEM)),
    ("store-tenant-drift", _item("stores", STORE_TENANT, tenant_id="tenant-b")),
    ("store-session-policy-drift", _item("stores", STORE_TENANT, session_binding_required=True)),
    ("store-writer-drift", _item("stores", STORE_TENANT, allowed_writer_agent_ids=(AGENT_RETRIEVAL,))),
    ("store-reader-drift", _item("stores", STORE_TENANT, allowed_reader_agent_ids=(AGENT_RETRIEVAL,))),
    ("store-unknown-agent", _store_unknown_agent),
    ("store-classification-drift", _item("stores", STORE_TENANT, maximum_classification=MemoryClassification.RESTRICTED)),
    ("store-trust-drift", _item("stores", STORE_TENANT, minimum_persisted_trust=MemoryTrust.USER_ASSERTED)),
    ("store-retention-drift", _item("stores", STORE_TENANT, retention_seconds=999)),
    ("store-invariant-drift", _item("stores", STORE_TENANT, required_p7i_invariant_ids=(INV_TENANT,))),
    ("store-invariant-unknown", _item("stores", STORE_TENANT, required_p7i_invariant_ids=("INV-UNKNOWN",))),
)

MEMORY_CASES: tuple[tuple[str, Mutation], ...] = (
    ("memory-omission", _drop("memories", "memory_id", MEM_TOOL_NOTE)),
    ("memory-duplicate", _duplicate("memories", "memory_id", MEM_TOOL_NOTE)),
    ("memory-owner-untrusted", _item("memories", MEM_TOOL_NOTE, owner_id="attacker")),
    ("memory-store-unknown", _item("memories", MEM_TOOL_NOTE, store_id="store-unknown")),
    ("memory-content-digest-invalid", _item("memories", MEM_TOOL_NOTE, content_sha256="bad")),
    ("memory-source-digest-invalid", _item("memories", MEM_TOOL_NOTE, source_context_sha256="bad")),
    ("memory-creator-unknown", _item("memories", MEM_TOOL_NOTE, created_by_agent_id="agent-unknown")),
    ("memory-principal-unknown", _item("memories", MEM_TOOL_NOTE, original_principal_id="principal-unknown")),
    ("memory-delegation-unknown", _item("memories", MEM_TOOL_NOTE, delegation_id="delegation-unknown")),
    ("memory-parent-duplicate", _item("memories", MEM_TOOL_NOTE, parent_memory_ids=(MEM_RETRIEVAL_SUMMARY, MEM_RETRIEVAL_SUMMARY))),
    ("memory-parent-unknown", _item("memories", MEM_TOOL_NOTE, parent_memory_ids=("memory-unknown",))),
    ("memory-p7c-duplicate", _item("memories", MEM_TOOL_NOTE, p7c_path_ids=(P7C_PATH_TENANT, P7C_PATH_TENANT))),
    ("memory-p7c-unknown", _item("memories", MEM_TOOL_NOTE, p7c_path_ids=("path-unknown",))),
    ("memory-supersedes-unknown", _item("memories", MEM_CURRENT_PROFILE, supersedes_memory_id="memory-unknown")),
    ("memory-sanitization-evidence-invalid", _item("memories", MEM_TOOL_NOTE, sanitization_evidence_sha256="8" * 64)),
    ("memory-unsanitized-carries-evidence", _item("memories", MEM_TOOL_NOTE, sanitized=False)),
    ("memory-expiry-invalid", _item("memories", MEM_TOOL_NOTE, expires_at_epoch=NOW - 500)),
    ("memory-revocation-before-creation", _item("memories", MEM_TOOL_NOTE, revoked_at_epoch=NOW - 1000)),
    ("memory-provenance-cycle", _cycle),
)

WRITE_CASES: tuple[tuple[str, Mutation], ...] = (
    ("write-omission", _drop("writes", "write_id", WRITE_TOOL_NOTE)),
    ("write-duplicate", _duplicate("writes", "write_id", WRITE_TOOL_NOTE)),
    ("write-owner-untrusted", _item("writes", WRITE_TOOL_NOTE, owner_id="attacker")),
    ("write-memory-unknown", _item("writes", WRITE_TOOL_NOTE, memory_id="memory-unknown")),
    ("write-agent-unknown", _item("writes", WRITE_TOOL_NOTE, writer_agent_id="agent-unknown")),
    ("write-principal-unknown", _item("writes", WRITE_TOOL_NOTE, original_principal_id="principal-unknown")),
    ("write-delegation-unknown", _item("writes", WRITE_TOOL_NOTE, delegation_id="delegation-unknown")),
    ("write-source-digest-invalid", _item("writes", WRITE_TOOL_NOTE, source_context_sha256="bad")),
    ("write-future-dated", _item("writes", WRITE_TOOL_NOTE, issued_at_epoch=NOW + 100)),
)

RETRIEVAL_CASES: tuple[tuple[str, Mutation], ...] = (
    ("retrieval-omission", _drop("retrievals", "retrieval_id", RETRIEVE_SUMMARY)),
    ("retrieval-duplicate", _duplicate("retrievals", "retrieval_id", RETRIEVE_SUMMARY)),
    ("retrieval-owner-untrusted", _item("retrievals", RETRIEVE_SUMMARY, owner_id="attacker")),
    ("retrieval-reader-unknown", _item("retrievals", RETRIEVE_SUMMARY, reader_agent_id="agent-unknown")),
    ("retrieval-principal-unknown", _item("retrievals", RETRIEVE_SUMMARY, original_principal_id="principal-unknown")),
    ("retrieval-memory-empty", _item("retrievals", RETRIEVE_SUMMARY, memory_ids=())),
    ("retrieval-memory-duplicate", _item("retrievals", RETRIEVE_SUMMARY, memory_ids=(MEM_RETRIEVAL_SUMMARY, MEM_RETRIEVAL_SUMMARY))),
    ("retrieval-memory-unknown", _item("retrievals", RETRIEVE_SUMMARY, memory_ids=("memory-unknown",))),
    ("retrieval-trust-map-coverage-mismatch", _item("retrievals", RETRIEVE_SUMMARY, declared_trust_by_memory={MEM_RETRIEVAL_SUMMARY: MemoryTrust.DELEGATED})),
    ("retrieval-class-map-coverage-mismatch", _item("retrievals", RETRIEVE_SUMMARY, declared_classification_by_memory={MEM_RETRIEVAL_SUMMARY: MemoryClassification.CONFIDENTIAL})),
    ("retrieval-future-dated", _item("retrievals", RETRIEVE_SUMMARY, issued_at_epoch=NOW + 100)),
)

POLICY_CASES: tuple[tuple[str, Mutation], ...] = (
    ("policy-store-map-coverage-omission", _policy_map_omit("expected_store_scope", STORE_TENANT)),
    ("policy-writer-trust-map-coverage-omission", _policy_map_omit("writer_max_trust", AGENT_ORCH)),
    ("policy-retention-zero", lambda ctx: {**ctx, "policy": replace(ctx["policy"], expected_store_retention_seconds={**ctx["policy"].expected_store_retention_seconds, STORE_TENANT: 0})}),
    ("policy-sanitization-hash-invalid", lambda ctx: {**ctx, "policy": replace(ctx["policy"], allowed_sanitization_evidence_sha256=frozenset({"bad"}))}),
    ("policy-known-agents-empty", lambda ctx: {**ctx, "policy": replace(ctx["policy"], known_agent_ids=frozenset())}),
    ("policy-principals-empty", lambda ctx: {**ctx, "policy": replace(ctx["policy"], original_principal_tenant={})}),
)

SEMANTIC_CASES: tuple[tuple[str, Mutation], ...] = (
    ("writer-not-authorized-for-store", _item("writes", WRITE_RETRIEVAL_SUMMARY, writer_agent_id=AGENT_TOOL_EXECUTOR)),
    ("cross-tenant-write", _item("writes", WRITE_RETRIEVAL_SUMMARY, tenant_id="tenant-b")),
    ("cross-session-write", _item("writes", WRITE_SESSION_QUERY, session_id="session-a-2")),
    ("write-source-provenance-mismatch", _item("writes", WRITE_RETRIEVAL_SUMMARY, source_context_sha256=hashlib.sha256(b"mismatch").hexdigest())),
    ("write-classification-provenance-mismatch", _item("writes", WRITE_RETRIEVAL_SUMMARY, requested_classification=MemoryClassification.INTERNAL)),
    ("write-trust-provenance-mismatch", _item("writes", WRITE_RETRIEVAL_SUMMARY, requested_trust_label=MemoryTrust.USER_ASSERTED)),
    ("memory-creator-write-mismatch", _item("memories", MEM_RETRIEVAL_SUMMARY, created_by_agent_id=AGENT_ORCH)),
    ("memory-principal-write-mismatch", _item("memories", MEM_RETRIEVAL_SUMMARY, original_principal_id="user-b")),
    ("p8a-delegation-denied", _unsafe_upstreams(denied=frozenset({DELEGATION_RETRIEVAL}))),
    ("memory-writer-trust-upgrade", _item("memories", MEM_RETRIEVAL_SUMMARY, trust_label=MemoryTrust.VERIFIED_SYSTEM)),
    ("memory-store-classification-overflow", _item("memories", MEM_RETRIEVAL_SUMMARY, classification=MemoryClassification.RESTRICTED)),
    ("memory-parent-cross-tenant", _item("memories", MEM_RETRIEVAL_SUMMARY, parent_memory_ids=(MEM_SECURITY_BASELINE,))),
    ("memory-laundering-trust-and-class", lambda ctx: _item("memories", MEM_TOOL_NOTE, trust_label=MemoryTrust.VERIFIED_SYSTEM, classification=MemoryClassification.INTERNAL, sanitized=False, sanitization_evidence_sha256=None)(ctx)),
    ("untrusted-longterm-persistence", lambda ctx: _item("memories", MEM_TOOL_NOTE, trust_label=MemoryTrust.USER_ASSERTED, source_kind="derived_summary", sanitized=False, sanitization_evidence_sha256=None)(ctx)),
    ("poisoned-user-content-persistence", lambda ctx: _item("memories", MEM_TOOL_NOTE, trust_label=MemoryTrust.USER_ASSERTED, source_kind="user_message", sanitized=False, sanitization_evidence_sha256=None)(ctx)),
    ("supersedes-cross-tenant", _item("memories", MEM_CURRENT_PROFILE, supersedes_memory_id=MEM_SECURITY_BASELINE)),
    ("retention-window-exceeded", _item("memories", MEM_CURRENT_PROFILE, expires_at_epoch=NOW + 90_000)),
    ("p7c-exposed-memory-data-path", _unsafe_upstreams(p7c=frozenset({P7C_PATH_TENANT}))),
    ("p7i-tenant-invariant-unsafe", _unsafe_upstreams(p7i=frozenset({INV_TENANT}))),
    ("retrieval-reader-unauthorized", _item("retrievals", RETRIEVE_SUMMARY, reader_agent_id=AGENT_SECURITY)),
    ("retrieval-cross-tenant", _item("retrievals", RETRIEVE_SUMMARY, tenant_id="tenant-b")),
    ("retrieval-cross-session", _item("retrievals", RETRIEVE_SESSION, session_id="session-a-2")),
    ("retrieval-revoked-memory", _item("memories", MEM_CURRENT_PROFILE, revoked_at_epoch=NOW - 1)),
    ("retrieval-expired-memory", _item("memories", MEM_CURRENT_PROFILE, expires_at_epoch=NOW - 1)),
    ("retrieval-superseded-memory", _item("retrievals", RETRIEVE_PROFILE, memory_ids=(MEM_OLD_PROFILE,), declared_trust_by_memory={MEM_OLD_PROFILE: MemoryTrust.DELEGATED}, declared_classification_by_memory={MEM_OLD_PROFILE: MemoryClassification.CONFIDENTIAL})),
    ("retrieval-trust-label-forgery", _retrieval_value(RETRIEVE_SUMMARY, "declared_trust_by_memory", MEM_TOOL_NOTE, MemoryTrust.VERIFIED_SYSTEM)),
    ("retrieval-classification-forgery", _retrieval_value(RETRIEVE_SUMMARY, "declared_classification_by_memory", MEM_TOOL_NOTE, MemoryClassification.PUBLIC)),
    ("system-store-session-context-injection", _item("writes", "write-security-baseline", session_id="session-a-1")),
    ("coherent-tenant-store-session-binding-break", _coherent_store_session_flag),
    ("writer-trust-policy-downgrade", _coherent_writer_trust(AGENT_RETRIEVAL, MemoryTrust.USER_ASSERTED)),
    ("unsafe-admin-invariant", _unsafe_upstreams(p7i=frozenset({INV_ADMIN}))),
)

CALLER_CASES: tuple[tuple[str, Mutation], ...] = (
    ("caller-fake-denied-write", _request("declared_denied_write_ids", (WRITE_TOOL_NOTE,))),
    ("caller-fake-denied-retrieval", _request("declared_denied_retrieval_ids", (RETRIEVE_SUMMARY,))),
    ("caller-write-risk-map-omission", _request("declared_write_risks", {write_id: () for write_id in WRITE_IDS if write_id != WRITE_TOOL_NOTE})),
    ("caller-retrieval-risk-map-omission", _request("declared_retrieval_risks", {retrieval_id: () for retrieval_id in RETRIEVAL_IDS if retrieval_id != RETRIEVE_SUMMARY})),
    ("caller-fake-write-risk", _request("declared_write_risks", {write_id: ((MemoryRisk.CROSS_TENANT,) if write_id == WRITE_TOOL_NOTE else ()) for write_id in WRITE_IDS})),
    ("caller-fake-retrieval-risk", _request("declared_retrieval_risks", {retrieval_id: ((MemoryRisk.REVOKED_MEMORY,) if retrieval_id == RETRIEVE_SUMMARY else ()) for retrieval_id in RETRIEVAL_IDS})),
)

ADVERSARIAL_CASES = (
    REQUEST_MANIFEST_CASES
    + UPSTREAM_CASES
    + STORE_CASES
    + MEMORY_CASES
    + WRITE_CASES
    + RETRIEVAL_CASES
    + POLICY_CASES
    + SEMANTIC_CASES
    + CALLER_CASES
)


def _hardened_attack_succeeds(ctx: dict[str, object]) -> bool:
    try:
        result = AgentMemoryContextSecurityAnalyzer(ctx["policy"]).evaluate(
            ctx["request"], ctx["manifest"], ctx["p8a"], ctx["p7c"], ctx["p7i"]
        )
    except MemorySecurityRejected:
        return False
    return result.denied_write_count == 0 and result.denied_retrieval_count == 0


def _truthful_laundering() -> dict[str, object]:
    ctx = _item(
        "memories",
        MEM_TOOL_NOTE,
        trust_label=MemoryTrust.VERIFIED_SYSTEM,
        classification=MemoryClassification.INTERNAL,
        sanitized=False,
        sanitization_evidence_sha256=None,
    )(_clone())
    ctx = _item("writes", WRITE_TOOL_NOTE, requested_trust_label=MemoryTrust.VERIFIED_SYSTEM)(ctx)
    ctx = _retrieval_value(RETRIEVE_SUMMARY, "declared_trust_by_memory", MEM_TOOL_NOTE, MemoryTrust.VERIFIED_SYSTEM)(ctx)
    ctx["request"] = truthful_request_for_context(
        ctx,
        write_risks={
            WRITE_TOOL_NOTE: (
                MemoryRisk.MEMORY_LAUNDERING,
                MemoryRisk.TRUST_UPGRADE,
                MemoryRisk.CLASSIFICATION_DOWNGRADE,
            )
        },
    )
    return ctx


def _truthful_revocation() -> dict[str, object]:
    ctx = _item("memories", MEM_CURRENT_PROFILE, revoked_at_epoch=NOW - 1)(_clone())
    ctx["request"] = truthful_request_for_context(
        ctx,
        retrieval_risks={RETRIEVE_PROFILE: (MemoryRisk.REVOKED_MEMORY,)},
    )
    return ctx


def benign_contexts() -> tuple[tuple[str, dict[str, object]], ...]:
    return (
        ("safe-memory-graph", _clone()),
        ("truthful-memory-laundering-denial", _truthful_laundering()),
        ("truthful-revoked-memory-denial", _truthful_revocation()),
    )


def run() -> dict[str, object]:
    weak = VulnerableDeclaredMemorySafety()
    vulnerable_successes = 0
    hardened_successes = 0
    cases: list[dict[str, object]] = []
    for case_id, mutation in ADVERSARIAL_CASES:
        ctx = mutation(_clone())
        vulnerable = weak.evaluate(
            declared_tenant_isolation=True,
            declared_session_isolation=True,
            declared_memory_trusted=True,
            declared_denied_write_count=0,
            declared_denied_retrieval_count=0,
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
            AgentMemoryContextSecurityAnalyzer(ctx["policy"]).evaluate(
                ctx["request"], ctx["manifest"], ctx["p8a"], ctx["p7c"], ctx["p7i"]
            )
        except MemorySecurityRejected:
            accepted = False
        false_positives += int(not accepted)
        safe_successes += int(accepted)
        benign_results.append({"case_id": case_id, "accepted": accepted})

    fixture = build_fixture()
    dataset_sha = hashlib.sha256(json.dumps([case_id for case_id, _ in ADVERSARIAL_CASES], separators=(",", ":")).encode()).hexdigest()
    fixture_document = {
        "graph_sha256": fixture["request"].graph_sha256,
        "memory_ids": list(sorted(MEMORY_IDS)),
        "p7c_sha256": fixture["request"].p7c_assessment_evidence_sha256,
        "p7i_sha256": fixture["request"].p7i_assessment_evidence_sha256,
        "p8a_sha256": fixture["request"].p8a_assessment_evidence_sha256,
        "retrieval_ids": list(fixture["request"].retrieval_ids),
        "write_ids": list(fixture["request"].write_ids),
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
    assert result["vulnerable_asr"] == f"{result['adversarial_cases']}/{result['adversarial_cases']}"
    assert result["hardened_asr"] == f"0/{result['adversarial_cases']}"
    assert result["hardened_fpr"] == "0/3"
    assert result["safe_task_rate"] == "3/3"
