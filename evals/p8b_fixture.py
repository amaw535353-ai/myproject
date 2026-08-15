from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace
from typing import Mapping

from aegis.agentic.memory_security import (
    AgentMemoryManifest,
    AgentMemoryPolicy,
    AgentMemoryRequest,
    MemoryClassification,
    MemoryRecord,
    MemoryRetrieval,
    MemoryRisk,
    MemoryScope,
    MemoryStore,
    MemoryTrust,
    MemoryWrite,
    agent_memory_manifest_digest,
)

NOW = 2_200_400_000
GRAPH_ID = "aegisdesk-agent-memory-context-graph"
GRAPH_VERSION = "2026.08-p8b.1"
P8A_SHA = hashlib.sha256(b"p8a-for-p8b").hexdigest()
P7C_SHA = hashlib.sha256(b"p7c-for-p8b").hexdigest()
P7I_SHA = hashlib.sha256(b"p7i-for-p8b").hexdigest()
SANITIZE_SHA = hashlib.sha256(b"approved-memory-sanitization-v1").hexdigest()

AGENT_ORCH = "agent-orchestrator-a"
AGENT_RETRIEVAL = "agent-retrieval-a"
AGENT_TOOL_BROKER = "agent-tool-broker-a"
AGENT_TOOL_EXECUTOR = "agent-tool-executor-a"
AGENT_SECURITY = "agent-security"
AGENT_OBSERVABILITY = "agent-observability"
AGENT_IDS = (AGENT_ORCH, AGENT_RETRIEVAL, AGENT_TOOL_BROKER, AGENT_TOOL_EXECUTOR, AGENT_SECURITY, AGENT_OBSERVABILITY)

STORE_SESSION = "memory-session-a"
STORE_TENANT = "memory-tenant-a-longterm"
STORE_SYSTEM = "memory-system-security"
STORE_IDS = (STORE_SESSION, STORE_TENANT, STORE_SYSTEM)

MEM_SESSION_QUERY = "memory-session-user-query"
MEM_RETRIEVAL_SUMMARY = "memory-tenant-retrieval-summary"
MEM_TOOL_NOTE = "memory-tenant-tool-note"
MEM_OLD_PROFILE = "memory-tenant-old-profile"
MEM_CURRENT_PROFILE = "memory-tenant-current-profile"
MEM_SECURITY_BASELINE = "memory-security-baseline"
MEMORY_IDS = (MEM_SESSION_QUERY, MEM_RETRIEVAL_SUMMARY, MEM_TOOL_NOTE, MEM_OLD_PROFILE, MEM_CURRENT_PROFILE, MEM_SECURITY_BASELINE)

WRITE_SESSION_QUERY = "write-session-user-query"
WRITE_RETRIEVAL_SUMMARY = "write-tenant-retrieval-summary"
WRITE_TOOL_NOTE = "write-tenant-tool-note"
WRITE_OLD_PROFILE = "write-tenant-old-profile"
WRITE_CURRENT_PROFILE = "write-tenant-current-profile"
WRITE_SECURITY_BASELINE = "write-security-baseline"
WRITE_IDS = (WRITE_SESSION_QUERY, WRITE_RETRIEVAL_SUMMARY, WRITE_TOOL_NOTE, WRITE_OLD_PROFILE, WRITE_CURRENT_PROFILE, WRITE_SECURITY_BASELINE)

RETRIEVE_SESSION = "retrieve-session-query"
RETRIEVE_SUMMARY = "retrieve-tenant-summary"
RETRIEVE_PROFILE = "retrieve-current-profile"
RETRIEVE_SECURITY = "retrieve-security-baseline"
RETRIEVAL_IDS = (RETRIEVE_SESSION, RETRIEVE_SUMMARY, RETRIEVE_PROFILE, RETRIEVE_SECURITY)

DELEGATION_RETRIEVAL = "delegation-retrieval-allow"
DELEGATION_TOOL = "delegation-tool-allow"
P7C_PATH_TENANT = "data-tenant-memory"
P7C_PATH_TOOL = "data-tool-memory"
P7C_PATH_SECURITY = "data-security-memory"
INV_TENANT = "INV-TENANT-DATA-CONFINEMENT"
INV_TOOL = "INV-PRIVILEGED-TOOL-AUTHZ"
INV_TELEMETRY = "INV-SECURITY-TELEMETRY-CONTINUITY"
INV_ADMIN = "INV-ADMIN-NON-SELF-BYPASS"


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _stores() -> tuple[MemoryStore, ...]:
    return (
        MemoryStore(
            STORE_SESSION,
            MemoryScope.SESSION,
            "tenant-a",
            "agent-platform",
            (AGENT_ORCH, AGENT_RETRIEVAL),
            (AGENT_ORCH, AGENT_RETRIEVAL),
            MemoryClassification.CONFIDENTIAL,
            MemoryTrust.USER_ASSERTED,
            True,
            3_600,
            (INV_TENANT,),
            "Tenant A session memory.",
        ),
        MemoryStore(
            STORE_TENANT,
            MemoryScope.TENANT,
            "tenant-a",
            "agent-platform",
            (AGENT_ORCH, AGENT_RETRIEVAL, AGENT_TOOL_BROKER),
            (AGENT_ORCH, AGENT_RETRIEVAL, AGENT_TOOL_BROKER),
            MemoryClassification.CONFIDENTIAL,
            MemoryTrust.DELEGATED,
            False,
            86_400,
            (INV_TENANT, INV_TOOL),
            "Tenant A durable agent memory.",
        ),
        MemoryStore(
            STORE_SYSTEM,
            MemoryScope.SYSTEM,
            "system",
            "security-platform",
            (AGENT_SECURITY, AGENT_OBSERVABILITY),
            (AGENT_SECURITY, AGENT_OBSERVABILITY),
            MemoryClassification.RESTRICTED,
            MemoryTrust.VERIFIED_SYSTEM,
            False,
            86_400,
            (INV_TELEMETRY, INV_ADMIN),
            "System security memory.",
        ),
    )


def _memories() -> tuple[MemoryRecord, ...]:
    return (
        MemoryRecord(
            MEM_SESSION_QUERY,
            STORE_SESSION,
            "tenant-a",
            "session-a-1",
            MemoryClassification.CONFIDENTIAL,
            MemoryTrust.USER_ASSERTED,
            _hash("session-query-content"),
            _hash("session-query-context"),
            "user_message",
            AGENT_ORCH,
            "user-a",
            None,
            (),
            (P7C_PATH_TENANT,),
            False,
            None,
            NOW - 400,
            NOW + 1_000,
            None,
            None,
            "agent-platform",
            "Current user query retained only in session memory.",
        ),
        MemoryRecord(
            MEM_RETRIEVAL_SUMMARY,
            STORE_TENANT,
            "tenant-a",
            None,
            MemoryClassification.CONFIDENTIAL,
            MemoryTrust.DELEGATED,
            _hash("retrieval-summary-content"),
            _hash("retrieval-summary-context"),
            "derived_summary",
            AGENT_RETRIEVAL,
            "user-a",
            DELEGATION_RETRIEVAL,
            (MEM_SESSION_QUERY,),
            (P7C_PATH_TENANT,),
            True,
            SANITIZE_SHA,
            NOW - 300,
            NOW + 20_000,
            None,
            None,
            "agent-platform",
            "Sanitized durable summary derived from session context.",
        ),
        MemoryRecord(
            MEM_TOOL_NOTE,
            STORE_TENANT,
            "tenant-a",
            None,
            MemoryClassification.INTERNAL,
            MemoryTrust.DELEGATED,
            _hash("tool-note-content"),
            _hash("tool-note-context"),
            "tool_result",
            AGENT_TOOL_BROKER,
            "user-a",
            DELEGATION_TOOL,
            (MEM_RETRIEVAL_SUMMARY,),
            (P7C_PATH_TOOL,),
            True,
            SANITIZE_SHA,
            NOW - 250,
            NOW + 15_000,
            None,
            None,
            "agent-platform",
            "Sanitized tool-derived durable note.",
        ),
        MemoryRecord(
            MEM_OLD_PROFILE,
            STORE_TENANT,
            "tenant-a",
            None,
            MemoryClassification.CONFIDENTIAL,
            MemoryTrust.DELEGATED,
            _hash("old-profile-content"),
            _hash("old-profile-context"),
            "verified_application_state",
            AGENT_RETRIEVAL,
            "user-a",
            DELEGATION_RETRIEVAL,
            (),
            (P7C_PATH_TENANT,),
            False,
            None,
            NOW - 1_000,
            NOW + 20_000,
            None,
            None,
            "agent-platform",
            "Previous durable tenant profile.",
        ),
        MemoryRecord(
            MEM_CURRENT_PROFILE,
            STORE_TENANT,
            "tenant-a",
            None,
            MemoryClassification.CONFIDENTIAL,
            MemoryTrust.DELEGATED,
            _hash("current-profile-content"),
            _hash("current-profile-context"),
            "verified_application_state",
            AGENT_RETRIEVAL,
            "user-a",
            DELEGATION_RETRIEVAL,
            (MEM_OLD_PROFILE,),
            (P7C_PATH_TENANT,),
            False,
            None,
            NOW - 200,
            NOW + 20_000,
            None,
            MEM_OLD_PROFILE,
            "agent-platform",
            "Current profile superseding the previous version.",
        ),
        MemoryRecord(
            MEM_SECURITY_BASELINE,
            STORE_SYSTEM,
            "system",
            None,
            MemoryClassification.RESTRICTED,
            MemoryTrust.VERIFIED_SYSTEM,
            _hash("security-baseline-content"),
            _hash("security-baseline-context"),
            "system_event",
            AGENT_SECURITY,
            "security-admin",
            None,
            (),
            (P7C_PATH_SECURITY,),
            False,
            None,
            NOW - 150,
            NOW + 20_000,
            None,
            None,
            "security-platform",
            "Verified system security context.",
        ),
    )


def _writes(memories: Mapping[str, MemoryRecord]) -> tuple[MemoryWrite, ...]:
    rows = (
        (WRITE_SESSION_QUERY, MEM_SESSION_QUERY, AGENT_ORCH, "user-a", "tenant-a", "session-a-1", None),
        (WRITE_RETRIEVAL_SUMMARY, MEM_RETRIEVAL_SUMMARY, AGENT_RETRIEVAL, "user-a", "tenant-a", None, DELEGATION_RETRIEVAL),
        (WRITE_TOOL_NOTE, MEM_TOOL_NOTE, AGENT_TOOL_BROKER, "user-a", "tenant-a", None, DELEGATION_TOOL),
        (WRITE_OLD_PROFILE, MEM_OLD_PROFILE, AGENT_RETRIEVAL, "user-a", "tenant-a", None, DELEGATION_RETRIEVAL),
        (WRITE_CURRENT_PROFILE, MEM_CURRENT_PROFILE, AGENT_RETRIEVAL, "user-a", "tenant-a", None, DELEGATION_RETRIEVAL),
        (WRITE_SECURITY_BASELINE, MEM_SECURITY_BASELINE, AGENT_SECURITY, "security-admin", "system", None, None),
    )
    result: list[MemoryWrite] = []
    for index, (write_id, memory_id, writer, principal, tenant, session, delegation) in enumerate(rows):
        memory = memories[memory_id]
        result.append(
            MemoryWrite(
                write_id,
                memory_id,
                writer,
                principal,
                tenant,
                session,
                delegation,
                memory.source_context_sha256,
                memory.classification,
                memory.trust_label,
                NOW - 130 + index,
                "security-platform" if tenant == "system" else "agent-platform",
                f"Write event for {memory_id}.",
            )
        )
    return tuple(result)


def _retrievals(memories: Mapping[str, MemoryRecord]) -> tuple[MemoryRetrieval, ...]:
    specs = (
        (RETRIEVE_SESSION, AGENT_ORCH, "user-a", "tenant-a", "session-a-1", "answer-current-request", (MEM_SESSION_QUERY,)),
        (RETRIEVE_SUMMARY, AGENT_RETRIEVAL, "user-a", "tenant-a", None, "retrieve-durable-summary", (MEM_RETRIEVAL_SUMMARY, MEM_TOOL_NOTE)),
        (RETRIEVE_PROFILE, AGENT_RETRIEVAL, "user-a", "tenant-a", None, "retrieve-current-profile", (MEM_CURRENT_PROFILE,)),
        (RETRIEVE_SECURITY, AGENT_SECURITY, "security-admin", "system", None, "security-analysis", (MEM_SECURITY_BASELINE,)),
    )
    result: list[MemoryRetrieval] = []
    for index, (retrieval_id, reader, principal, tenant, session, purpose, memory_ids) in enumerate(specs):
        result.append(
            MemoryRetrieval(
                retrieval_id,
                reader,
                principal,
                tenant,
                session,
                purpose,
                memory_ids,
                {memory_id: memories[memory_id].trust_label for memory_id in memory_ids},
                {memory_id: memories[memory_id].classification for memory_id in memory_ids},
                NOW - 50 + index,
                "security-platform" if tenant == "system" else "agent-platform",
                f"Retrieval event {retrieval_id}.",
            )
        )
    return tuple(result)


def make_upstreams(
    *,
    denied_delegations: frozenset[str] = frozenset(),
    exposed_p7c_paths: frozenset[str] = frozenset(),
    unsafe_p7i_invariants: frozenset[str] = frozenset(),
) -> dict[str, object]:
    p8a = SimpleNamespace(
        assessment_evidence_sha256=P8A_SHA,
        exact_delegation_graph_binding_verified=True,
        agent_identity_continuity_verified=True,
        tenant_continuity_verified=True,
        authority_non_amplification_verified=True,
        delegations=(
            SimpleNamespace(
                delegation_id=DELEGATION_RETRIEVAL,
                decision="deny" if DELEGATION_RETRIEVAL in denied_delegations else "allow",
                delegatee_agent_id=AGENT_RETRIEVAL,
                original_principal_id="user-a",
                tenant_id="tenant-a",
            ),
            SimpleNamespace(
                delegation_id=DELEGATION_TOOL,
                decision="deny" if DELEGATION_TOOL in denied_delegations else "allow",
                delegatee_agent_id=AGENT_TOOL_BROKER,
                original_principal_id="user-a",
                tenant_id="tenant-a",
            ),
        ),
    )
    p7c = SimpleNamespace(
        assessment_evidence_sha256=P7C_SHA,
        exact_data_graph_binding_verified=True,
        exfiltration_derived_from_evidence=True,
        paths=tuple(
            SimpleNamespace(path_id=path_id, exposed=path_id in exposed_p7c_paths)
            for path_id in (P7C_PATH_TENANT, P7C_PATH_TOOL, P7C_PATH_SECURITY)
        ),
    )
    p7i = SimpleNamespace(
        assessment_evidence_sha256=P7I_SHA,
        exact_catalog_binding_verified=True,
        blast_radius_derived_from_evidence=True,
        counterevidence_preserved=True,
        invariants=tuple(
            SimpleNamespace(invariant_id=invariant_id, state="violated" if invariant_id in unsafe_p7i_invariants else "holds")
            for invariant_id in (INV_TENANT, INV_TOOL, INV_TELEMETRY, INV_ADMIN)
        ),
    )
    return {"p8a": p8a, "p7c": p7c, "p7i": p7i}


def build_fixture() -> dict[str, object]:
    stores = _stores()
    memory_tuple = _memories()
    memories = {item.memory_id: item for item in memory_tuple}
    writes = _writes(memories)
    retrievals = _retrievals(memories)
    manifest = AgentMemoryManifest(
        GRAPH_ID,
        GRAPH_VERSION,
        P8A_SHA,
        P7C_SHA,
        P7I_SHA,
        NOW - 300,
        stores,
        memory_tuple,
        writes,
        retrievals,
    )
    graph_sha = agent_memory_manifest_digest(manifest)
    policy = AgentMemoryPolicy(
        expected_graph_id=GRAPH_ID,
        expected_graph_version=GRAPH_VERSION,
        expected_graph_sha256=graph_sha,
        expected_p8a_assessment_evidence_sha256=P8A_SHA,
        expected_p7c_assessment_evidence_sha256=P7C_SHA,
        expected_p7i_assessment_evidence_sha256=P7I_SHA,
        required_store_ids=frozenset(STORE_IDS),
        required_memory_ids=frozenset(MEMORY_IDS),
        required_write_ids=frozenset(WRITE_IDS),
        required_retrieval_ids=frozenset(RETRIEVAL_IDS),
        trusted_owner_ids=frozenset({"agent-platform", "security-platform"}),
        known_agent_ids=frozenset(AGENT_IDS),
        original_principal_tenant={"user-a": "tenant-a", "user-b": "tenant-b", "security-admin": "system"},
        writer_max_trust={
            AGENT_ORCH: MemoryTrust.USER_ASSERTED,
            AGENT_RETRIEVAL: MemoryTrust.DELEGATED,
            AGENT_TOOL_BROKER: MemoryTrust.DELEGATED,
            AGENT_TOOL_EXECUTOR: MemoryTrust.DELEGATED,
            AGENT_SECURITY: MemoryTrust.VERIFIED_SYSTEM,
            AGENT_OBSERVABILITY: MemoryTrust.VERIFIED_SYSTEM,
        },
        expected_store_scope={item.store_id: item.scope for item in stores},
        expected_store_tenant={item.store_id: item.tenant_id for item in stores},
        expected_store_session_binding={item.store_id: item.session_binding_required for item in stores},
        expected_store_writer_ids={item.store_id: frozenset(item.allowed_writer_agent_ids) for item in stores},
        expected_store_reader_ids={item.store_id: frozenset(item.allowed_reader_agent_ids) for item in stores},
        expected_store_max_classification={item.store_id: item.maximum_classification for item in stores},
        expected_store_min_trust={item.store_id: item.minimum_persisted_trust for item in stores},
        expected_store_retention_seconds={item.store_id: item.retention_seconds for item in stores},
        expected_store_invariant_ids={item.store_id: frozenset(item.required_p7i_invariant_ids) for item in stores},
        allowed_sanitization_evidence_sha256=frozenset({SANITIZE_SHA}),
    )
    request = AgentMemoryRequest(
        GRAPH_ID,
        GRAPH_VERSION,
        graph_sha,
        P8A_SHA,
        P7C_SHA,
        P7I_SHA,
        NOW,
        tuple(sorted(WRITE_IDS)),
        tuple(sorted(RETRIEVAL_IDS)),
        (),
        (),
        {write_id: () for write_id in WRITE_IDS},
        {retrieval_id: () for retrieval_id in RETRIEVAL_IDS},
    )
    return {"manifest": manifest, "policy": policy, "request": request, **make_upstreams()}


def replace_manifest_item(manifest: AgentMemoryManifest, collection: str, item_id: str, **changes: object) -> AgentMemoryManifest:
    values = list(getattr(manifest, collection))
    key = {"stores": "store_id", "memories": "memory_id", "writes": "write_id", "retrievals": "retrieval_id"}[collection]
    for index, item in enumerate(values):
        if getattr(item, key) == item_id:
            values[index] = replace(item, **changes)
            return replace(manifest, **{collection: tuple(values)})
    raise KeyError(item_id)


def truthful_request_for_context(
    ctx: Mapping[str, object],
    *,
    write_risks: Mapping[str, tuple[MemoryRisk, ...]] | None = None,
    retrieval_risks: Mapping[str, tuple[MemoryRisk, ...]] | None = None,
) -> AgentMemoryRequest:
    request = ctx["request"]
    write_risks = dict(write_risks or {})
    retrieval_risks = dict(retrieval_risks or {})
    return replace(
        request,
        declared_denied_write_ids=tuple(sorted(key for key, risks in write_risks.items() if risks)),
        declared_denied_retrieval_ids=tuple(sorted(key for key, risks in retrieval_risks.items() if risks)),
        declared_write_risks={write_id: tuple(write_risks.get(write_id, ())) for write_id in request.write_ids},
        declared_retrieval_risks={retrieval_id: tuple(retrieval_risks.get(retrieval_id, ())) for retrieval_id in request.retrieval_ids},
    )
