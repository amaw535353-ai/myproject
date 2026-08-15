from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping

P8B_MEMORY_POLICY_VERSION = "agent-memory-context-boundary-security-v1"
P8B_MEMORY_SCHEMA_VERSION = "aegis-agent-memory-context-manifest-v1"
P8B_ASSESSMENT_SCHEMA_VERSION = "aegis-agent-memory-security-assessment-v1"
P8B_ASSESSMENT_MODE = "deterministic-evidence-bound-agent-memory-v1"


class MemoryScope(StrEnum):
    SESSION = "session"
    TENANT = "tenant"
    SYSTEM = "system"


class MemoryClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class MemoryTrust(StrEnum):
    UNTRUSTED = "untrusted"
    USER_ASSERTED = "user_asserted"
    DELEGATED = "delegated"
    VERIFIED_SYSTEM = "verified_system"


class MemoryDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class MemoryRisk(StrEnum):
    CROSS_TENANT = "cross_tenant"
    CROSS_SESSION = "cross_session"
    WRITER_UNAUTHORIZED = "writer_unauthorized"
    READER_UNAUTHORIZED = "reader_unauthorized"
    DELEGATION_MISMATCH = "delegation_mismatch"
    TRUST_UPGRADE = "trust_upgrade"
    CLASSIFICATION_DOWNGRADE = "classification_downgrade"
    UNTRUSTED_PERSISTENCE = "untrusted_persistence"
    PROVENANCE_BROKEN = "provenance_broken"
    MEMORY_LAUNDERING = "memory_laundering"
    POISON_PERSISTENCE = "poison_persistence"
    REVOKED_MEMORY = "revoked_memory"
    SUPERSEDED_MEMORY = "superseded_memory"
    EXPIRED_MEMORY = "expired_memory"
    UPSTREAM_DATA_EXPOSURE = "upstream_data_exposure"
    ARCHITECTURE_INVARIANT_UNSAFE = "architecture_invariant_unsafe"
    RETRIEVAL_TRUST_MISMATCH = "retrieval_trust_mismatch"
    RETRIEVAL_CLASSIFICATION_MISMATCH = "retrieval_classification_mismatch"


class MemoryRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    P8A_UNVERIFIED = "p8a_unverified"
    P8A_DIGEST_MISMATCH = "p8a_digest_mismatch"
    P7C_UNVERIFIED = "p7c_unverified"
    P7C_DIGEST_MISMATCH = "p7c_digest_mismatch"
    P7I_UNVERIFIED = "p7i_unverified"
    P7I_DIGEST_MISMATCH = "p7i_digest_mismatch"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_DIGEST_MISMATCH = "manifest_digest_mismatch"
    MANIFEST_STALE = "manifest_stale"
    MANIFEST_FUTURE = "manifest_future"
    STORE_DUPLICATE = "store_duplicate"
    STORE_COVERAGE_MISMATCH = "store_coverage_mismatch"
    STORE_OWNER_UNTRUSTED = "store_owner_untrusted"
    STORE_SCOPE_DRIFT = "store_scope_drift"
    STORE_TENANT_DRIFT = "store_tenant_drift"
    STORE_SESSION_POLICY_DRIFT = "store_session_policy_drift"
    STORE_WRITER_DRIFT = "store_writer_drift"
    STORE_READER_DRIFT = "store_reader_drift"
    STORE_CLASSIFICATION_DRIFT = "store_classification_drift"
    STORE_TRUST_DRIFT = "store_trust_drift"
    STORE_RETENTION_DRIFT = "store_retention_drift"
    STORE_INVARIANT_DRIFT = "store_invariant_drift"
    STORE_INVARIANT_UNKNOWN = "store_invariant_unknown"
    MEMORY_DUPLICATE = "memory_duplicate"
    MEMORY_COVERAGE_MISMATCH = "memory_coverage_mismatch"
    MEMORY_OWNER_UNTRUSTED = "memory_owner_untrusted"
    MEMORY_STORE_UNKNOWN = "memory_store_unknown"
    MEMORY_DIGEST_INVALID = "memory_digest_invalid"
    MEMORY_REFERENCE_UNKNOWN = "memory_reference_unknown"
    MEMORY_PROVENANCE_CYCLE = "memory_provenance_cycle"
    MEMORY_SANITIZATION_INVALID = "memory_sanitization_invalid"
    WRITE_DUPLICATE = "write_duplicate"
    WRITE_COVERAGE_MISMATCH = "write_coverage_mismatch"
    WRITE_OWNER_UNTRUSTED = "write_owner_untrusted"
    WRITE_MEMORY_UNKNOWN = "write_memory_unknown"
    WRITE_REFERENCE_INVALID = "write_reference_invalid"
    RETRIEVAL_DUPLICATE = "retrieval_duplicate"
    RETRIEVAL_COVERAGE_MISMATCH = "retrieval_coverage_mismatch"
    RETRIEVAL_OWNER_UNTRUSTED = "retrieval_owner_untrusted"
    RETRIEVAL_REFERENCE_INVALID = "retrieval_reference_invalid"
    DECLARED_DECISION_MISMATCH = "declared_decision_mismatch"
    DECLARED_RISK_MISMATCH = "declared_risk_mismatch"


class MemorySecurityRejected(ValueError):
    def __init__(
        self,
        reason: MemoryRejectReason,
        message: str,
        *,
        store_id: str | None = None,
        memory_id: str | None = None,
        write_id: str | None = None,
        retrieval_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.store_id = store_id
        self.memory_id = memory_id
        self.write_id = write_id
        self.retrieval_id = retrieval_id


@dataclass(frozen=True)
class MemoryStore:
    store_id: str
    scope: MemoryScope
    tenant_id: str
    owner_id: str
    allowed_writer_agent_ids: tuple[str, ...]
    allowed_reader_agent_ids: tuple[str, ...]
    maximum_classification: MemoryClassification
    minimum_persisted_trust: MemoryTrust
    session_binding_required: bool
    retention_seconds: int
    required_p7i_invariant_ids: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class MemoryRecord:
    memory_id: str
    store_id: str
    tenant_id: str
    session_id: str | None
    classification: MemoryClassification
    trust_label: MemoryTrust
    content_sha256: str
    source_context_sha256: str
    source_kind: str
    created_by_agent_id: str
    original_principal_id: str
    delegation_id: str | None
    parent_memory_ids: tuple[str, ...]
    p7c_path_ids: tuple[str, ...]
    sanitized: bool
    sanitization_evidence_sha256: str | None
    created_at_epoch: int
    expires_at_epoch: int
    revoked_at_epoch: int | None
    supersedes_memory_id: str | None
    owner_id: str
    description: str


@dataclass(frozen=True)
class MemoryWrite:
    write_id: str
    memory_id: str
    writer_agent_id: str
    original_principal_id: str
    tenant_id: str
    session_id: str | None
    delegation_id: str | None
    source_context_sha256: str
    requested_classification: MemoryClassification
    requested_trust_label: MemoryTrust
    issued_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class MemoryRetrieval:
    retrieval_id: str
    reader_agent_id: str
    original_principal_id: str
    tenant_id: str
    session_id: str | None
    purpose: str
    memory_ids: tuple[str, ...]
    declared_trust_by_memory: Mapping[str, MemoryTrust]
    declared_classification_by_memory: Mapping[str, MemoryClassification]
    issued_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class AgentMemoryManifest:
    graph_id: str
    version: str
    p8a_assessment_evidence_sha256: str
    p7c_assessment_evidence_sha256: str
    p7i_assessment_evidence_sha256: str
    created_at_epoch: int
    stores: tuple[MemoryStore, ...]
    memories: tuple[MemoryRecord, ...]
    writes: tuple[MemoryWrite, ...]
    retrievals: tuple[MemoryRetrieval, ...]
    schema_version: str = P8B_MEMORY_SCHEMA_VERSION


@dataclass(frozen=True)
class AgentMemoryRequest:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8a_assessment_evidence_sha256: str
    p7c_assessment_evidence_sha256: str
    p7i_assessment_evidence_sha256: str
    evaluated_at_epoch: int
    write_ids: tuple[str, ...]
    retrieval_ids: tuple[str, ...]
    declared_denied_write_ids: tuple[str, ...]
    declared_denied_retrieval_ids: tuple[str, ...]
    declared_write_risks: Mapping[str, tuple[MemoryRisk, ...]]
    declared_retrieval_risks: Mapping[str, tuple[MemoryRisk, ...]]


@dataclass(frozen=True)
class AgentMemoryPolicy:
    expected_graph_id: str
    expected_graph_version: str
    expected_graph_sha256: str
    expected_p8a_assessment_evidence_sha256: str
    expected_p7c_assessment_evidence_sha256: str
    expected_p7i_assessment_evidence_sha256: str
    required_store_ids: frozenset[str]
    required_memory_ids: frozenset[str]
    required_write_ids: frozenset[str]
    required_retrieval_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    known_agent_ids: frozenset[str]
    original_principal_tenant: Mapping[str, str]
    writer_max_trust: Mapping[str, MemoryTrust]
    expected_store_scope: Mapping[str, MemoryScope]
    expected_store_tenant: Mapping[str, str]
    expected_store_session_binding: Mapping[str, bool]
    expected_store_writer_ids: Mapping[str, frozenset[str]]
    expected_store_reader_ids: Mapping[str, frozenset[str]]
    expected_store_max_classification: Mapping[str, MemoryClassification]
    expected_store_min_trust: Mapping[str, MemoryTrust]
    expected_store_retention_seconds: Mapping[str, int]
    expected_store_invariant_ids: Mapping[str, frozenset[str]]
    allowed_sanitization_evidence_sha256: frozenset[str]
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class MemoryWriteFact:
    write_id: str
    memory_id: str
    writer_agent_id: str
    decision: MemoryDecision
    risks: tuple[MemoryRisk, ...]
    tenant_id: str
    session_id: str | None
    trust_label: MemoryTrust
    classification: MemoryClassification
    delegation_id: str | None
    parent_memory_ids: tuple[str, ...]
    p7c_path_ids: tuple[str, ...]
    p7i_invariant_ids: tuple[str, ...]


@dataclass(frozen=True)
class MemoryRetrievalFact:
    retrieval_id: str
    reader_agent_id: str
    decision: MemoryDecision
    risks: tuple[MemoryRisk, ...]
    tenant_id: str
    session_id: str | None
    memory_ids: tuple[str, ...]
    trust_by_memory: Mapping[str, MemoryTrust]
    classification_by_memory: Mapping[str, MemoryClassification]
    p7c_path_ids: tuple[str, ...]
    p7i_invariant_ids: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedAgentMemoryAssessment:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8a_assessment_evidence_sha256: str
    p7c_assessment_evidence_sha256: str
    p7i_assessment_evidence_sha256: str
    write_count: int
    allowed_write_count: int
    denied_write_count: int
    retrieval_count: int
    allowed_retrieval_count: int
    denied_retrieval_count: int
    cross_tenant_denial_count: int
    cross_session_denial_count: int
    memory_laundering_denial_count: int
    poison_persistence_denial_count: int
    revoked_or_superseded_denial_count: int
    writes: tuple[MemoryWriteFact, ...]
    retrievals: tuple[MemoryRetrievalFact, ...]
    assessment_evidence_sha256: str
    exact_memory_graph_binding_verified: bool = True
    exact_p8a_delegation_binding_verified: bool = True
    exact_p7c_data_binding_verified: bool = True
    exact_p7i_invariant_binding_verified: bool = True
    tenant_context_isolation_verified: bool = True
    session_context_isolation_verified: bool = True
    memory_write_authorization_verified: bool = True
    memory_provenance_verified: bool = True
    retrieval_trust_labels_derived_from_evidence: bool = True
    revocation_and_supersession_enforced: bool = True
    caller_declared_memory_safety_trusted: bool = False
    production_vector_database_enforcement: bool = False
    production_memory_provider_integration: bool = False
    cryptographic_memory_attestation: bool = False
    formal_noninterference_proof: bool = False
    exhaustive_poisoning_coverage: bool = False
    network_operations: int = 0
    schema_version: str = P8B_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P8B_MEMORY_POLICY_VERSION
    assessment_mode: str = P8B_ASSESSMENT_MODE


def _reject(reason: MemoryRejectReason, message: str, **context: str | None) -> None:
    raise MemorySecurityRejected(reason, message, **context)


def _is_sha256(value: str | None) -> bool:
    if value is None:
        return False
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def _digest(value: object) -> str:
    return str(getattr(value, "assessment_evidence_sha256", "")).casefold()


def _verified(value: object, *flags: str) -> bool:
    return all(bool(getattr(value, flag, False)) for flag in flags)


def _class_rank(value: MemoryClassification) -> int:
    return {
        MemoryClassification.PUBLIC: 1,
        MemoryClassification.INTERNAL: 2,
        MemoryClassification.CONFIDENTIAL: 3,
        MemoryClassification.RESTRICTED: 4,
    }[value]


def _trust_rank(value: MemoryTrust) -> int:
    return {
        MemoryTrust.UNTRUSTED: 1,
        MemoryTrust.USER_ASSERTED: 2,
        MemoryTrust.DELEGATED: 3,
        MemoryTrust.VERIFIED_SYSTEM: 4,
    }[value]


def _state_value(value: object) -> str:
    raw = getattr(value, "value", value)
    return str(raw).casefold()


def canonical_agent_memory_manifest_bytes(manifest: AgentMemoryManifest) -> bytes:
    document = {
        "created_at_epoch": manifest.created_at_epoch,
        "graph_id": manifest.graph_id,
        "memories": [
            {
                "classification": item.classification.value,
                "content_sha256": item.content_sha256.casefold(),
                "created_at_epoch": item.created_at_epoch,
                "created_by_agent_id": item.created_by_agent_id,
                "delegation_id": item.delegation_id,
                "description": item.description,
                "expires_at_epoch": item.expires_at_epoch,
                "memory_id": item.memory_id,
                "original_principal_id": item.original_principal_id,
                "owner_id": item.owner_id,
                "parent_memory_ids": sorted(item.parent_memory_ids),
                "p7c_path_ids": sorted(item.p7c_path_ids),
                "revoked_at_epoch": item.revoked_at_epoch,
                "sanitization_evidence_sha256": item.sanitization_evidence_sha256.casefold() if item.sanitization_evidence_sha256 else None,
                "sanitized": item.sanitized,
                "session_id": item.session_id,
                "source_context_sha256": item.source_context_sha256.casefold(),
                "source_kind": item.source_kind,
                "store_id": item.store_id,
                "supersedes_memory_id": item.supersedes_memory_id,
                "tenant_id": item.tenant_id,
                "trust_label": item.trust_label.value,
            }
            for item in sorted(manifest.memories, key=lambda value: value.memory_id)
        ],
        "p7c_assessment_evidence_sha256": manifest.p7c_assessment_evidence_sha256.casefold(),
        "p7i_assessment_evidence_sha256": manifest.p7i_assessment_evidence_sha256.casefold(),
        "p8a_assessment_evidence_sha256": manifest.p8a_assessment_evidence_sha256.casefold(),
        "retrievals": [
            {
                "declared_classification_by_memory": {key: value.value for key, value in sorted(item.declared_classification_by_memory.items())},
                "declared_trust_by_memory": {key: value.value for key, value in sorted(item.declared_trust_by_memory.items())},
                "description": item.description,
                "issued_at_epoch": item.issued_at_epoch,
                "memory_ids": sorted(item.memory_ids),
                "original_principal_id": item.original_principal_id,
                "owner_id": item.owner_id,
                "purpose": item.purpose,
                "reader_agent_id": item.reader_agent_id,
                "retrieval_id": item.retrieval_id,
                "session_id": item.session_id,
                "tenant_id": item.tenant_id,
            }
            for item in sorted(manifest.retrievals, key=lambda value: value.retrieval_id)
        ],
        "schema_version": manifest.schema_version,
        "stores": [
            {
                "allowed_reader_agent_ids": sorted(item.allowed_reader_agent_ids),
                "allowed_writer_agent_ids": sorted(item.allowed_writer_agent_ids),
                "description": item.description,
                "maximum_classification": item.maximum_classification.value,
                "minimum_persisted_trust": item.minimum_persisted_trust.value,
                "owner_id": item.owner_id,
                "required_p7i_invariant_ids": sorted(item.required_p7i_invariant_ids),
                "retention_seconds": item.retention_seconds,
                "scope": item.scope.value,
                "session_binding_required": item.session_binding_required,
                "store_id": item.store_id,
                "tenant_id": item.tenant_id,
            }
            for item in sorted(manifest.stores, key=lambda value: value.store_id)
        ],
        "version": manifest.version,
        "writes": [
            {
                "delegation_id": item.delegation_id,
                "description": item.description,
                "issued_at_epoch": item.issued_at_epoch,
                "memory_id": item.memory_id,
                "original_principal_id": item.original_principal_id,
                "owner_id": item.owner_id,
                "requested_classification": item.requested_classification.value,
                "requested_trust_label": item.requested_trust_label.value,
                "session_id": item.session_id,
                "source_context_sha256": item.source_context_sha256.casefold(),
                "tenant_id": item.tenant_id,
                "write_id": item.write_id,
                "writer_agent_id": item.writer_agent_id,
            }
            for item in sorted(manifest.writes, key=lambda value: value.write_id)
        ],
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def agent_memory_manifest_digest(manifest: AgentMemoryManifest) -> str:
    return hashlib.sha256(canonical_agent_memory_manifest_bytes(manifest)).hexdigest()


def _validate_policy(policy: AgentMemoryPolicy) -> None:
    hashes = (
        policy.expected_graph_sha256,
        policy.expected_p8a_assessment_evidence_sha256,
        policy.expected_p7c_assessment_evidence_sha256,
        policy.expected_p7i_assessment_evidence_sha256,
    )
    if (
        not policy.expected_graph_id
        or not policy.expected_graph_version
        or not all(_is_sha256(value) for value in hashes)
        or not policy.required_store_ids
        or not policy.required_memory_ids
        or not policy.required_write_ids
        or not policy.required_retrieval_ids
        or not policy.trusted_owner_ids
        or not policy.known_agent_ids
        or not policy.original_principal_tenant
        or policy.max_manifest_age_seconds <= 0
        or policy.max_future_skew_seconds < 0
    ):
        _reject(MemoryRejectReason.POLICY_INVALID, "memory policy metadata is invalid")
    store_maps = (
        policy.expected_store_scope,
        policy.expected_store_tenant,
        policy.expected_store_session_binding,
        policy.expected_store_writer_ids,
        policy.expected_store_reader_ids,
        policy.expected_store_max_classification,
        policy.expected_store_min_trust,
        policy.expected_store_retention_seconds,
        policy.expected_store_invariant_ids,
    )
    if any(set(mapping) != set(policy.required_store_ids) for mapping in store_maps):
        _reject(MemoryRejectReason.POLICY_INVALID, "store policy maps must exactly cover required stores")
    if set(policy.writer_max_trust) != set(policy.known_agent_ids):
        _reject(MemoryRejectReason.POLICY_INVALID, "writer trust policy must exactly cover known agents")
    if any(value <= 0 for value in policy.expected_store_retention_seconds.values()):
        _reject(MemoryRejectReason.POLICY_INVALID, "store retention must be positive")
    if not all(_is_sha256(value) for value in policy.allowed_sanitization_evidence_sha256):
        _reject(MemoryRejectReason.POLICY_INVALID, "sanitization evidence allowlist contains invalid digest")


def _unique(items: tuple[object, ...], attribute: str, reason: MemoryRejectReason) -> dict[str, object]:
    result: dict[str, object] = {}
    for item in items:
        object_id = str(getattr(item, attribute, ""))
        if not object_id or object_id in result:
            _reject(reason, "upstream evidence contains duplicate or empty identifiers")
        result[object_id] = item
    if not result:
        _reject(reason, "upstream evidence inventory is empty")
    return result


def _validate_upstreams(
    policy: AgentMemoryPolicy,
    p8a: object,
    p7c: object,
    p7i: object,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    if not _verified(
        p8a,
        "exact_delegation_graph_binding_verified",
        "agent_identity_continuity_verified",
        "tenant_continuity_verified",
        "authority_non_amplification_verified",
    ):
        _reject(MemoryRejectReason.P8A_UNVERIFIED, "P8-A delegation evidence is not fully verified")
    if _digest(p8a) != policy.expected_p8a_assessment_evidence_sha256.casefold():
        _reject(MemoryRejectReason.P8A_DIGEST_MISMATCH, "P8-A evidence digest does not match memory policy")

    if not _verified(p7c, "exact_data_graph_binding_verified", "exfiltration_derived_from_evidence"):
        _reject(MemoryRejectReason.P7C_UNVERIFIED, "P7-C data evidence is not fully verified")
    if _digest(p7c) != policy.expected_p7c_assessment_evidence_sha256.casefold():
        _reject(MemoryRejectReason.P7C_DIGEST_MISMATCH, "P7-C evidence digest does not match memory policy")

    if not _verified(p7i, "exact_catalog_binding_verified", "blast_radius_derived_from_evidence", "counterevidence_preserved"):
        _reject(MemoryRejectReason.P7I_UNVERIFIED, "P7-I invariant evidence is not fully verified")
    if _digest(p7i) != policy.expected_p7i_assessment_evidence_sha256.casefold():
        _reject(MemoryRejectReason.P7I_DIGEST_MISMATCH, "P7-I evidence digest does not match memory policy")

    delegations = _unique(tuple(getattr(p8a, "delegations", ())), "delegation_id", MemoryRejectReason.P8A_UNVERIFIED)
    data_paths = _unique(tuple(getattr(p7c, "paths", ())), "path_id", MemoryRejectReason.P7C_UNVERIFIED)
    invariants = _unique(tuple(getattr(p7i, "invariants", ())), "invariant_id", MemoryRejectReason.P7I_UNVERIFIED)
    return delegations, data_paths, invariants


def _validate_manifest(
    policy: AgentMemoryPolicy,
    request: AgentMemoryRequest,
    manifest: AgentMemoryManifest,
    delegations: Mapping[str, object],
    data_paths: Mapping[str, object],
    invariants: Mapping[str, object],
) -> tuple[dict[str, MemoryStore], dict[str, MemoryRecord], dict[str, MemoryWrite], dict[str, MemoryRetrieval], str]:
    if (
        manifest.schema_version != P8B_MEMORY_SCHEMA_VERSION
        or manifest.graph_id != policy.expected_graph_id
        or manifest.version != policy.expected_graph_version
        or not manifest.stores
        or not manifest.memories
        or not manifest.writes
        or not manifest.retrievals
    ):
        _reject(MemoryRejectReason.MANIFEST_INVALID, "memory manifest metadata is invalid")
    pins = (
        (manifest.p8a_assessment_evidence_sha256, policy.expected_p8a_assessment_evidence_sha256),
        (manifest.p7c_assessment_evidence_sha256, policy.expected_p7c_assessment_evidence_sha256),
        (manifest.p7i_assessment_evidence_sha256, policy.expected_p7i_assessment_evidence_sha256),
    )
    if any(left.casefold() != right.casefold() for left, right in pins):
        _reject(MemoryRejectReason.MANIFEST_INVALID, "memory manifest upstream evidence pins are invalid")
    if manifest.created_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
        _reject(MemoryRejectReason.MANIFEST_FUTURE, "memory manifest is future-dated")
    if request.evaluated_at_epoch - manifest.created_at_epoch > policy.max_manifest_age_seconds:
        _reject(MemoryRejectReason.MANIFEST_STALE, "memory manifest is stale")
    actual_sha = agent_memory_manifest_digest(manifest)
    if not hmac.compare_digest(actual_sha, policy.expected_graph_sha256.casefold()) or not hmac.compare_digest(actual_sha, request.graph_sha256.casefold()):
        _reject(MemoryRejectReason.MANIFEST_DIGEST_MISMATCH, "memory manifest digest does not match request/policy")

    stores: dict[str, MemoryStore] = {}
    for store in manifest.stores:
        if not store.store_id or store.store_id in stores:
            _reject(MemoryRejectReason.STORE_DUPLICATE, "memory store is duplicate or empty", store_id=store.store_id or None)
        stores[store.store_id] = store
    if set(stores) != set(policy.required_store_ids):
        _reject(MemoryRejectReason.STORE_COVERAGE_MISMATCH, "memory store coverage differs from policy")
    for store_id, store in stores.items():
        if store.owner_id not in policy.trusted_owner_ids:
            _reject(MemoryRejectReason.STORE_OWNER_UNTRUSTED, "memory store owner is untrusted", store_id=store_id)
        if store.scope != policy.expected_store_scope[store_id]:
            _reject(MemoryRejectReason.STORE_SCOPE_DRIFT, "memory store scope differs from policy", store_id=store_id)
        if store.tenant_id != policy.expected_store_tenant[store_id]:
            _reject(MemoryRejectReason.STORE_TENANT_DRIFT, "memory store tenant differs from policy", store_id=store_id)
        if store.session_binding_required != policy.expected_store_session_binding[store_id]:
            _reject(MemoryRejectReason.STORE_SESSION_POLICY_DRIFT, "memory store session policy differs from policy", store_id=store_id)
        if set(store.allowed_writer_agent_ids) != set(policy.expected_store_writer_ids[store_id]) or len(set(store.allowed_writer_agent_ids)) != len(store.allowed_writer_agent_ids):
            _reject(MemoryRejectReason.STORE_WRITER_DRIFT, "memory store writers differ from policy", store_id=store_id)
        if set(store.allowed_reader_agent_ids) != set(policy.expected_store_reader_ids[store_id]) or len(set(store.allowed_reader_agent_ids)) != len(store.allowed_reader_agent_ids):
            _reject(MemoryRejectReason.STORE_READER_DRIFT, "memory store readers differ from policy", store_id=store_id)
        if any(agent_id not in policy.known_agent_ids for agent_id in (*store.allowed_writer_agent_ids, *store.allowed_reader_agent_ids)):
            _reject(MemoryRejectReason.STORE_WRITER_DRIFT, "memory store references unknown agent", store_id=store_id)
        if store.maximum_classification != policy.expected_store_max_classification[store_id]:
            _reject(MemoryRejectReason.STORE_CLASSIFICATION_DRIFT, "memory store classification ceiling differs from policy", store_id=store_id)
        if store.minimum_persisted_trust != policy.expected_store_min_trust[store_id]:
            _reject(MemoryRejectReason.STORE_TRUST_DRIFT, "memory store trust floor differs from policy", store_id=store_id)
        if store.retention_seconds != policy.expected_store_retention_seconds[store_id] or store.retention_seconds <= 0:
            _reject(MemoryRejectReason.STORE_RETENTION_DRIFT, "memory store retention differs from policy", store_id=store_id)
        if set(store.required_p7i_invariant_ids) != set(policy.expected_store_invariant_ids[store_id]) or len(set(store.required_p7i_invariant_ids)) != len(store.required_p7i_invariant_ids):
            _reject(MemoryRejectReason.STORE_INVARIANT_DRIFT, "memory store invariants differ from policy", store_id=store_id)
        if any(invariant_id not in invariants for invariant_id in store.required_p7i_invariant_ids):
            _reject(MemoryRejectReason.STORE_INVARIANT_UNKNOWN, "memory store references unknown P7-I invariant", store_id=store_id)

    memories: dict[str, MemoryRecord] = {}
    for memory in manifest.memories:
        if not memory.memory_id or memory.memory_id in memories:
            _reject(MemoryRejectReason.MEMORY_DUPLICATE, "memory record is duplicate or empty", memory_id=memory.memory_id or None)
        memories[memory.memory_id] = memory
    if set(memories) != set(policy.required_memory_ids):
        _reject(MemoryRejectReason.MEMORY_COVERAGE_MISMATCH, "memory record coverage differs from policy")
    for memory_id, memory in memories.items():
        if memory.owner_id not in policy.trusted_owner_ids:
            _reject(MemoryRejectReason.MEMORY_OWNER_UNTRUSTED, "memory record owner is untrusted", memory_id=memory_id)
        if memory.store_id not in stores:
            _reject(MemoryRejectReason.MEMORY_STORE_UNKNOWN, "memory references unknown store", memory_id=memory_id)
        if not _is_sha256(memory.content_sha256) or not _is_sha256(memory.source_context_sha256):
            _reject(MemoryRejectReason.MEMORY_DIGEST_INVALID, "memory content/source digest is invalid", memory_id=memory_id)
        if memory.created_by_agent_id not in policy.known_agent_ids or memory.original_principal_id not in policy.original_principal_tenant:
            _reject(MemoryRejectReason.MEMORY_REFERENCE_UNKNOWN, "memory references unknown agent/principal", memory_id=memory_id)
        if memory.delegation_id is not None and memory.delegation_id not in delegations:
            _reject(MemoryRejectReason.MEMORY_REFERENCE_UNKNOWN, "memory references unknown P8-A delegation", memory_id=memory_id)
        if len(set(memory.parent_memory_ids)) != len(memory.parent_memory_ids) or any(parent_id not in memories for parent_id in memory.parent_memory_ids):
            _reject(MemoryRejectReason.MEMORY_REFERENCE_UNKNOWN, "memory parent references are duplicate or unknown", memory_id=memory_id)
        if len(set(memory.p7c_path_ids)) != len(memory.p7c_path_ids) or any(path_id not in data_paths for path_id in memory.p7c_path_ids):
            _reject(MemoryRejectReason.MEMORY_REFERENCE_UNKNOWN, "memory P7-C path references are duplicate or unknown", memory_id=memory_id)
        if memory.supersedes_memory_id is not None and memory.supersedes_memory_id not in memories:
            _reject(MemoryRejectReason.MEMORY_REFERENCE_UNKNOWN, "memory supersedes unknown record", memory_id=memory_id)
        if memory.sanitized:
            if not _is_sha256(memory.sanitization_evidence_sha256) or memory.sanitization_evidence_sha256.casefold() not in policy.allowed_sanitization_evidence_sha256:
                _reject(MemoryRejectReason.MEMORY_SANITIZATION_INVALID, "memory sanitization evidence is invalid", memory_id=memory_id)
        elif memory.sanitization_evidence_sha256 is not None:
            _reject(MemoryRejectReason.MEMORY_SANITIZATION_INVALID, "unsanitized memory cannot carry sanitization evidence", memory_id=memory_id)
        if memory.expires_at_epoch <= memory.created_at_epoch:
            _reject(MemoryRejectReason.MEMORY_REFERENCE_UNKNOWN, "memory expiry is not after creation", memory_id=memory_id)
        if memory.revoked_at_epoch is not None and memory.revoked_at_epoch < memory.created_at_epoch:
            _reject(MemoryRejectReason.MEMORY_REFERENCE_UNKNOWN, "memory revocation predates creation", memory_id=memory_id)

    for memory_id in memories:
        seen: set[str] = set()
        stack = list(memories[memory_id].parent_memory_ids)
        while stack:
            current = stack.pop()
            if current == memory_id or current in seen:
                if current == memory_id:
                    _reject(MemoryRejectReason.MEMORY_PROVENANCE_CYCLE, "memory provenance graph contains a cycle", memory_id=memory_id)
                continue
            seen.add(current)
            stack.extend(memories[current].parent_memory_ids)

    writes: dict[str, MemoryWrite] = {}
    for write in manifest.writes:
        if not write.write_id or write.write_id in writes:
            _reject(MemoryRejectReason.WRITE_DUPLICATE, "memory write is duplicate or empty", write_id=write.write_id or None)
        writes[write.write_id] = write
    if set(writes) != set(policy.required_write_ids):
        _reject(MemoryRejectReason.WRITE_COVERAGE_MISMATCH, "memory write coverage differs from policy")
    for write_id, write in writes.items():
        if write.owner_id not in policy.trusted_owner_ids:
            _reject(MemoryRejectReason.WRITE_OWNER_UNTRUSTED, "memory write owner is untrusted", write_id=write_id)
        if write.memory_id not in memories:
            _reject(MemoryRejectReason.WRITE_MEMORY_UNKNOWN, "memory write references unknown memory", write_id=write_id)
        if write.writer_agent_id not in policy.known_agent_ids or write.original_principal_id not in policy.original_principal_tenant:
            _reject(MemoryRejectReason.WRITE_REFERENCE_INVALID, "memory write references unknown agent/principal", write_id=write_id)
        if write.delegation_id is not None and write.delegation_id not in delegations:
            _reject(MemoryRejectReason.WRITE_REFERENCE_INVALID, "memory write references unknown P8-A delegation", write_id=write_id)
        if not _is_sha256(write.source_context_sha256):
            _reject(MemoryRejectReason.WRITE_REFERENCE_INVALID, "memory write source digest is invalid", write_id=write_id)
        if write.issued_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
            _reject(MemoryRejectReason.WRITE_REFERENCE_INVALID, "memory write is future-dated", write_id=write_id)

    retrievals: dict[str, MemoryRetrieval] = {}
    for retrieval in manifest.retrievals:
        if not retrieval.retrieval_id or retrieval.retrieval_id in retrievals:
            _reject(MemoryRejectReason.RETRIEVAL_DUPLICATE, "memory retrieval is duplicate or empty", retrieval_id=retrieval.retrieval_id or None)
        retrievals[retrieval.retrieval_id] = retrieval
    if set(retrievals) != set(policy.required_retrieval_ids):
        _reject(MemoryRejectReason.RETRIEVAL_COVERAGE_MISMATCH, "memory retrieval coverage differs from policy")
    for retrieval_id, retrieval in retrievals.items():
        if retrieval.owner_id not in policy.trusted_owner_ids:
            _reject(MemoryRejectReason.RETRIEVAL_OWNER_UNTRUSTED, "memory retrieval owner is untrusted", retrieval_id=retrieval_id)
        if retrieval.reader_agent_id not in policy.known_agent_ids or retrieval.original_principal_id not in policy.original_principal_tenant:
            _reject(MemoryRejectReason.RETRIEVAL_REFERENCE_INVALID, "memory retrieval references unknown agent/principal", retrieval_id=retrieval_id)
        if not retrieval.memory_ids or len(set(retrieval.memory_ids)) != len(retrieval.memory_ids) or any(memory_id not in memories for memory_id in retrieval.memory_ids):
            _reject(MemoryRejectReason.RETRIEVAL_REFERENCE_INVALID, "memory retrieval references empty, duplicate, or unknown memory", retrieval_id=retrieval_id)
        if set(retrieval.declared_trust_by_memory) != set(retrieval.memory_ids) or set(retrieval.declared_classification_by_memory) != set(retrieval.memory_ids):
            _reject(MemoryRejectReason.RETRIEVAL_REFERENCE_INVALID, "memory retrieval trust/classification maps must exactly cover memory IDs", retrieval_id=retrieval_id)
        if retrieval.issued_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
            _reject(MemoryRejectReason.RETRIEVAL_REFERENCE_INVALID, "memory retrieval is future-dated", retrieval_id=retrieval_id)

    return stores, memories, writes, retrievals, actual_sha


def _p8a_delegation_allowed(item: object) -> bool:
    return _state_value(getattr(item, "decision", "deny")) == "allow"


def _p7c_exposed(item: object) -> bool:
    return bool(getattr(item, "exposed", getattr(item, "exfiltration_possible", False)))


def _p7i_unsafe(item: object) -> bool:
    return _state_value(getattr(item, "state", "holds")) in {"degraded", "violated"}


def _risk_order(risk: MemoryRisk) -> int:
    return {
        MemoryRisk.CROSS_TENANT: 100,
        MemoryRisk.CROSS_SESSION: 98,
        MemoryRisk.MEMORY_LAUNDERING: 96,
        MemoryRisk.POISON_PERSISTENCE: 94,
        MemoryRisk.DELEGATION_MISMATCH: 92,
        MemoryRisk.WRITER_UNAUTHORIZED: 90,
        MemoryRisk.READER_UNAUTHORIZED: 90,
        MemoryRisk.TRUST_UPGRADE: 88,
        MemoryRisk.CLASSIFICATION_DOWNGRADE: 86,
        MemoryRisk.UNTRUSTED_PERSISTENCE: 84,
        MemoryRisk.PROVENANCE_BROKEN: 82,
        MemoryRisk.UPSTREAM_DATA_EXPOSURE: 80,
        MemoryRisk.ARCHITECTURE_INVARIANT_UNSAFE: 78,
        MemoryRisk.REVOKED_MEMORY: 76,
        MemoryRisk.SUPERSEDED_MEMORY: 74,
        MemoryRisk.EXPIRED_MEMORY: 72,
        MemoryRisk.RETRIEVAL_TRUST_MISMATCH: 70,
        MemoryRisk.RETRIEVAL_CLASSIFICATION_MISMATCH: 68,
    }[risk]


class AgentMemoryContextSecurityAnalyzer:
    def __init__(self, policy: AgentMemoryPolicy) -> None:
        _validate_policy(policy)
        self.policy = policy

    def evaluate(
        self,
        request: AgentMemoryRequest,
        manifest: AgentMemoryManifest,
        p8a_assessment: object,
        p7c_assessment: object,
        p7i_assessment: object,
    ) -> VerifiedAgentMemoryAssessment:
        request_pins = (
            request.graph_sha256,
            request.p8a_assessment_evidence_sha256,
            request.p7c_assessment_evidence_sha256,
            request.p7i_assessment_evidence_sha256,
        )
        expected_pins = (
            self.policy.expected_graph_sha256,
            self.policy.expected_p8a_assessment_evidence_sha256,
            self.policy.expected_p7c_assessment_evidence_sha256,
            self.policy.expected_p7i_assessment_evidence_sha256,
        )
        if (
            request.graph_id != self.policy.expected_graph_id
            or request.graph_version != self.policy.expected_graph_version
            or not all(_is_sha256(value) for value in request_pins)
            or any(left.casefold() != right.casefold() for left, right in zip(request_pins, expected_pins))
            or set(request.write_ids) != set(self.policy.required_write_ids)
            or len(set(request.write_ids)) != len(request.write_ids)
            or set(request.retrieval_ids) != set(self.policy.required_retrieval_ids)
            or len(set(request.retrieval_ids)) != len(request.retrieval_ids)
        ):
            _reject(MemoryRejectReason.REQUEST_INVALID, "memory assessment request identity/evidence/scope is invalid")

        delegations, data_paths, invariants = _validate_upstreams(self.policy, p8a_assessment, p7c_assessment, p7i_assessment)
        stores, memories, writes, retrievals, graph_sha = _validate_manifest(
            self.policy, request, manifest, delegations, data_paths, invariants
        )

        superseded_by: dict[str, str] = {}
        for memory in memories.values():
            if memory.supersedes_memory_id is not None:
                if memory.supersedes_memory_id in superseded_by:
                    superseded_by[memory.supersedes_memory_id] = "__ambiguous__"
                else:
                    superseded_by[memory.supersedes_memory_id] = memory.memory_id

        write_facts: list[MemoryWriteFact] = []
        for write_id in sorted(writes):
            write = writes[write_id]
            memory = memories[write.memory_id]
            store = stores[memory.store_id]
            risks: list[MemoryRisk] = []

            if write.writer_agent_id not in store.allowed_writer_agent_ids:
                risks.append(MemoryRisk.WRITER_UNAUTHORIZED)
            principal_tenant = self.policy.original_principal_tenant[write.original_principal_id]
            if write.tenant_id != principal_tenant or memory.tenant_id != write.tenant_id or store.tenant_id not in {write.tenant_id, "system"}:
                risks.append(MemoryRisk.CROSS_TENANT)
            if store.session_binding_required and (write.session_id is None or memory.session_id != write.session_id):
                risks.append(MemoryRisk.CROSS_SESSION)
            if not store.session_binding_required and store.scope == MemoryScope.SYSTEM and write.session_id is not None:
                risks.append(MemoryRisk.CROSS_SESSION)

            if write.source_context_sha256.casefold() != memory.source_context_sha256.casefold():
                risks.append(MemoryRisk.PROVENANCE_BROKEN)
            if write.requested_classification != memory.classification or write.requested_trust_label != memory.trust_label:
                risks.append(MemoryRisk.PROVENANCE_BROKEN)
            if write.writer_agent_id != memory.created_by_agent_id or write.original_principal_id != memory.original_principal_id or write.delegation_id != memory.delegation_id:
                risks.append(MemoryRisk.PROVENANCE_BROKEN)

            writer_max_trust = self.policy.writer_max_trust[write.writer_agent_id]
            if _trust_rank(memory.trust_label) > _trust_rank(writer_max_trust):
                risks.append(MemoryRisk.TRUST_UPGRADE)
            if _class_rank(memory.classification) > _class_rank(store.maximum_classification):
                risks.append(MemoryRisk.CLASSIFICATION_DOWNGRADE)

            if memory.delegation_id is not None:
                delegation = delegations[memory.delegation_id]
                if (
                    not _p8a_delegation_allowed(delegation)
                    or str(getattr(delegation, "delegatee_agent_id", "")) != write.writer_agent_id
                    or str(getattr(delegation, "original_principal_id", "")) != write.original_principal_id
                    or str(getattr(delegation, "tenant_id", "")) != write.tenant_id
                ):
                    risks.append(MemoryRisk.DELEGATION_MISMATCH)
            elif memory.trust_label == MemoryTrust.DELEGATED:
                risks.append(MemoryRisk.DELEGATION_MISMATCH)

            parent_trusts: list[MemoryTrust] = []
            parent_classes: list[MemoryClassification] = []
            for parent_id in memory.parent_memory_ids:
                parent = memories[parent_id]
                parent_trusts.append(parent.trust_label)
                parent_classes.append(parent.classification)
                if parent.tenant_id != memory.tenant_id:
                    risks.append(MemoryRisk.CROSS_TENANT)
                if store.session_binding_required and parent.session_id != memory.session_id:
                    risks.append(MemoryRisk.CROSS_SESSION)
            if parent_trusts:
                highest_allowed_trust = max(_trust_rank(value) for value in parent_trusts)
                if _trust_rank(memory.trust_label) > highest_allowed_trust and not memory.sanitized:
                    risks.extend((MemoryRisk.TRUST_UPGRADE, MemoryRisk.MEMORY_LAUNDERING))
                highest_parent_class = max(_class_rank(value) for value in parent_classes)
                if _class_rank(memory.classification) < highest_parent_class and not memory.sanitized:
                    risks.extend((MemoryRisk.CLASSIFICATION_DOWNGRADE, MemoryRisk.MEMORY_LAUNDERING))

            if memory.sanitized:
                if memory.sanitization_evidence_sha256 is None or memory.sanitization_evidence_sha256.casefold() not in self.policy.allowed_sanitization_evidence_sha256:
                    risks.append(MemoryRisk.PROVENANCE_BROKEN)
            elif _trust_rank(memory.trust_label) < _trust_rank(store.minimum_persisted_trust):
                risks.append(MemoryRisk.UNTRUSTED_PERSISTENCE)
                if store.scope in {MemoryScope.TENANT, MemoryScope.SYSTEM}:
                    risks.append(MemoryRisk.POISON_PERSISTENCE)

            if memory.source_kind in {"user_message", "tool_result", "external_content"} and _trust_rank(memory.trust_label) < _trust_rank(MemoryTrust.DELEGATED):
                if store.scope in {MemoryScope.TENANT, MemoryScope.SYSTEM} and not memory.sanitized:
                    risks.append(MemoryRisk.POISON_PERSISTENCE)

            if memory.supersedes_memory_id is not None:
                predecessor = memories[memory.supersedes_memory_id]
                if predecessor.tenant_id != memory.tenant_id or predecessor.store_id != memory.store_id:
                    risks.append(MemoryRisk.PROVENANCE_BROKEN)
                if _trust_rank(memory.trust_label) > _trust_rank(predecessor.trust_label) and not memory.sanitized:
                    risks.extend((MemoryRisk.TRUST_UPGRADE, MemoryRisk.MEMORY_LAUNDERING))
                if _class_rank(memory.classification) < _class_rank(predecessor.classification) and not memory.sanitized:
                    risks.extend((MemoryRisk.CLASSIFICATION_DOWNGRADE, MemoryRisk.MEMORY_LAUNDERING))

            if memory.expires_at_epoch > memory.created_at_epoch + store.retention_seconds:
                risks.append(MemoryRisk.PROVENANCE_BROKEN)
            if any(_p7c_exposed(data_paths[path_id]) for path_id in memory.p7c_path_ids):
                risks.append(MemoryRisk.UPSTREAM_DATA_EXPOSURE)
            if any(_p7i_unsafe(invariants[invariant_id]) for invariant_id in store.required_p7i_invariant_ids):
                risks.append(MemoryRisk.ARCHITECTURE_INVARIANT_UNSAFE)

            unique_risks = tuple(sorted(set(risks), key=lambda value: (-_risk_order(value), value.value)))
            decision = MemoryDecision.DENY if unique_risks else MemoryDecision.ALLOW
            write_facts.append(
                MemoryWriteFact(
                    write_id=write_id,
                    memory_id=memory.memory_id,
                    writer_agent_id=write.writer_agent_id,
                    decision=decision,
                    risks=unique_risks,
                    tenant_id=write.tenant_id,
                    session_id=write.session_id,
                    trust_label=memory.trust_label,
                    classification=memory.classification,
                    delegation_id=memory.delegation_id,
                    parent_memory_ids=tuple(sorted(memory.parent_memory_ids)),
                    p7c_path_ids=tuple(sorted(memory.p7c_path_ids)),
                    p7i_invariant_ids=tuple(sorted(store.required_p7i_invariant_ids)),
                )
            )

        retrieval_facts: list[MemoryRetrievalFact] = []
        for retrieval_id in sorted(retrievals):
            retrieval = retrievals[retrieval_id]
            risks: list[MemoryRisk] = []
            p7c_ids: set[str] = set()
            p7i_ids: set[str] = set()
            trust_by_memory: dict[str, MemoryTrust] = {}
            classification_by_memory: dict[str, MemoryClassification] = {}
            principal_tenant = self.policy.original_principal_tenant[retrieval.original_principal_id]
            if retrieval.tenant_id != principal_tenant:
                risks.append(MemoryRisk.CROSS_TENANT)

            for memory_id in retrieval.memory_ids:
                memory = memories[memory_id]
                store = stores[memory.store_id]
                trust_by_memory[memory_id] = memory.trust_label
                classification_by_memory[memory_id] = memory.classification
                p7c_ids.update(memory.p7c_path_ids)
                p7i_ids.update(store.required_p7i_invariant_ids)

                if retrieval.reader_agent_id not in store.allowed_reader_agent_ids:
                    risks.append(MemoryRisk.READER_UNAUTHORIZED)
                if memory.tenant_id != retrieval.tenant_id or store.tenant_id not in {retrieval.tenant_id, "system"}:
                    risks.append(MemoryRisk.CROSS_TENANT)
                if store.session_binding_required and (retrieval.session_id is None or memory.session_id != retrieval.session_id):
                    risks.append(MemoryRisk.CROSS_SESSION)
                if memory.revoked_at_epoch is not None and memory.revoked_at_epoch <= request.evaluated_at_epoch:
                    risks.append(MemoryRisk.REVOKED_MEMORY)
                if memory.expires_at_epoch <= request.evaluated_at_epoch:
                    risks.append(MemoryRisk.EXPIRED_MEMORY)
                if memory_id in superseded_by:
                    risks.append(MemoryRisk.SUPERSEDED_MEMORY)
                if retrieval.declared_trust_by_memory[memory_id] != memory.trust_label:
                    risks.append(MemoryRisk.RETRIEVAL_TRUST_MISMATCH)
                if retrieval.declared_classification_by_memory[memory_id] != memory.classification:
                    risks.append(MemoryRisk.RETRIEVAL_CLASSIFICATION_MISMATCH)
                if any(_p7c_exposed(data_paths[path_id]) for path_id in memory.p7c_path_ids):
                    risks.append(MemoryRisk.UPSTREAM_DATA_EXPOSURE)
                if any(_p7i_unsafe(invariants[invariant_id]) for invariant_id in store.required_p7i_invariant_ids):
                    risks.append(MemoryRisk.ARCHITECTURE_INVARIANT_UNSAFE)

            unique_risks = tuple(sorted(set(risks), key=lambda value: (-_risk_order(value), value.value)))
            decision = MemoryDecision.DENY if unique_risks else MemoryDecision.ALLOW
            retrieval_facts.append(
                MemoryRetrievalFact(
                    retrieval_id=retrieval_id,
                    reader_agent_id=retrieval.reader_agent_id,
                    decision=decision,
                    risks=unique_risks,
                    tenant_id=retrieval.tenant_id,
                    session_id=retrieval.session_id,
                    memory_ids=tuple(sorted(retrieval.memory_ids)),
                    trust_by_memory={key: trust_by_memory[key] for key in sorted(trust_by_memory)},
                    classification_by_memory={key: classification_by_memory[key] for key in sorted(classification_by_memory)},
                    p7c_path_ids=tuple(sorted(p7c_ids)),
                    p7i_invariant_ids=tuple(sorted(p7i_ids)),
                )
            )

        denied_write_ids = tuple(fact.write_id for fact in write_facts if fact.decision == MemoryDecision.DENY)
        denied_retrieval_ids = tuple(fact.retrieval_id for fact in retrieval_facts if fact.decision == MemoryDecision.DENY)
        if set(request.declared_denied_write_ids) != set(denied_write_ids) or set(request.declared_denied_retrieval_ids) != set(denied_retrieval_ids):
            _reject(MemoryRejectReason.DECLARED_DECISION_MISMATCH, "caller-declared memory decisions differ from derived evidence")
        if set(request.declared_write_risks) != set(request.write_ids) or set(request.declared_retrieval_risks) != set(request.retrieval_ids):
            _reject(MemoryRejectReason.DECLARED_RISK_MISMATCH, "caller risk maps must exactly cover write/retrieval IDs")
        for fact in write_facts:
            declared = tuple(request.declared_write_risks[fact.write_id])
            if set(declared) != set(fact.risks) or len(set(declared)) != len(declared):
                _reject(MemoryRejectReason.DECLARED_RISK_MISMATCH, "caller-declared write risks differ from derived evidence", write_id=fact.write_id)
        for fact in retrieval_facts:
            declared = tuple(request.declared_retrieval_risks[fact.retrieval_id])
            if set(declared) != set(fact.risks) or len(set(declared)) != len(declared):
                _reject(MemoryRejectReason.DECLARED_RISK_MISMATCH, "caller-declared retrieval risks differ from derived evidence", retrieval_id=fact.retrieval_id)

        evidence_document = {
            "graph_sha256": graph_sha,
            "p7c_assessment_evidence_sha256": _digest(p7c_assessment),
            "p7i_assessment_evidence_sha256": _digest(p7i_assessment),
            "p8a_assessment_evidence_sha256": _digest(p8a_assessment),
            "retrievals": [asdict(fact) for fact in retrieval_facts],
            "writes": [asdict(fact) for fact in write_facts],
        }
        assessment_sha = hashlib.sha256(
            json.dumps(evidence_document, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()
        all_facts = tuple(write_facts) + tuple(retrieval_facts)
        return VerifiedAgentMemoryAssessment(
            graph_id=manifest.graph_id,
            graph_version=manifest.version,
            graph_sha256=graph_sha,
            p8a_assessment_evidence_sha256=_digest(p8a_assessment),
            p7c_assessment_evidence_sha256=_digest(p7c_assessment),
            p7i_assessment_evidence_sha256=_digest(p7i_assessment),
            write_count=len(write_facts),
            allowed_write_count=len(write_facts) - len(denied_write_ids),
            denied_write_count=len(denied_write_ids),
            retrieval_count=len(retrieval_facts),
            allowed_retrieval_count=len(retrieval_facts) - len(denied_retrieval_ids),
            denied_retrieval_count=len(denied_retrieval_ids),
            cross_tenant_denial_count=sum(MemoryRisk.CROSS_TENANT in fact.risks for fact in all_facts),
            cross_session_denial_count=sum(MemoryRisk.CROSS_SESSION in fact.risks for fact in all_facts),
            memory_laundering_denial_count=sum(MemoryRisk.MEMORY_LAUNDERING in fact.risks for fact in all_facts),
            poison_persistence_denial_count=sum(MemoryRisk.POISON_PERSISTENCE in fact.risks for fact in all_facts),
            revoked_or_superseded_denial_count=sum(
                MemoryRisk.REVOKED_MEMORY in fact.risks or MemoryRisk.SUPERSEDED_MEMORY in fact.risks for fact in retrieval_facts
            ),
            writes=tuple(write_facts),
            retrievals=tuple(retrieval_facts),
            assessment_evidence_sha256=assessment_sha,
        )
