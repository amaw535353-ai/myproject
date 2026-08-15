from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, is_dataclass
from enum import StrEnum
from typing import Mapping

P8K_INCIDENT_POLICY_VERSION = "agent-provenance-incident-containment-forensics-v1"
P8K_INCIDENT_SCHEMA_VERSION = "aegis-agent-incident-forensics-manifest-v1"
P8K_ASSESSMENT_SCHEMA_VERSION = "aegis-agent-incident-forensics-assessment-v1"
P8K_ASSESSMENT_MODE = "deterministic-evidence-bound-agent-incident-forensics-v1"

ZERO_SHA256 = "0" * 64


class IncidentEventKind(StrEnum):
    ALERT = "alert"
    MESSAGE = "message"
    TOOL_INVOCATION = "tool_invocation"
    ARTIFACT_WRITE = "artifact_write"
    CREDENTIAL_USE = "credential_use"
    STATE_TRANSITION = "state_transition"
    RECOVERY = "recovery"
    MEMORY_WRITE = "memory_write"
    OTHER = "other"


class ContainmentKind(StrEnum):
    QUARANTINE_AGENT = "quarantine_agent"
    ISOLATE_CHANNEL = "isolate_channel"
    FREEZE_STATE = "freeze_state"
    REVOKE_CREDENTIAL = "revoke_credential"
    PRESERVE_EVIDENCE = "preserve_evidence"


class IncidentDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class IncidentRisk(StrEnum):
    EVENT_HASH_MISMATCH = "event_hash_mismatch"
    EVENT_CHAIN_BROKEN = "event_chain_broken"
    EVENT_SEQUENCE_INVALID = "event_sequence_invalid"
    CAUSAL_PARENT_MISSING = "causal_parent_missing"
    CAUSAL_ORDER_INVALID = "causal_order_invalid"
    INCIDENT_TRIGGER_INVALID = "incident_trigger_invalid"
    INCIDENT_SCOPE_INCOMPLETE = "incident_scope_incomplete"
    INCIDENT_SCOPE_AGENT_MISMATCH = "incident_scope_agent_mismatch"
    POST_CONTAINMENT_ACTIVITY = "post_containment_activity"
    AGENT_NOT_QUARANTINED = "agent_not_quarantined"
    CHANNEL_NOT_ISOLATED = "channel_not_isolated"
    STATE_NOT_FROZEN = "state_not_frozen"
    CREDENTIAL_NOT_REVOKED = "credential_not_revoked"
    CONTAINMENT_ACTION_INVALID = "containment_action_invalid"
    CONTAINMENT_TIME_INVALID = "containment_time_invalid"
    EVIDENCE_SCOPE_INCOMPLETE = "evidence_scope_incomplete"
    EVIDENCE_DIGEST_MISMATCH = "evidence_digest_mismatch"
    FORENSIC_PACKAGE_MISSING = "forensic_package_missing"
    FORENSIC_PACKAGE_SCOPE_MISMATCH = "forensic_package_scope_mismatch"
    FORENSIC_PACKAGE_HASH_MISMATCH = "forensic_package_hash_mismatch"
    RECONSTRUCTION_ORDER_INVALID = "reconstruction_order_invalid"
    RECONSTRUCTION_ROOT_MISMATCH = "reconstruction_root_mismatch"
    REENTRY_UNAUTHORIZED = "reentry_unauthorized"
    REENTRY_BEFORE_CONTAINMENT = "reentry_before_containment"
    REENTRY_PACKAGE_MISMATCH = "reentry_package_mismatch"
    REENTRY_CHECKPOINT_MISMATCH = "reentry_checkpoint_mismatch"
    REENTRY_CREDENTIAL_NOT_ROTATED = "reentry_credential_not_rotated"
    REENTRY_STATE_VERSION_STALE = "reentry_state_version_stale"
    REENTRY_EXPIRED = "reentry_expired"
    UPSTREAM_MESSAGE_UNSAFE = "upstream_message_unsafe"
    UPSTREAM_STATE_UNSAFE = "upstream_state_unsafe"
    UPSTREAM_ARTIFACT_UNSAFE = "upstream_artifact_unsafe"
    UPSTREAM_RECOVERY_UNSAFE = "upstream_recovery_unsafe"


class IncidentRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    UPSTREAM_INVALID = "upstream_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    COVERAGE_MISMATCH = "coverage_mismatch"
    OWNER_UNTRUSTED = "owner_untrusted"
    POLICY_DRIFT = "policy_drift"
    REFERENCE_INVALID = "reference_invalid"
    DECLARED_DECISION_MISMATCH = "declared_decision_mismatch"
    DECLARED_SCOPE_MISMATCH = "declared_scope_mismatch"
    DECLARED_RECONSTRUCTION_MISMATCH = "declared_reconstruction_mismatch"
    DECLARED_REENTRY_MISMATCH = "declared_reentry_mismatch"


class AgentIncidentForensicsRejected(ValueError):
    def __init__(self, reason: IncidentRejectReason, message: str, *, item_id: str | None = None):
        super().__init__(message)
        self.reason = reason
        self.item_id = item_id


@dataclass(frozen=True)
class IncidentEvent:
    event_id: str
    sequence: int
    agent_id: str
    original_principal_id: str
    tenant_id: str
    session_id: str | None
    kind: IncidentEventKind
    object_id: str
    parent_event_ids: tuple[str, ...]
    previous_event_sha256: str
    payload_sha256: str
    event_sha256: str
    observed_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class ContainmentAction:
    action_id: str
    incident_id: str
    kind: ContainmentKind
    target_id: str
    evidence_event_ids: tuple[str, ...]
    evidence_digest_sha256: str
    issued_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class ForensicPackage:
    package_id: str
    incident_id: str
    scope_event_ids: tuple[str, ...]
    reconstruction_event_ids: tuple[str, ...]
    root_event_ids: tuple[str, ...]
    preserved_event_sha256_by_id: Mapping[str, str]
    generated_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class ReentryAuthorization:
    reentry_id: str
    incident_id: str
    agent_id: str
    safe_checkpoint_id: str
    forensic_package_sha256: str
    replacement_credential_sha256: str
    minimum_state_version: int
    issued_at_epoch: int
    not_before_epoch: int
    expires_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class IncidentCase:
    incident_id: str
    trigger_event_ids: tuple[str, ...]
    containment_action_ids: tuple[str, ...]
    forensic_package_id: str
    reentry_authorization_ids: tuple[str, ...]
    contained_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class AgentIncidentForensicsManifest:
    graph_id: str
    version: str
    p8g_assessment_evidence_sha256: str
    p8h_assessment_evidence_sha256: str
    p8i_assessment_evidence_sha256: str
    p8j_assessment_evidence_sha256: str
    created_at_epoch: int
    events: tuple[IncidentEvent, ...]
    containment_actions: tuple[ContainmentAction, ...]
    forensic_packages: tuple[ForensicPackage, ...]
    reentry_authorizations: tuple[ReentryAuthorization, ...]
    incidents: tuple[IncidentCase, ...]
    schema_version: str = P8K_INCIDENT_SCHEMA_VERSION


@dataclass(frozen=True)
class AgentIncidentForensicsPolicy:
    expected_graph_id: str
    expected_graph_version: str
    expected_graph_sha256: str
    expected_p8g_assessment_evidence_sha256: str
    expected_p8h_assessment_evidence_sha256: str
    expected_p8i_assessment_evidence_sha256: str
    expected_p8j_assessment_evidence_sha256: str
    required_event_ids: frozenset[str]
    required_containment_action_ids: frozenset[str]
    required_forensic_package_ids: frozenset[str]
    required_reentry_authorization_ids: frozenset[str]
    required_incident_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    expected_event_profiles: Mapping[str, tuple[object, ...]]
    expected_incident_profiles: Mapping[str, tuple[object, ...]]
    safe_checkpoint_id_by_agent: Mapping[str, str]
    replacement_credential_sha256_by_agent: Mapping[str, str]
    minimum_reentry_state_version_by_agent: Mapping[str, int]
    max_manifest_age_seconds: int = 86_400
    max_forensic_package_age_seconds: int = 604_800
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class AgentIncidentForensicsRequest:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8g_assessment_evidence_sha256: str
    p8h_assessment_evidence_sha256: str
    p8i_assessment_evidence_sha256: str
    p8j_assessment_evidence_sha256: str
    evaluated_at_epoch: int
    incident_ids: tuple[str, ...]
    declared_complete_incident_ids: tuple[str, ...]
    declared_scope_event_ids_by_incident: Mapping[str, tuple[str, ...]]
    declared_reconstruction_sha256_by_incident: Mapping[str, str]
    declared_reentry_ids_by_incident: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class IncidentForensicsFact:
    incident_id: str
    decision: IncidentDecision
    risks: tuple[IncidentRisk, ...]
    trigger_event_ids: tuple[str, ...]
    scope_event_ids: tuple[str, ...]
    scope_agent_ids: tuple[str, ...]
    containment_action_ids: tuple[str, ...]
    forensic_package_id: str
    reconstruction_sha256: str
    reentry_authorization_ids: tuple[str, ...]
    risk_score: int


@dataclass(frozen=True)
class VerifiedAgentIncidentForensicsAssessment:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8g_assessment_evidence_sha256: str
    p8h_assessment_evidence_sha256: str
    p8i_assessment_evidence_sha256: str
    p8j_assessment_evidence_sha256: str
    incident_count: int
    allowed_incident_count: int
    denied_incident_count: int
    chain_integrity_denial_count: int
    containment_denial_count: int
    forensic_denial_count: int
    reentry_denial_count: int
    upstream_safety_denial_count: int
    maximum_risk_score: int
    incidents: tuple[IncidentForensicsFact, ...]
    assessment_evidence_sha256: str
    exact_incident_graph_binding_verified: bool = True
    exact_p8g_message_binding_verified: bool = True
    exact_p8h_state_binding_verified: bool = True
    exact_p8i_artifact_binding_verified: bool = True
    exact_p8j_recovery_binding_verified: bool = True
    tamper_evident_event_chains_verified: bool = True
    causal_incident_scope_derived: bool = True
    compromised_agents_quarantined: bool = True
    evidence_preservation_verified: bool = True
    deterministic_reconstruction_verified: bool = True
    controlled_reentry_checked: bool = True
    caller_declared_incident_safety_trusted: bool = False
    production_siem_or_edr_integration: bool = False
    production_distributed_log_integration: bool = False
    cryptographic_log_signatures: bool = False
    cross_host_clock_attestation: bool = False
    formal_causality_proof: bool = False
    exhaustive_incident_attack_coverage: bool = False
    network_operations: int = 0
    schema_version: str = P8K_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P8K_INCIDENT_POLICY_VERSION
    assessment_mode: str = P8K_ASSESSMENT_MODE


def _reject(reason: IncidentRejectReason, message: str, item_id: str | None = None) -> None:
    raise AgentIncidentForensicsRejected(reason, message, item_id=item_id)


def _sha(value: str | None) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value.casefold())


def _norm(value: object):
    if is_dataclass(value):
        return _norm(asdict(value))
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, dict):
        return {str(k): _norm(value[k]) for k in sorted(value)}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_norm(v) for v in sorted(value, key=lambda x: str(getattr(x, "value", x)))]
    if isinstance(value, str) and _sha(value):
        return value.casefold()
    return value


def _digest_json(value: object) -> str:
    raw = json.dumps(_norm(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _upstream_digest(value: object) -> str:
    return str(getattr(value, "assessment_evidence_sha256", "")).casefold()


def _state(value: object) -> str:
    raw = getattr(value, "decision", getattr(value, "outcome", getattr(value, "state", "")))
    return str(getattr(raw, "value", raw)).casefold()


def _safe(value: object) -> bool:
    return _state(value) in {"allow", "allowed", "safe", "holds"}


def _event_material(event: IncidentEvent) -> dict[str, object]:
    return {
        "event_id": event.event_id,
        "sequence": event.sequence,
        "agent_id": event.agent_id,
        "original_principal_id": event.original_principal_id,
        "tenant_id": event.tenant_id,
        "session_id": event.session_id,
        "kind": event.kind,
        "object_id": event.object_id,
        "parent_event_ids": event.parent_event_ids,
        "previous_event_sha256": event.previous_event_sha256,
        "payload_sha256": event.payload_sha256,
        "observed_at_epoch": event.observed_at_epoch,
        "owner_id": event.owner_id,
        "description": event.description,
    }


def incident_event_digest(event: IncidentEvent) -> str:
    return _digest_json(_event_material(event))


def _event_profile(event: IncidentEvent) -> tuple[object, ...]:
    return (
        event.sequence,
        event.agent_id,
        event.original_principal_id,
        event.tenant_id,
        event.session_id,
        event.kind.value,
        event.object_id,
        event.parent_event_ids,
        event.previous_event_sha256.casefold(),
        event.payload_sha256.casefold(),
        event.observed_at_epoch,
    )


def _incident_profile(incident: IncidentCase) -> tuple[object, ...]:
    return (
        incident.trigger_event_ids,
        incident.containment_action_ids,
        incident.forensic_package_id,
        incident.reentry_authorization_ids,
        incident.contained_at_epoch,
    )


def canonical_agent_incident_forensics_manifest_bytes(manifest: AgentIncidentForensicsManifest) -> bytes:
    return json.dumps(
        _norm(manifest), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()


def agent_incident_forensics_manifest_digest(manifest: AgentIncidentForensicsManifest) -> str:
    return hashlib.sha256(canonical_agent_incident_forensics_manifest_bytes(manifest)).hexdigest()


def forensic_package_digest(package: ForensicPackage) -> str:
    return _digest_json(package)


def reconstruction_digest(event_ids: tuple[str, ...]) -> str:
    return _digest_json({"reconstruction_event_ids": event_ids})


def evidence_scope_digest(events: Mapping[str, IncidentEvent], event_ids: tuple[str, ...]) -> str:
    payload = {event_id: events[event_id].event_sha256.casefold() for event_id in sorted(event_ids)}
    return _digest_json(payload)


def _coverage(values: tuple[object, ...], attr: str, required: frozenset[str], name: str) -> dict[str, object]:
    ids = [str(getattr(v, attr)) for v in values]
    if len(ids) != len(set(ids)):
        _reject(IncidentRejectReason.COVERAGE_MISMATCH, f"duplicate {name} identifier")
    if frozenset(ids) != required:
        _reject(IncidentRejectReason.COVERAGE_MISMATCH, f"{name} coverage mismatch")
    return {str(getattr(v, attr)): v for v in values}


def _assert_owner(owner_id: str, trusted: frozenset[str], item_id: str) -> None:
    if owner_id not in trusted:
        _reject(IncidentRejectReason.OWNER_UNTRUSTED, "untrusted evidence owner", item_id)


