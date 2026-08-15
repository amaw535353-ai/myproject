from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, is_dataclass
from enum import StrEnum
from typing import Mapping

P8J_RECOVERY_POLICY_VERSION = "agent-rollback-recovery-persistence-boundary-security-v1"
P8J_RECOVERY_SCHEMA_VERSION = "aegis-agent-recovery-persistence-manifest-v1"
P8J_ASSESSMENT_SCHEMA_VERSION = "aegis-agent-recovery-persistence-assessment-v1"
P8J_ASSESSMENT_MODE = "deterministic-evidence-bound-agent-recovery-security-v1"


class RecoveryItemKind(StrEnum):
    MEMORY = "memory"
    ARTIFACT = "artifact"
    MESSAGE = "message"
    CREDENTIAL = "credential"
    TASK_STATE = "task_state"
    POLICY_STATE = "policy_state"
    GENERIC = "generic"


class PersistenceState(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    QUARANTINED = "quarantined"
    SUPERSEDED = "superseded"


class CheckpointTrust(StrEnum):
    TRUSTED = "trusted"
    DEGRADED = "degraded"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"


class RecoveryMode(StrEnum):
    RESUME = "resume"
    ROLLBACK = "rollback"
    RESTORE = "restore"
    FORENSIC = "forensic"


class RecoveryDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class RecoveryRisk(StrEnum):
    CHECKPOINT_UNTRUSTED = "checkpoint_untrusted"
    CHECKPOINT_EXPIRED = "checkpoint_expired"
    CHECKPOINT_ANCESTRY_BROKEN = "checkpoint_ancestry_broken"
    CHECKPOINT_ROLLBACK_PAST_FLOOR = "checkpoint_rollback_past_floor"
    TARGET_NEWER_THAN_SOURCE = "target_newer_than_source"
    RESUME_TARGET_MISMATCH = "resume_target_mismatch"
    RECOVERY_TARGET_STALE = "recovery_target_stale"
    ITEM_REVOKED = "item_revoked"
    ITEM_QUARANTINED = "item_quarantined"
    ITEM_SUPERSEDED = "item_superseded"
    ITEM_HASH_MISMATCH = "item_hash_mismatch"
    ITEM_TENANT_MISMATCH = "item_tenant_mismatch"
    ITEM_SESSION_MISMATCH = "item_session_mismatch"
    ITEM_PRINCIPAL_MISMATCH = "item_principal_mismatch"
    RECOVERY_PROVENANCE_BROKEN = "recovery_provenance_broken"
    PARTITION_INCOMPLETE = "partition_incomplete"
    QUARANTINE_BYPASS = "quarantine_bypass"
    REVOCATION_BYPASS = "revocation_bypass"
    UNSAFE_MEMORY_REINTRODUCTION = "unsafe_memory_reintroduction"
    UNSAFE_ARTIFACT_REINTRODUCTION = "unsafe_artifact_reintroduction"
    UNSAFE_MESSAGE_REINTRODUCTION = "unsafe_message_reintroduction"
    CREDENTIAL_RESURRECTION = "credential_resurrection"
    STATE_ROLLBACK_UNSAFE = "state_rollback_unsafe"
    DESTRUCTIVE_ROLLBACK_UNAUTHORIZED = "destructive_rollback_unauthorized"
    AUTHORIZATION_SCOPE_MISMATCH = "authorization_scope_mismatch"
    AUTHORIZATION_EXPIRED = "authorization_expired"
    AUTHORIZATION_ITEM_MISMATCH = "authorization_item_mismatch"
    ROLLBACK_DEPTH_EXCEEDED = "rollback_depth_exceeded"
    RESUME_AFTER_COMPROMISE = "resume_after_compromise"
    UPSTREAM_MEMORY_UNSAFE = "upstream_memory_unsafe"
    UPSTREAM_ARTIFACT_UNSAFE = "upstream_artifact_unsafe"
    UPSTREAM_STATE_UNSAFE = "upstream_state_unsafe"


class RecoveryRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    UPSTREAM_INVALID = "upstream_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    COVERAGE_MISMATCH = "coverage_mismatch"
    OWNER_UNTRUSTED = "owner_untrusted"
    POLICY_DRIFT = "policy_drift"
    REFERENCE_INVALID = "reference_invalid"
    DECLARED_DECISION_MISMATCH = "declared_decision_mismatch"
    DECLARED_RISK_MISMATCH = "declared_risk_mismatch"
    DECLARED_CHECKPOINT_MISMATCH = "declared_checkpoint_mismatch"


class AgentRecoverySecurityRejected(ValueError):
    def __init__(self, reason: RecoveryRejectReason, message: str, *, item_id: str | None = None):
        super().__init__(message)
        self.reason = reason
        self.item_id = item_id


@dataclass(frozen=True)
class RecoveryItem:
    item_id: str
    kind: RecoveryItemKind
    tenant_id: str
    session_id: str | None
    original_principal_id: str
    source_ref_id: str
    content_sha256: str
    generation: int
    persistence_state: PersistenceState
    created_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class RecoveryCheckpoint:
    checkpoint_id: str
    tenant_id: str
    session_id: str | None
    original_principal_id: str
    parent_checkpoint_id: str | None
    generation: int
    state_sha256: str
    item_ids: tuple[str, ...]
    trust: CheckpointTrust
    created_at_epoch: int
    expires_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class RecoveryAuthorization:
    authorization_id: str
    actor_agent_id: str
    original_principal_id: str
    tenant_id: str
    allowed_modes: frozenset[RecoveryMode]
    approved_item_ids: frozenset[str]
    max_rollback_generations: int
    destructive_allowed: bool
    issued_at_epoch: int
    expires_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class RecoveryOperation:
    recovery_id: str
    mode: RecoveryMode
    actor_agent_id: str
    original_principal_id: str
    tenant_id: str
    session_id: str | None
    source_checkpoint_id: str
    target_checkpoint_id: str
    restore_item_ids: tuple[str, ...]
    quarantine_item_ids: tuple[str, ...]
    revoke_item_ids: tuple[str, ...]
    authorization_id: str | None
    expected_source_state_sha256: str
    expected_target_state_sha256: str
    issued_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class AgentRecoveryManifest:
    graph_id: str
    version: str
    p8b_assessment_evidence_sha256: str
    p8i_assessment_evidence_sha256: str
    p8h_assessment_evidence_sha256: str
    created_at_epoch: int
    items: tuple[RecoveryItem, ...]
    checkpoints: tuple[RecoveryCheckpoint, ...]
    authorizations: tuple[RecoveryAuthorization, ...]
    recoveries: tuple[RecoveryOperation, ...]
    schema_version: str = P8J_RECOVERY_SCHEMA_VERSION


@dataclass(frozen=True)
class AgentRecoveryPolicy:
    expected_graph_id: str
    expected_graph_version: str
    expected_graph_sha256: str
    expected_p8b_assessment_evidence_sha256: str
    expected_p8i_assessment_evidence_sha256: str
    expected_p8h_assessment_evidence_sha256: str
    required_item_ids: frozenset[str]
    required_checkpoint_ids: frozenset[str]
    required_authorization_ids: frozenset[str]
    required_recovery_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    expected_item_profiles: Mapping[str, tuple[object, ...]]
    expected_checkpoint_profiles: Mapping[str, tuple[object, ...]]
    recovery_floor_generation_by_tenant: Mapping[str, int]
    non_restorable_item_ids: frozenset[str]
    credential_refresh_required_item_ids: frozenset[str]
    authorization_required_modes: frozenset[RecoveryMode]
    destructive_modes: frozenset[RecoveryMode]
    max_manifest_age_seconds: int = 86_400
    max_checkpoint_age_seconds: int = 604_800
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class AgentRecoveryRequest:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8b_assessment_evidence_sha256: str
    p8i_assessment_evidence_sha256: str
    p8h_assessment_evidence_sha256: str
    evaluated_at_epoch: int
    recovery_ids: tuple[str, ...]
    declared_denied_recovery_ids: tuple[str, ...]
    declared_risks_by_recovery: Mapping[str, tuple[RecoveryRisk, ...]]
    declared_target_checkpoint_by_recovery: Mapping[str, str]


@dataclass(frozen=True)
class RecoveryFact:
    recovery_id: str
    mode: RecoveryMode
    decision: RecoveryDecision
    risks: tuple[RecoveryRisk, ...]
    source_checkpoint_id: str
    target_checkpoint_id: str
    restored_item_ids: tuple[str, ...]
    quarantined_item_ids: tuple[str, ...]
    revoked_item_ids: tuple[str, ...]
    rollback_generations: int
    risk_score: int


@dataclass(frozen=True)
class VerifiedAgentRecoveryAssessment:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8b_assessment_evidence_sha256: str
    p8i_assessment_evidence_sha256: str
    p8h_assessment_evidence_sha256: str
    recovery_count: int
    allowed_recovery_count: int
    denied_recovery_count: int
    checkpoint_denial_count: int
    persistence_reintroduction_denial_count: int
    authorization_denial_count: int
    upstream_safety_denial_count: int
    quarantine_or_revocation_denial_count: int
    maximum_risk_score: int
    recoveries: tuple[RecoveryFact, ...]
    assessment_evidence_sha256: str
    exact_recovery_graph_binding_verified: bool = True
    exact_p8b_memory_binding_verified: bool = True
    exact_p8i_artifact_binding_verified: bool = True
    exact_p8h_state_transition_binding_verified: bool = True
    checkpoint_ancestry_and_generation_checked: bool = True
    persistence_revocation_and_quarantine_enforced: bool = True
    compromised_state_resume_prevented: bool = True
    destructive_rollback_authorization_checked: bool = True
    recovery_provenance_partition_checked: bool = True
    caller_declared_recovery_safety_trusted: bool = False
    production_backup_restore_enforcement: bool = False
    production_checkpoint_store_integration: bool = False
    cryptographic_checkpoint_attestation: bool = False
    formal_recovery_safety_proof: bool = False
    exhaustive_recovery_attack_coverage: bool = False
    network_operations: int = 0
    schema_version: str = P8J_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P8J_RECOVERY_POLICY_VERSION
    assessment_mode: str = P8J_ASSESSMENT_MODE


def _reject(reason: RecoveryRejectReason, message: str, item_id: str | None = None) -> None:
    raise AgentRecoverySecurityRejected(reason, message, item_id=item_id)


def _sha(value: str | None) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value.casefold())


def _digest(value: object) -> str:
    return str(getattr(value, "assessment_evidence_sha256", "")).casefold()


def _state(value: object) -> str:
    raw = getattr(value, "decision", getattr(value, "outcome", getattr(value, "state", "")))
    return str(getattr(raw, "value", raw)).casefold()


def _safe(value: object) -> bool:
    return _state(value) in {"allow", "allowed", "safe", "holds"}


def _norm(value: object):
    if is_dataclass(value):
        return _norm(asdict(value))
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, dict):
        return {str(k): _norm(value[k]) for k in sorted(value)}
    if isinstance(value, (tuple, list, set, frozenset)):
        return [_norm(v) for v in sorted(value, key=lambda x: str(getattr(x, "value", x)))]
    if isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value):
        return value.casefold()
    return value


def canonical_agent_recovery_manifest_bytes(manifest: AgentRecoveryManifest) -> bytes:
    return json.dumps(_norm(manifest), sort_keys=True, separators=(",", ":")).encode()


def agent_recovery_manifest_digest(manifest: AgentRecoveryManifest) -> str:
    return hashlib.sha256(canonical_agent_recovery_manifest_bytes(manifest)).hexdigest()


def _item_profile(item: RecoveryItem) -> tuple[object, ...]:
    return (
        item.kind,
        item.tenant_id,
        item.session_id,
        item.original_principal_id,
        item.source_ref_id,
        item.content_sha256.casefold(),
        item.generation,
        item.persistence_state,
    )


def _checkpoint_profile(checkpoint: RecoveryCheckpoint) -> tuple[object, ...]:
    return (
        checkpoint.tenant_id,
        checkpoint.session_id,
        checkpoint.original_principal_id,
        checkpoint.parent_checkpoint_id,
        checkpoint.generation,
        checkpoint.state_sha256.casefold(),
        checkpoint.item_ids,
        checkpoint.trust,
    )


_RISK_SCORE = {
    RecoveryRisk.CHECKPOINT_UNTRUSTED: 118,
    RecoveryRisk.CHECKPOINT_EXPIRED: 100,
    RecoveryRisk.CHECKPOINT_ANCESTRY_BROKEN: 116,
    RecoveryRisk.CHECKPOINT_ROLLBACK_PAST_FLOOR: 121,
    RecoveryRisk.TARGET_NEWER_THAN_SOURCE: 108,
    RecoveryRisk.RESUME_TARGET_MISMATCH: 108,
    RecoveryRisk.RECOVERY_TARGET_STALE: 109,
    RecoveryRisk.ITEM_REVOKED: 122,
    RecoveryRisk.ITEM_QUARANTINED: 122,
    RecoveryRisk.ITEM_SUPERSEDED: 116,
    RecoveryRisk.ITEM_HASH_MISMATCH: 113,
    RecoveryRisk.ITEM_TENANT_MISMATCH: 120,
    RecoveryRisk.ITEM_SESSION_MISMATCH: 112,
    RecoveryRisk.ITEM_PRINCIPAL_MISMATCH: 118,
    RecoveryRisk.RECOVERY_PROVENANCE_BROKEN: 117,
    RecoveryRisk.PARTITION_INCOMPLETE: 111,
    RecoveryRisk.QUARANTINE_BYPASS: 122,
    RecoveryRisk.REVOCATION_BYPASS: 124,
    RecoveryRisk.UNSAFE_MEMORY_REINTRODUCTION: 124,
    RecoveryRisk.UNSAFE_ARTIFACT_REINTRODUCTION: 124,
    RecoveryRisk.UNSAFE_MESSAGE_REINTRODUCTION: 123,
    RecoveryRisk.CREDENTIAL_RESURRECTION: 126,
    RecoveryRisk.STATE_ROLLBACK_UNSAFE: 123,
    RecoveryRisk.DESTRUCTIVE_ROLLBACK_UNAUTHORIZED: 126,
    RecoveryRisk.AUTHORIZATION_SCOPE_MISMATCH: 121,
    RecoveryRisk.AUTHORIZATION_EXPIRED: 113,
    RecoveryRisk.AUTHORIZATION_ITEM_MISMATCH: 120,
    RecoveryRisk.ROLLBACK_DEPTH_EXCEEDED: 116,
    RecoveryRisk.RESUME_AFTER_COMPROMISE: 126,
    RecoveryRisk.UPSTREAM_MEMORY_UNSAFE: 122,
    RecoveryRisk.UPSTREAM_ARTIFACT_UNSAFE: 122,
    RecoveryRisk.UPSTREAM_STATE_UNSAFE: 122,
}


def _assessment_digest(facts: tuple[RecoveryFact, ...], manifest: AgentRecoveryManifest) -> str:
    doc = {
        "graph_sha256": agent_recovery_manifest_digest(manifest),
        "recoveries": [
            {
                "id": f.recovery_id,
                "decision": f.decision.value,
                "risks": [r.value for r in f.risks],
                "target": f.target_checkpoint_id,
                "restore": list(f.restored_item_ids),
                "quarantine": list(f.quarantined_item_ids),
                "revoke": list(f.revoked_item_ids),
                "rollback_generations": f.rollback_generations,
                "score": f.risk_score,
            }
            for f in facts
        ],
    }
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AgentRollbackRecoverySecurityAnalyzer:
    def __init__(self, policy: AgentRecoveryPolicy):
        self.policy = policy

    def _validate_policy(self) -> None:
        p = self.policy
        if not p.expected_graph_id or not p.expected_graph_version or not p.trusted_owner_ids:
            _reject(RecoveryRejectReason.POLICY_INVALID, "missing graph or owner policy")
        if not all(
            _sha(x)
            for x in (
                p.expected_graph_sha256,
                p.expected_p8b_assessment_evidence_sha256,
                p.expected_p8i_assessment_evidence_sha256,
                p.expected_p8h_assessment_evidence_sha256,
            )
        ):
            _reject(RecoveryRejectReason.POLICY_INVALID, "invalid digest pin")
        if p.max_manifest_age_seconds <= 0 or p.max_checkpoint_age_seconds <= 0 or p.max_future_skew_seconds < 0:
            _reject(RecoveryRejectReason.POLICY_INVALID, "invalid freshness policy")
        if set(p.expected_item_profiles) != set(p.required_item_ids):
            _reject(RecoveryRejectReason.POLICY_INVALID, "item profile coverage mismatch")
        if set(p.expected_checkpoint_profiles) != set(p.required_checkpoint_ids):
            _reject(RecoveryRejectReason.POLICY_INVALID, "checkpoint profile coverage mismatch")
        if not (p.non_restorable_item_ids | p.credential_refresh_required_item_ids).issubset(p.required_item_ids):
            _reject(RecoveryRejectReason.POLICY_INVALID, "item policy references unknown item")
        if not p.authorization_required_modes.issubset(set(RecoveryMode)) or not p.destructive_modes.issubset(set(RecoveryMode)):
            _reject(RecoveryRejectReason.POLICY_INVALID, "mode policy invalid")

    def _validate_upstreams(self, manifest: AgentRecoveryManifest, p8b: object, p8i: object, p8h: object) -> None:
        checks = (
            (
                p8b,
                self.policy.expected_p8b_assessment_evidence_sha256,
                manifest.p8b_assessment_evidence_sha256,
                ("exact_memory_graph_binding_verified", "revocation_and_supersession_enforced"),
                "caller_declared_memory_safety_trusted",
            ),
            (
                p8i,
                self.policy.expected_p8i_assessment_evidence_sha256,
                manifest.p8i_assessment_evidence_sha256,
                ("exact_artifact_graph_binding_verified", "sensitive_persistence_paths_checked"),
                "caller_declared_artifact_safety_trusted",
            ),
            (
                p8h,
                self.policy.expected_p8h_assessment_evidence_sha256,
                manifest.p8h_assessment_evidence_sha256,
                ("exact_state_transition_graph_binding_verified", "cancellation_and_rollback_races_checked"),
                "caller_declared_state_safety_trusted",
            ),
        )
        for obj, pin, manifest_pin, flags, caller_flag in checks:
            if _digest(obj) != pin.casefold() or manifest_pin.casefold() != pin.casefold():
                _reject(RecoveryRejectReason.UPSTREAM_INVALID, "upstream digest mismatch")
            if not all(bool(getattr(obj, flag, False)) for flag in flags) or bool(getattr(obj, caller_flag, True)):
                _reject(RecoveryRejectReason.UPSTREAM_INVALID, "upstream verification boundary invalid")

    def _map(self, items: tuple[object, ...], attr: str) -> dict[str, object]:
        out: dict[str, object] = {}
        for item in items:
            key = str(getattr(item, attr))
            if key in out:
                _reject(RecoveryRejectReason.COVERAGE_MISMATCH, "duplicate identifier", key)
            out[key] = item
        return out

    def _validate_checkpoint_ancestry(self, checkpoints: Mapping[str, RecoveryCheckpoint]) -> None:
        for checkpoint_id, cp in checkpoints.items():
            seen: set[str] = set()
            cur = cp
            while cur.parent_checkpoint_id is not None:
                if cur.checkpoint_id in seen:
                    _reject(RecoveryRejectReason.REFERENCE_INVALID, "checkpoint ancestry cycle", checkpoint_id)
                seen.add(cur.checkpoint_id)
                parent = checkpoints.get(cur.parent_checkpoint_id)
                if parent is None:
                    _reject(RecoveryRejectReason.REFERENCE_INVALID, "checkpoint parent missing", checkpoint_id)
                if parent.tenant_id != cur.tenant_id or parent.original_principal_id != cur.original_principal_id:
                    _reject(RecoveryRejectReason.REFERENCE_INVALID, "checkpoint ancestry scope mismatch", checkpoint_id)
                if parent.generation >= cur.generation:
                    _reject(RecoveryRejectReason.REFERENCE_INVALID, "checkpoint generation non-monotonic", checkpoint_id)
                cur = parent

    def _validate_manifest(self, manifest: AgentRecoveryManifest, now: int):
        p = self.policy
        if (
            manifest.schema_version != P8J_RECOVERY_SCHEMA_VERSION
            or manifest.graph_id != p.expected_graph_id
            or manifest.version != p.expected_graph_version
        ):
            _reject(RecoveryRejectReason.MANIFEST_INVALID, "manifest identity invalid")
        if agent_recovery_manifest_digest(manifest) != p.expected_graph_sha256.casefold():
            _reject(RecoveryRejectReason.MANIFEST_INVALID, "manifest digest mismatch")
        if now - manifest.created_at_epoch > p.max_manifest_age_seconds or manifest.created_at_epoch - now > p.max_future_skew_seconds:
            _reject(RecoveryRejectReason.MANIFEST_INVALID, "manifest freshness invalid")

        items = self._map(manifest.items, "item_id")
        checkpoints = self._map(manifest.checkpoints, "checkpoint_id")
        authorizations = self._map(manifest.authorizations, "authorization_id")
        recoveries = self._map(manifest.recoveries, "recovery_id")
        if (
            set(items) != set(p.required_item_ids)
            or set(checkpoints) != set(p.required_checkpoint_ids)
            or set(authorizations) != set(p.required_authorization_ids)
            or set(recoveries) != set(p.required_recovery_ids)
        ):
            _reject(RecoveryRejectReason.COVERAGE_MISMATCH, "manifest coverage mismatch")

        for item_id, item in items.items():
            if item.owner_id not in p.trusted_owner_ids:
                _reject(RecoveryRejectReason.OWNER_UNTRUSTED, "item owner untrusted", item_id)
            if item.generation < 0 or not item.source_ref_id or not _sha(item.content_sha256):
                _reject(RecoveryRejectReason.REFERENCE_INVALID, "item reference invalid", item_id)
            if _item_profile(item) != p.expected_item_profiles.get(item_id):
                _reject(RecoveryRejectReason.POLICY_DRIFT, "item profile drift", item_id)

        for checkpoint_id, cp in checkpoints.items():
            if cp.owner_id not in p.trusted_owner_ids:
                _reject(RecoveryRejectReason.OWNER_UNTRUSTED, "checkpoint owner untrusted", checkpoint_id)
            if cp.generation < 0 or not _sha(cp.state_sha256) or cp.expires_at_epoch < cp.created_at_epoch:
                _reject(RecoveryRejectReason.REFERENCE_INVALID, "checkpoint state invalid", checkpoint_id)
            if len(set(cp.item_ids)) != len(cp.item_ids) or not set(cp.item_ids).issubset(items):
                _reject(RecoveryRejectReason.REFERENCE_INVALID, "checkpoint item references invalid", checkpoint_id)
            if any(items[item_id].generation > cp.generation for item_id in cp.item_ids):
                _reject(RecoveryRejectReason.REFERENCE_INVALID, "checkpoint contains future-generation item", checkpoint_id)
            if _checkpoint_profile(cp) != p.expected_checkpoint_profiles.get(checkpoint_id):
                _reject(RecoveryRejectReason.POLICY_DRIFT, "checkpoint profile drift", checkpoint_id)

        self._validate_checkpoint_ancestry(checkpoints)

        for auth_id, auth in authorizations.items():
            if auth.owner_id not in p.trusted_owner_ids:
                _reject(RecoveryRejectReason.OWNER_UNTRUSTED, "authorization owner untrusted", auth_id)
            if (
                not auth.actor_agent_id
                or not auth.original_principal_id
                or not auth.tenant_id
                or not auth.allowed_modes
                or auth.max_rollback_generations < 0
                or auth.expires_at_epoch < auth.issued_at_epoch
                or not set(auth.approved_item_ids).issubset(items)
            ):
                _reject(RecoveryRejectReason.REFERENCE_INVALID, "authorization invalid", auth_id)

        for recovery_id, op in recoveries.items():
            if op.owner_id not in p.trusted_owner_ids:
                _reject(RecoveryRejectReason.OWNER_UNTRUSTED, "recovery owner untrusted", recovery_id)
            if op.source_checkpoint_id not in checkpoints or op.target_checkpoint_id not in checkpoints:
                _reject(RecoveryRejectReason.REFERENCE_INVALID, "checkpoint reference invalid", recovery_id)
            if op.authorization_id is not None and op.authorization_id not in authorizations:
                _reject(RecoveryRejectReason.REFERENCE_INVALID, "authorization reference invalid", recovery_id)
            item_refs = set(op.restore_item_ids) | set(op.quarantine_item_ids) | set(op.revoke_item_ids)
            if not item_refs.issubset(items):
                _reject(RecoveryRejectReason.REFERENCE_INVALID, "recovery item reference invalid", recovery_id)
            if len(op.restore_item_ids) != len(set(op.restore_item_ids)) or len(op.quarantine_item_ids) != len(set(op.quarantine_item_ids)) or len(op.revoke_item_ids) != len(set(op.revoke_item_ids)):
                _reject(RecoveryRejectReason.REFERENCE_INVALID, "duplicate recovery item reference", recovery_id)
            if not all(_sha(v) for v in (op.expected_source_state_sha256, op.expected_target_state_sha256)):
                _reject(RecoveryRejectReason.REFERENCE_INVALID, "recovery state digest invalid", recovery_id)
        return items, checkpoints, authorizations, recoveries

    def _upstream_memory_safe(self, item: RecoveryItem, p8b: object) -> bool | None:
        matches = [x for x in getattr(p8b, "writes", ()) if str(getattr(x, "memory_id", "")) == item.source_ref_id]
        if not matches:
            retrieval_matches = [
                x
                for x in getattr(p8b, "retrievals", ())
                if item.source_ref_id in tuple(str(v) for v in getattr(x, "memory_ids", ()))
            ]
            matches = retrieval_matches
        if not matches:
            return None
        return all(_safe(x) for x in matches)

    def _upstream_artifact_safe(self, item: RecoveryItem, p8i: object) -> bool | None:
        matches = [x for x in getattr(p8i, "actions", ()) if str(getattr(x, "artifact_id", "")) == item.source_ref_id]
        if not matches:
            return None
        return all(_safe(x) for x in matches)

    def _upstream_state_safe(self, item: RecoveryItem, p8h: object) -> bool | None:
        matches = [x for x in getattr(p8h, "transitions", ()) if str(getattr(x, "object_id", "")) == item.source_ref_id]
        if not matches:
            return None
        return all(_safe(x) for x in matches)

    def derive(
        self,
        manifest: AgentRecoveryManifest,
        p8b: object,
        p8i: object,
        p8h: object,
        evaluated_at_epoch: int,
    ) -> tuple[RecoveryFact, ...]:
        self._validate_policy()
        self._validate_upstreams(manifest, p8b, p8i, p8h)
        items, checkpoints, authorizations, recoveries = self._validate_manifest(manifest, evaluated_at_epoch)
        p = self.policy
        facts: list[RecoveryFact] = []

        for op in manifest.recoveries:
            risks: set[RecoveryRisk] = set()
            source = checkpoints[op.source_checkpoint_id]
            target = checkpoints[op.target_checkpoint_id]
            rollback_generations = max(0, source.generation - target.generation)

            if op.expected_source_state_sha256.casefold() != source.state_sha256.casefold() or op.expected_target_state_sha256.casefold() != target.state_sha256.casefold():
                risks.add(RecoveryRisk.RECOVERY_TARGET_STALE)
            if source.tenant_id != op.tenant_id or target.tenant_id != op.tenant_id:
                risks.add(RecoveryRisk.ITEM_TENANT_MISMATCH)
            if source.session_id != op.session_id or target.session_id != op.session_id:
                risks.add(RecoveryRisk.ITEM_SESSION_MISMATCH)
            if source.original_principal_id != op.original_principal_id or target.original_principal_id != op.original_principal_id:
                risks.add(RecoveryRisk.ITEM_PRINCIPAL_MISMATCH)
            if target.trust in {CheckpointTrust.COMPROMISED, CheckpointTrust.QUARANTINED}:
                risks.add(RecoveryRisk.CHECKPOINT_UNTRUSTED)
            if op.mode == RecoveryMode.RESUME and source.trust != CheckpointTrust.TRUSTED:
                risks.add(RecoveryRisk.RESUME_AFTER_COMPROMISE)
            if evaluated_at_epoch > target.expires_at_epoch or evaluated_at_epoch - target.created_at_epoch > p.max_checkpoint_age_seconds:
                risks.add(RecoveryRisk.CHECKPOINT_EXPIRED)
            if op.issued_at_epoch < target.created_at_epoch or op.issued_at_epoch > evaluated_at_epoch + p.max_future_skew_seconds:
                risks.add(RecoveryRisk.RECOVERY_TARGET_STALE)
            floor = p.recovery_floor_generation_by_tenant.get(op.tenant_id, 0)
            if target.generation < floor:
                risks.add(RecoveryRisk.CHECKPOINT_ROLLBACK_PAST_FLOOR)
            if op.mode == RecoveryMode.ROLLBACK and target.generation > source.generation:
                risks.add(RecoveryRisk.TARGET_NEWER_THAN_SOURCE)
            if op.mode == RecoveryMode.RESUME and source.checkpoint_id != target.checkpoint_id:
                risks.add(RecoveryRisk.RESUME_TARGET_MISMATCH)

            restore = set(op.restore_item_ids)
            quarantine = set(op.quarantine_item_ids)
            revoke = set(op.revoke_item_ids)
            if (restore & quarantine) or (restore & revoke) or (quarantine & revoke):
                risks.add(RecoveryRisk.RECOVERY_PROVENANCE_BROKEN)
            target_items = set(target.item_ids)
            if not restore.issubset(target_items):
                risks.add(RecoveryRisk.RECOVERY_PROVENANCE_BROKEN)
            if restore != target_items:
                risks.add(RecoveryRisk.PARTITION_INCOMPLETE)

            source_only = set(source.item_ids) - target_items
            handled_source_only = quarantine | revoke
            if source.trust in {CheckpointTrust.DEGRADED, CheckpointTrust.COMPROMISED, CheckpointTrust.QUARANTINED} and not source_only.issubset(handled_source_only):
                risks.add(RecoveryRisk.QUARANTINE_BYPASS)

            for item_id in restore:
                item = items[item_id]
                if item.tenant_id != op.tenant_id:
                    risks.add(RecoveryRisk.ITEM_TENANT_MISMATCH)
                if item.session_id != op.session_id:
                    risks.add(RecoveryRisk.ITEM_SESSION_MISMATCH)
                if item.original_principal_id != op.original_principal_id:
                    risks.add(RecoveryRisk.ITEM_PRINCIPAL_MISMATCH)
                if item.generation > target.generation or item.created_at_epoch > target.created_at_epoch:
                    risks.add(RecoveryRisk.RECOVERY_PROVENANCE_BROKEN)
                if item.persistence_state == PersistenceState.REVOKED:
                    risks.add(RecoveryRisk.ITEM_REVOKED)
                elif item.persistence_state == PersistenceState.QUARANTINED:
                    risks.add(RecoveryRisk.ITEM_QUARANTINED)
                elif item.persistence_state == PersistenceState.SUPERSEDED:
                    risks.add(RecoveryRisk.ITEM_SUPERSEDED)
                if item_id in p.non_restorable_item_ids:
                    if item.kind == RecoveryItemKind.MESSAGE:
                        risks.add(RecoveryRisk.UNSAFE_MESSAGE_REINTRODUCTION)
                    elif item.kind == RecoveryItemKind.MEMORY:
                        risks.add(RecoveryRisk.UNSAFE_MEMORY_REINTRODUCTION)
                    elif item.kind == RecoveryItemKind.ARTIFACT:
                        risks.add(RecoveryRisk.UNSAFE_ARTIFACT_REINTRODUCTION)
                    else:
                        risks.add(RecoveryRisk.REVOCATION_BYPASS)
                if item.kind == RecoveryItemKind.CREDENTIAL and item_id in p.credential_refresh_required_item_ids:
                    risks.add(RecoveryRisk.CREDENTIAL_RESURRECTION)
                if item.kind == RecoveryItemKind.MEMORY:
                    safe = self._upstream_memory_safe(item, p8b)
                    if safe is None:
                        risks.add(RecoveryRisk.RECOVERY_PROVENANCE_BROKEN)
                    elif not safe:
                        risks.add(RecoveryRisk.UPSTREAM_MEMORY_UNSAFE)
                        risks.add(RecoveryRisk.UNSAFE_MEMORY_REINTRODUCTION)
                elif item.kind == RecoveryItemKind.ARTIFACT:
                    safe = self._upstream_artifact_safe(item, p8i)
                    if safe is None:
                        risks.add(RecoveryRisk.RECOVERY_PROVENANCE_BROKEN)
                    elif not safe:
                        risks.add(RecoveryRisk.UPSTREAM_ARTIFACT_UNSAFE)
                        risks.add(RecoveryRisk.UNSAFE_ARTIFACT_REINTRODUCTION)
                elif item.kind in {RecoveryItemKind.TASK_STATE, RecoveryItemKind.POLICY_STATE}:
                    safe = self._upstream_state_safe(item, p8h)
                    if safe is None:
                        risks.add(RecoveryRisk.RECOVERY_PROVENANCE_BROKEN)
                    elif not safe:
                        risks.add(RecoveryRisk.UPSTREAM_STATE_UNSAFE)
                        risks.add(RecoveryRisk.STATE_ROLLBACK_UNSAFE)

            for item_id in quarantine:
                item = items[item_id]
                if item.persistence_state not in {PersistenceState.QUARANTINED, PersistenceState.REVOKED, PersistenceState.SUPERSEDED} and item_id not in p.non_restorable_item_ids:
                    risks.add(RecoveryRisk.QUARANTINE_BYPASS)
            for item_id in revoke:
                item = items[item_id]
                if item.persistence_state != PersistenceState.REVOKED and item.kind != RecoveryItemKind.CREDENTIAL:
                    risks.add(RecoveryRisk.REVOCATION_BYPASS)

            auth = authorizations.get(op.authorization_id or "") if op.authorization_id else None
            needs_auth = op.mode in p.authorization_required_modes
            destructive = op.mode in p.destructive_modes or bool(revoke)
            if needs_auth and auth is None:
                risks.add(RecoveryRisk.DESTRUCTIVE_ROLLBACK_UNAUTHORIZED)
            if auth is not None:
                if (
                    auth.actor_agent_id != op.actor_agent_id
                    or auth.original_principal_id != op.original_principal_id
                    or auth.tenant_id != op.tenant_id
                    or op.mode not in auth.allowed_modes
                ):
                    risks.add(RecoveryRisk.AUTHORIZATION_SCOPE_MISMATCH)
                if not (auth.issued_at_epoch <= op.issued_at_epoch <= auth.expires_at_epoch) or evaluated_at_epoch > auth.expires_at_epoch:
                    risks.add(RecoveryRisk.AUTHORIZATION_EXPIRED)
                touched = restore | quarantine | revoke
                if not touched.issubset(auth.approved_item_ids):
                    risks.add(RecoveryRisk.AUTHORIZATION_ITEM_MISMATCH)
                if rollback_generations > auth.max_rollback_generations:
                    risks.add(RecoveryRisk.ROLLBACK_DEPTH_EXCEEDED)
                if destructive and not auth.destructive_allowed:
                    risks.add(RecoveryRisk.DESTRUCTIVE_ROLLBACK_UNAUTHORIZED)
            elif destructive:
                risks.add(RecoveryRisk.DESTRUCTIVE_ROLLBACK_UNAUTHORIZED)

            ordered = tuple(sorted(risks, key=lambda r: r.value))
            facts.append(
                RecoveryFact(
                    recovery_id=op.recovery_id,
                    mode=op.mode,
                    decision=RecoveryDecision.DENY if ordered else RecoveryDecision.ALLOW,
                    risks=ordered,
                    source_checkpoint_id=source.checkpoint_id,
                    target_checkpoint_id=target.checkpoint_id,
                    restored_item_ids=tuple(sorted(restore)),
                    quarantined_item_ids=tuple(sorted(quarantine)),
                    revoked_item_ids=tuple(sorted(revoke)),
                    rollback_generations=rollback_generations,
                    risk_score=max((_RISK_SCORE[r] for r in ordered), default=0),
                )
            )
        return tuple(facts)

    def evaluate(
        self,
        request: AgentRecoveryRequest,
        manifest: AgentRecoveryManifest,
        p8b: object,
        p8i: object,
        p8h: object,
    ) -> VerifiedAgentRecoveryAssessment:
        p = self.policy
        if (
            request.graph_id != p.expected_graph_id
            or request.graph_version != p.expected_graph_version
            or request.graph_sha256.casefold() != p.expected_graph_sha256.casefold()
        ):
            _reject(RecoveryRejectReason.REQUEST_INVALID, "request graph binding invalid")
        if (
            request.p8b_assessment_evidence_sha256.casefold() != p.expected_p8b_assessment_evidence_sha256.casefold()
            or request.p8i_assessment_evidence_sha256.casefold() != p.expected_p8i_assessment_evidence_sha256.casefold()
            or request.p8h_assessment_evidence_sha256.casefold() != p.expected_p8h_assessment_evidence_sha256.casefold()
        ):
            _reject(RecoveryRejectReason.REQUEST_INVALID, "request upstream binding invalid")
        if tuple(request.recovery_ids) != tuple(r.recovery_id for r in manifest.recoveries):
            _reject(RecoveryRejectReason.COVERAGE_MISMATCH, "request recovery coverage mismatch")
        facts = self.derive(manifest, p8b, p8i, p8h, request.evaluated_at_epoch)
        denied = tuple(f.recovery_id for f in facts if f.decision == RecoveryDecision.DENY)
        if tuple(request.declared_denied_recovery_ids) != denied:
            _reject(RecoveryRejectReason.DECLARED_DECISION_MISMATCH, "declared denied recovery IDs mismatch")
        derived_risks = {f.recovery_id: f.risks for f in facts}
        if dict(request.declared_risks_by_recovery) != derived_risks:
            _reject(RecoveryRejectReason.DECLARED_RISK_MISMATCH, "declared recovery risks mismatch")
        derived_targets = {f.recovery_id: f.target_checkpoint_id for f in facts}
        if dict(request.declared_target_checkpoint_by_recovery) != derived_targets:
            _reject(RecoveryRejectReason.DECLARED_CHECKPOINT_MISMATCH, "declared target checkpoint mismatch")

        checkpoint_risks = {
            RecoveryRisk.CHECKPOINT_UNTRUSTED,
            RecoveryRisk.CHECKPOINT_EXPIRED,
            RecoveryRisk.CHECKPOINT_ANCESTRY_BROKEN,
            RecoveryRisk.CHECKPOINT_ROLLBACK_PAST_FLOOR,
            RecoveryRisk.TARGET_NEWER_THAN_SOURCE,
            RecoveryRisk.RESUME_TARGET_MISMATCH,
            RecoveryRisk.RECOVERY_TARGET_STALE,
            RecoveryRisk.RESUME_AFTER_COMPROMISE,
        }
        reintro_risks = {
            RecoveryRisk.UNSAFE_MEMORY_REINTRODUCTION,
            RecoveryRisk.UNSAFE_ARTIFACT_REINTRODUCTION,
            RecoveryRisk.UNSAFE_MESSAGE_REINTRODUCTION,
            RecoveryRisk.CREDENTIAL_RESURRECTION,
            RecoveryRisk.ITEM_REVOKED,
            RecoveryRisk.ITEM_QUARANTINED,
            RecoveryRisk.ITEM_SUPERSEDED,
        }
        auth_risks = {
            RecoveryRisk.DESTRUCTIVE_ROLLBACK_UNAUTHORIZED,
            RecoveryRisk.AUTHORIZATION_SCOPE_MISMATCH,
            RecoveryRisk.AUTHORIZATION_EXPIRED,
            RecoveryRisk.AUTHORIZATION_ITEM_MISMATCH,
            RecoveryRisk.ROLLBACK_DEPTH_EXCEEDED,
        }
        upstream_risks = {
            RecoveryRisk.UPSTREAM_MEMORY_UNSAFE,
            RecoveryRisk.UPSTREAM_ARTIFACT_UNSAFE,
            RecoveryRisk.UPSTREAM_STATE_UNSAFE,
        }
        quarantine_risks = {
            RecoveryRisk.QUARANTINE_BYPASS,
            RecoveryRisk.REVOCATION_BYPASS,
            RecoveryRisk.PARTITION_INCOMPLETE,
            RecoveryRisk.RECOVERY_PROVENANCE_BROKEN,
        }

        def count(bucket: set[RecoveryRisk]) -> int:
            return sum(any(r in bucket for r in f.risks) for f in facts)

        return VerifiedAgentRecoveryAssessment(
            graph_id=request.graph_id,
            graph_version=request.graph_version,
            graph_sha256=request.graph_sha256.casefold(),
            p8b_assessment_evidence_sha256=request.p8b_assessment_evidence_sha256.casefold(),
            p8i_assessment_evidence_sha256=request.p8i_assessment_evidence_sha256.casefold(),
            p8h_assessment_evidence_sha256=request.p8h_assessment_evidence_sha256.casefold(),
            recovery_count=len(facts),
            allowed_recovery_count=sum(f.decision == RecoveryDecision.ALLOW for f in facts),
            denied_recovery_count=sum(f.decision == RecoveryDecision.DENY for f in facts),
            checkpoint_denial_count=count(checkpoint_risks),
            persistence_reintroduction_denial_count=count(reintro_risks),
            authorization_denial_count=count(auth_risks),
            upstream_safety_denial_count=count(upstream_risks),
            quarantine_or_revocation_denial_count=count(quarantine_risks),
            maximum_risk_score=max((f.risk_score for f in facts), default=0),
            recoveries=facts,
            assessment_evidence_sha256=_assessment_digest(facts, manifest),
        )
