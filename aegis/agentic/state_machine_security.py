from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, is_dataclass
from enum import StrEnum
from typing import Mapping

P8H_STATE_POLICY_VERSION = "agent-state-machine-concurrency-race-security-v1"
P8H_STATE_SCHEMA_VERSION = "aegis-agent-state-transition-manifest-v1"
P8H_ASSESSMENT_SCHEMA_VERSION = "aegis-agent-state-transition-assessment-v1"
P8H_ASSESSMENT_MODE = "deterministic-evidence-bound-state-transition-security-v1"


class StateObjectType(StrEnum):
    TASK = "task"
    TOOL_RESOURCE = "tool_resource"
    RELEASE = "release"
    TELEMETRY = "telemetry"
    POLICY = "policy"
    MEMORY = "memory"


class TransitionIntent(StrEnum):
    READ = "read"
    RESERVE = "reserve"
    MUTATE = "mutate"
    COMMIT = "commit"
    CANCEL = "cancel"
    ROLLBACK = "rollback"


class ConcurrencyControl(StrEnum):
    NONE = "none"
    IDEMPOTENCY_KEY = "idempotency_key"
    EXPECTED_VERSION = "expected_version"
    LEASE = "lease"
    SERIALIZABLE = "serializable"


class TransitionDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class TransitionRisk(StrEnum):
    DUPLICATE_EXECUTION = "duplicate_execution"
    IDEMPOTENCY_REUSE_MISMATCH = "idempotency_reuse_mismatch"
    STALE_EXPECTED_VERSION = "stale_expected_version"
    EXPECTED_STATE_MISMATCH = "expected_state_mismatch"
    VERSION_NON_MONOTONIC = "version_non_monotonic"
    LOST_UPDATE = "lost_update"
    CONCURRENT_CONFLICT = "concurrent_conflict"
    LEASE_REQUIRED = "lease_required"
    LEASE_EXPIRED = "lease_expired"
    LEASE_OWNER_MISMATCH = "lease_owner_mismatch"
    LEASE_OBJECT_MISMATCH = "lease_object_mismatch"
    CANCEL_EXECUTE_RACE = "cancel_execute_race"
    APPROVAL_TO_USE_RACE = "approval_to_use_race"
    TOCTOU_STATE_CHANGE = "toctou_state_change"
    IRREVERSIBLE_REPLAY = "irreversible_replay"
    ROLLBACK_RACE = "rollback_race"
    DUPLICATE_SIDE_EFFECT = "duplicate_side_effect"
    TENANT_MISMATCH = "tenant_mismatch"
    PRINCIPAL_MISMATCH = "principal_mismatch"
    CONTROL_MISMATCH = "control_mismatch"
    INTENT_UNAUTHORIZED = "intent_unauthorized"
    UPSTREAM_MESSAGE_UNSAFE = "upstream_message_unsafe"
    UPSTREAM_APPROVAL_UNSAFE = "upstream_approval_unsafe"
    UPSTREAM_OBSERVATION_UNSAFE = "upstream_observation_unsafe"


class StateRejectReason(StrEnum):
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


class AgentStateSecurityRejected(ValueError):
    def __init__(self, reason: StateRejectReason, message: str, *, item_id: str | None = None):
        super().__init__(message)
        self.reason = reason
        self.item_id = item_id


@dataclass(frozen=True)
class StateObject:
    object_id: str
    object_type: StateObjectType
    tenant_id: str
    version: int
    state_sha256: str
    owner_id: str
    description: str


@dataclass(frozen=True)
class LeaseRecord:
    lease_id: str
    object_id: str
    owner_agent_id: str
    issued_at_epoch: int
    expires_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class StateTransition:
    transition_id: str
    object_id: str
    message_id: str
    approval_action_id: str | None
    observation_id: str | None
    actor_agent_id: str
    original_principal_id: str
    tenant_id: str
    intent: TransitionIntent
    concurrency_control: ConcurrencyControl
    expected_version: int
    expected_state_sha256: str
    proposed_version: int
    proposed_state_sha256: str
    idempotency_key: str | None
    lease_id: str | None
    approval_bound_version: int | None
    approval_bound_state_sha256: str | None
    payload_sha256: str
    irreversible: bool
    issued_at_epoch: int
    commit_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class AgentStateTransitionManifest:
    graph_id: str
    version: str
    p8d_assessment_evidence_sha256: str
    p8f_assessment_evidence_sha256: str
    p8g_assessment_evidence_sha256: str
    created_at_epoch: int
    objects: tuple[StateObject, ...]
    leases: tuple[LeaseRecord, ...]
    transitions: tuple[StateTransition, ...]
    schema_version: str = P8H_STATE_SCHEMA_VERSION


@dataclass(frozen=True)
class AgentStateTransitionPolicy:
    expected_graph_id: str
    expected_graph_version: str
    expected_graph_sha256: str
    expected_p8d_assessment_evidence_sha256: str
    expected_p8f_assessment_evidence_sha256: str
    expected_p8g_assessment_evidence_sha256: str
    required_object_ids: frozenset[str]
    required_lease_ids: frozenset[str]
    required_transition_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    expected_object_profiles: Mapping[str, tuple[object, ...]]
    allowed_intents_by_object: Mapping[str, frozenset[TransitionIntent]]
    allowed_controls_by_object: Mapping[str, frozenset[ConcurrencyControl]]
    approval_required_object_ids: frozenset[str]
    observation_required_object_ids: frozenset[str]
    lease_required_object_ids: frozenset[str]
    irreversible_object_ids: frozenset[str]
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class AgentStateTransitionRequest:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8d_assessment_evidence_sha256: str
    p8f_assessment_evidence_sha256: str
    p8g_assessment_evidence_sha256: str
    evaluated_at_epoch: int
    transition_ids: tuple[str, ...]
    declared_denied_transition_ids: tuple[str, ...]
    declared_risks_by_transition: Mapping[str, tuple[TransitionRisk, ...]]
    declared_final_versions: Mapping[str, int]


@dataclass(frozen=True)
class StateTransitionFact:
    transition_id: str
    object_id: str
    intent: TransitionIntent
    decision: TransitionDecision
    risks: tuple[TransitionRisk, ...]
    expected_version: int
    derived_pre_version: int
    proposed_version: int
    applied_version: int
    idempotency_key: str | None
    lease_id: str | None
    irreversible: bool
    risk_score: int


@dataclass(frozen=True)
class VerifiedAgentStateTransitionAssessment:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8d_assessment_evidence_sha256: str
    p8f_assessment_evidence_sha256: str
    p8g_assessment_evidence_sha256: str
    transition_count: int
    allowed_transition_count: int
    denied_transition_count: int
    duplicate_or_replay_denial_count: int
    stale_or_lost_update_denial_count: int
    lease_denial_count: int
    cancellation_or_rollback_race_denial_count: int
    approval_or_toctou_denial_count: int
    upstream_safety_denial_count: int
    maximum_risk_score: int
    final_versions: Mapping[str, int]
    final_state_sha256: Mapping[str, str]
    transitions: tuple[StateTransitionFact, ...]
    assessment_evidence_sha256: str
    exact_state_transition_graph_binding_verified: bool = True
    exact_p8d_tool_observation_binding_verified: bool = True
    exact_p8f_human_approval_binding_verified: bool = True
    exact_p8g_message_binding_verified: bool = True
    optimistic_version_checks_enforced: bool = True
    idempotency_semantics_checked: bool = True
    lease_ownership_and_expiry_checked: bool = True
    cancellation_and_rollback_races_checked: bool = True
    approval_to_use_toctou_checked: bool = True
    caller_declared_state_safety_trusted: bool = False
    production_transaction_enforcement: bool = False
    production_distributed_lock_enforcement: bool = False
    production_exactly_once_execution: bool = False
    formal_serializability_proof: bool = False
    exhaustive_race_coverage: bool = False
    network_operations: int = 0
    schema_version: str = P8H_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P8H_STATE_POLICY_VERSION
    assessment_mode: str = P8H_ASSESSMENT_MODE


def _reject(reason: StateRejectReason, message: str, item_id: str | None = None) -> None:
    raise AgentStateSecurityRejected(reason, message, item_id=item_id)


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


def canonical_agent_state_transition_manifest_bytes(manifest: AgentStateTransitionManifest) -> bytes:
    return json.dumps(_norm(manifest), sort_keys=True, separators=(",", ":")).encode()


def agent_state_transition_manifest_digest(manifest: AgentStateTransitionManifest) -> str:
    return hashlib.sha256(canonical_agent_state_transition_manifest_bytes(manifest)).hexdigest()


def _object_profile(obj: StateObject) -> tuple[object, ...]:
    return (obj.object_type, obj.tenant_id, obj.version, obj.state_sha256.casefold())


def _transition_semantic_fingerprint(t: StateTransition) -> tuple[object, ...]:
    return (
        t.object_id,
        t.message_id,
        t.approval_action_id,
        t.observation_id,
        t.actor_agent_id,
        t.original_principal_id,
        t.tenant_id,
        t.intent,
        t.expected_version,
        t.expected_state_sha256.casefold(),
        t.proposed_version,
        t.proposed_state_sha256.casefold(),
        t.payload_sha256.casefold(),
        t.irreversible,
    )


_RISK_SCORE = {
    TransitionRisk.DUPLICATE_EXECUTION: 104,
    TransitionRisk.IDEMPOTENCY_REUSE_MISMATCH: 116,
    TransitionRisk.STALE_EXPECTED_VERSION: 108,
    TransitionRisk.EXPECTED_STATE_MISMATCH: 109,
    TransitionRisk.VERSION_NON_MONOTONIC: 111,
    TransitionRisk.LOST_UPDATE: 115,
    TransitionRisk.CONCURRENT_CONFLICT: 112,
    TransitionRisk.LEASE_REQUIRED: 103,
    TransitionRisk.LEASE_EXPIRED: 110,
    TransitionRisk.LEASE_OWNER_MISMATCH: 113,
    TransitionRisk.LEASE_OBJECT_MISMATCH: 113,
    TransitionRisk.CANCEL_EXECUTE_RACE: 118,
    TransitionRisk.APPROVAL_TO_USE_RACE: 117,
    TransitionRisk.TOCTOU_STATE_CHANGE: 116,
    TransitionRisk.IRREVERSIBLE_REPLAY: 120,
    TransitionRisk.ROLLBACK_RACE: 119,
    TransitionRisk.DUPLICATE_SIDE_EFFECT: 120,
    TransitionRisk.TENANT_MISMATCH: 108,
    TransitionRisk.PRINCIPAL_MISMATCH: 108,
    TransitionRisk.CONTROL_MISMATCH: 101,
    TransitionRisk.INTENT_UNAUTHORIZED: 105,
    TransitionRisk.UPSTREAM_MESSAGE_UNSAFE: 110,
    TransitionRisk.UPSTREAM_APPROVAL_UNSAFE: 114,
    TransitionRisk.UPSTREAM_OBSERVATION_UNSAFE: 112,
}


def _assessment_digest(
    facts: tuple[StateTransitionFact, ...],
    manifest: AgentStateTransitionManifest,
    final_versions: Mapping[str, int],
    final_hashes: Mapping[str, str],
) -> str:
    doc = {
        "graph_sha256": agent_state_transition_manifest_digest(manifest),
        "final_versions": dict(sorted(final_versions.items())),
        "final_hashes": dict(sorted(final_hashes.items())),
        "transitions": [
            {
                "id": f.transition_id,
                "decision": f.decision.value,
                "risks": [r.value for r in f.risks],
                "pre": f.derived_pre_version,
                "applied": f.applied_version,
                "score": f.risk_score,
            }
            for f in facts
        ],
    }
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AgentStateMachineSecurityAnalyzer:
    def __init__(self, policy: AgentStateTransitionPolicy):
        self.policy = policy

    def _validate_policy(self) -> None:
        p = self.policy
        if not p.expected_graph_id or not p.expected_graph_version or not p.trusted_owner_ids:
            _reject(StateRejectReason.POLICY_INVALID, "missing graph or trust policy")
        if not all(
            _sha(x)
            for x in (
                p.expected_graph_sha256,
                p.expected_p8d_assessment_evidence_sha256,
                p.expected_p8f_assessment_evidence_sha256,
                p.expected_p8g_assessment_evidence_sha256,
            )
        ):
            _reject(StateRejectReason.POLICY_INVALID, "invalid digest pin")
        if p.max_manifest_age_seconds <= 0 or p.max_future_skew_seconds < 0:
            _reject(StateRejectReason.POLICY_INVALID, "invalid freshness policy")
        expected = set(p.required_object_ids)
        if set(p.expected_object_profiles) != expected:
            _reject(StateRejectReason.POLICY_INVALID, "object profile coverage mismatch")
        if set(p.allowed_intents_by_object) != expected or set(p.allowed_controls_by_object) != expected:
            _reject(StateRejectReason.POLICY_INVALID, "object policy map coverage mismatch")
        if not (
            p.approval_required_object_ids
            | p.observation_required_object_ids
            | p.lease_required_object_ids
            | p.irreversible_object_ids
        ).issubset(expected):
            _reject(StateRejectReason.POLICY_INVALID, "object policy references unknown object")

    def _validate_upstreams(self, manifest: AgentStateTransitionManifest, p8d: object, p8f: object, p8g: object) -> None:
        checks = (
            (
                p8d,
                self.policy.expected_p8d_assessment_evidence_sha256,
                manifest.p8d_assessment_evidence_sha256,
                "exact_tool_observation_graph_binding_verified",
                "caller_declared_tool_observation_safety_trusted",
            ),
            (
                p8f,
                self.policy.expected_p8f_assessment_evidence_sha256,
                manifest.p8f_assessment_evidence_sha256,
                "exact_human_approval_graph_binding_verified",
                "caller_declared_approval_safety_trusted",
            ),
            (
                p8g,
                self.policy.expected_p8g_assessment_evidence_sha256,
                manifest.p8g_assessment_evidence_sha256,
                "exact_agent_message_graph_binding_verified",
                "caller_declared_message_safety_trusted",
            ),
        )
        for obj, pin, manifest_pin, verified_flag, caller_flag in checks:
            if _digest(obj) != pin.casefold() or manifest_pin.casefold() != pin.casefold():
                _reject(StateRejectReason.UPSTREAM_INVALID, "upstream digest mismatch")
            if not bool(getattr(obj, verified_flag, False)) or bool(getattr(obj, caller_flag, True)):
                _reject(StateRejectReason.UPSTREAM_INVALID, "upstream verification boundary invalid")

    def _map(self, items: tuple[object, ...], attr: str) -> dict[str, object]:
        out: dict[str, object] = {}
        for item in items:
            key = str(getattr(item, attr))
            if key in out:
                _reject(StateRejectReason.COVERAGE_MISMATCH, "duplicate identifier", key)
            out[key] = item
        return out

    def _validate_manifest(self, manifest: AgentStateTransitionManifest, now: int):
        p = self.policy
        if (
            manifest.schema_version != P8H_STATE_SCHEMA_VERSION
            or manifest.graph_id != p.expected_graph_id
            or manifest.version != p.expected_graph_version
        ):
            _reject(StateRejectReason.MANIFEST_INVALID, "manifest identity invalid")
        if agent_state_transition_manifest_digest(manifest) != p.expected_graph_sha256.casefold():
            _reject(StateRejectReason.MANIFEST_INVALID, "manifest digest mismatch")
        if now - manifest.created_at_epoch > p.max_manifest_age_seconds or manifest.created_at_epoch - now > p.max_future_skew_seconds:
            _reject(StateRejectReason.MANIFEST_INVALID, "manifest freshness invalid")

        objects = self._map(manifest.objects, "object_id")
        leases = self._map(manifest.leases, "lease_id")
        transitions = self._map(manifest.transitions, "transition_id")
        if (
            set(objects) != set(p.required_object_ids)
            or set(leases) != set(p.required_lease_ids)
            or set(transitions) != set(p.required_transition_ids)
        ):
            _reject(StateRejectReason.COVERAGE_MISMATCH, "manifest coverage mismatch")

        for object_id, obj in objects.items():
            if obj.owner_id not in p.trusted_owner_ids:
                _reject(StateRejectReason.OWNER_UNTRUSTED, "object owner untrusted", object_id)
            if obj.version < 0 or not _sha(obj.state_sha256):
                _reject(StateRejectReason.REFERENCE_INVALID, "invalid object state", object_id)
            if _object_profile(obj) != p.expected_object_profiles.get(object_id):
                _reject(StateRejectReason.POLICY_DRIFT, "object profile drift", object_id)
            if not p.allowed_intents_by_object[object_id] or not p.allowed_controls_by_object[object_id]:
                _reject(StateRejectReason.POLICY_INVALID, "empty object policy", object_id)

        for lease_id, lease in leases.items():
            if lease.owner_id not in p.trusted_owner_ids:
                _reject(StateRejectReason.OWNER_UNTRUSTED, "lease owner untrusted", lease_id)
            if lease.object_id not in objects or not lease.owner_agent_id:
                _reject(StateRejectReason.REFERENCE_INVALID, "lease reference invalid", lease_id)
            if lease.expires_at_epoch < lease.issued_at_epoch:
                _reject(StateRejectReason.REFERENCE_INVALID, "lease time invalid", lease_id)

        for transition_id, t in transitions.items():
            if t.owner_id not in p.trusted_owner_ids:
                _reject(StateRejectReason.OWNER_UNTRUSTED, "transition owner untrusted", transition_id)
            if t.object_id not in objects or not t.message_id:
                _reject(StateRejectReason.REFERENCE_INVALID, "transition reference invalid", transition_id)
            if not all(_sha(v) for v in (t.expected_state_sha256, t.proposed_state_sha256, t.payload_sha256)):
                _reject(StateRejectReason.REFERENCE_INVALID, "transition digest invalid", transition_id)
            if t.idempotency_key is not None and not t.idempotency_key:
                _reject(StateRejectReason.REFERENCE_INVALID, "empty idempotency key", transition_id)
            if t.lease_id is not None and t.lease_id not in leases:
                _reject(StateRejectReason.REFERENCE_INVALID, "unknown lease", transition_id)
            if t.approval_bound_state_sha256 is not None and not _sha(t.approval_bound_state_sha256):
                _reject(StateRejectReason.REFERENCE_INVALID, "approval state digest invalid", transition_id)
            if (t.approval_bound_version is None) != (t.approval_bound_state_sha256 is None):
                _reject(StateRejectReason.REFERENCE_INVALID, "partial approval state binding", transition_id)
            if t.commit_at_epoch < t.issued_at_epoch:
                _reject(StateRejectReason.REFERENCE_INVALID, "transition time invalid", transition_id)
        return objects, leases, transitions

    def derive(
        self,
        manifest: AgentStateTransitionManifest,
        p8d: object,
        p8f: object,
        p8g: object,
        evaluated_at_epoch: int,
    ) -> tuple[tuple[StateTransitionFact, ...], dict[str, int], dict[str, str]]:
        self._validate_policy()
        self._validate_upstreams(manifest, p8d, p8f, p8g)
        objects, leases, transitions = self._validate_manifest(manifest, evaluated_at_epoch)

        observations = {str(getattr(x, "observation_id", "")): x for x in getattr(p8d, "observations", ())}
        approvals = {str(getattr(x, "action_id", "")): x for x in getattr(p8f, "actions", ())}
        messages = {str(getattr(x, "message_id", "")): x for x in getattr(p8g, "messages", ())}

        current_versions = {oid: obj.version for oid, obj in objects.items()}
        current_hashes = {oid: obj.state_sha256.casefold() for oid, obj in objects.items()}
        cancelled_objects: set[str] = set()
        idem_seen: dict[str, tuple[object, ...]] = {}
        idem_transition: dict[str, str] = {}
        observation_use_count: dict[str, int] = {}
        expected_version_writers: dict[tuple[str, int], list[str]] = {}
        rollback_versions: set[tuple[str, int]] = set()

        ordered = sorted(
            transitions.values(),
            key=lambda t: (t.commit_at_epoch, t.issued_at_epoch, t.transition_id),
        )
        for t in ordered:
            if t.intent != TransitionIntent.READ:
                expected_version_writers.setdefault((t.object_id, t.expected_version), []).append(t.transition_id)
                if t.intent == TransitionIntent.ROLLBACK:
                    rollback_versions.add((t.object_id, t.expected_version))
            if t.observation_id is not None:
                observation_use_count[t.observation_id] = observation_use_count.get(t.observation_id, 0) + 1

        facts: list[StateTransitionFact] = []
        for t in ordered:
            risks: set[TransitionRisk] = set()
            pre_version = current_versions[t.object_id]
            pre_hash = current_hashes[t.object_id]
            object_policy = objects[t.object_id]

            if t.tenant_id != object_policy.tenant_id:
                risks.add(TransitionRisk.TENANT_MISMATCH)
            if t.intent not in self.policy.allowed_intents_by_object[t.object_id]:
                risks.add(TransitionRisk.INTENT_UNAUTHORIZED)
            if t.concurrency_control not in self.policy.allowed_controls_by_object[t.object_id]:
                risks.add(TransitionRisk.CONTROL_MISMATCH)

            message = messages.get(t.message_id)
            if message is None or not _safe(message):
                risks.add(TransitionRisk.UPSTREAM_MESSAGE_UNSAFE)
            else:
                if str(getattr(message, "tenant_id", t.tenant_id)) != t.tenant_id:
                    risks.add(TransitionRisk.TENANT_MISMATCH)
                if str(getattr(message, "sender_agent_id", t.actor_agent_id)) != t.actor_agent_id:
                    risks.add(TransitionRisk.PRINCIPAL_MISMATCH)

            if t.object_id in self.policy.approval_required_object_ids:
                approval = approvals.get(t.approval_action_id or "")
                if approval is None or not _safe(approval):
                    risks.add(TransitionRisk.UPSTREAM_APPROVAL_UNSAFE)
                if t.approval_bound_version is None or t.approval_bound_state_sha256 is None:
                    risks.add(TransitionRisk.APPROVAL_TO_USE_RACE)
                elif t.approval_bound_version != pre_version or t.approval_bound_state_sha256.casefold() != pre_hash:
                    risks.add(TransitionRisk.APPROVAL_TO_USE_RACE)
            elif t.approval_action_id is not None:
                approval = approvals.get(t.approval_action_id)
                if approval is None or not _safe(approval):
                    risks.add(TransitionRisk.UPSTREAM_APPROVAL_UNSAFE)

            if t.object_id in self.policy.observation_required_object_ids:
                observation = observations.get(t.observation_id or "")
                if observation is None or not _safe(observation):
                    risks.add(TransitionRisk.UPSTREAM_OBSERVATION_UNSAFE)
            elif t.observation_id is not None:
                observation = observations.get(t.observation_id)
                if observation is None or not _safe(observation):
                    risks.add(TransitionRisk.UPSTREAM_OBSERVATION_UNSAFE)

            if t.observation_id is not None and observation_use_count.get(t.observation_id, 0) > 1:
                risks.add(TransitionRisk.DUPLICATE_SIDE_EFFECT)

            if t.object_id in self.policy.lease_required_object_ids:
                if t.lease_id is None:
                    risks.add(TransitionRisk.LEASE_REQUIRED)
                else:
                    lease = leases[t.lease_id]
                    if lease.object_id != t.object_id:
                        risks.add(TransitionRisk.LEASE_OBJECT_MISMATCH)
                    if lease.owner_agent_id != t.actor_agent_id:
                        risks.add(TransitionRisk.LEASE_OWNER_MISMATCH)
                    if t.commit_at_epoch > lease.expires_at_epoch or t.commit_at_epoch < lease.issued_at_epoch:
                        risks.add(TransitionRisk.LEASE_EXPIRED)

            if t.idempotency_key is not None:
                fingerprint = _transition_semantic_fingerprint(t)
                if t.idempotency_key in idem_seen:
                    if idem_seen[t.idempotency_key] == fingerprint:
                        risks.add(TransitionRisk.DUPLICATE_EXECUTION)
                        if t.irreversible or t.object_id in self.policy.irreversible_object_ids:
                            risks.add(TransitionRisk.IRREVERSIBLE_REPLAY)
                    else:
                        risks.add(TransitionRisk.IDEMPOTENCY_REUSE_MISMATCH)
                else:
                    idem_seen[t.idempotency_key] = fingerprint
                    idem_transition[t.idempotency_key] = t.transition_id
            elif t.concurrency_control == ConcurrencyControl.IDEMPOTENCY_KEY:
                risks.add(TransitionRisk.CONTROL_MISMATCH)

            if t.intent != TransitionIntent.READ:
                if t.expected_version != pre_version:
                    risks.add(TransitionRisk.STALE_EXPECTED_VERSION)
                    if t.expected_version < pre_version:
                        risks.add(TransitionRisk.LOST_UPDATE)
                if t.expected_state_sha256.casefold() != pre_hash:
                    risks.add(TransitionRisk.EXPECTED_STATE_MISMATCH)
                    risks.add(TransitionRisk.TOCTOU_STATE_CHANGE)
                if t.proposed_version != t.expected_version + 1:
                    risks.add(TransitionRisk.VERSION_NON_MONOTONIC)

                writers = expected_version_writers.get((t.object_id, t.expected_version), [])
                if len(writers) > 1:
                    risks.add(TransitionRisk.CONCURRENT_CONFLICT)
                    risks.add(TransitionRisk.LOST_UPDATE)
                    if (t.object_id, t.expected_version) in rollback_versions:
                        risks.add(TransitionRisk.ROLLBACK_RACE)

                if t.object_id in cancelled_objects and t.intent not in {TransitionIntent.ROLLBACK, TransitionIntent.READ}:
                    risks.add(TransitionRisk.CANCEL_EXECUTE_RACE)

                if t.irreversible and t.intent not in {TransitionIntent.COMMIT, TransitionIntent.MUTATE}:
                    risks.add(TransitionRisk.INTENT_UNAUTHORIZED)
                if (t.irreversible or t.object_id in self.policy.irreversible_object_ids) and t.idempotency_key is None:
                    risks.add(TransitionRisk.CONTROL_MISMATCH)
            else:
                if t.proposed_version != t.expected_version or t.proposed_state_sha256.casefold() != t.expected_state_sha256.casefold():
                    risks.add(TransitionRisk.VERSION_NON_MONOTONIC)

            decision = TransitionDecision.DENY if risks else TransitionDecision.ALLOW
            if decision == TransitionDecision.ALLOW and t.intent != TransitionIntent.READ:
                current_versions[t.object_id] = t.proposed_version
                current_hashes[t.object_id] = t.proposed_state_sha256.casefold()
                if t.intent == TransitionIntent.CANCEL:
                    cancelled_objects.add(t.object_id)
                elif t.intent == TransitionIntent.ROLLBACK:
                    cancelled_objects.discard(t.object_id)

            facts.append(
                StateTransitionFact(
                    transition_id=t.transition_id,
                    object_id=t.object_id,
                    intent=t.intent,
                    decision=decision,
                    risks=tuple(sorted(risks, key=lambda r: r.value)),
                    expected_version=t.expected_version,
                    derived_pre_version=pre_version,
                    proposed_version=t.proposed_version,
                    applied_version=current_versions[t.object_id],
                    idempotency_key=t.idempotency_key,
                    lease_id=t.lease_id,
                    irreversible=t.irreversible,
                    risk_score=max((_RISK_SCORE[r] for r in risks), default=0),
                )
            )
        return tuple(facts), current_versions, current_hashes

    def evaluate(
        self,
        request: AgentStateTransitionRequest,
        manifest: AgentStateTransitionManifest,
        p8d: object,
        p8f: object,
        p8g: object,
    ) -> VerifiedAgentStateTransitionAssessment:
        self._validate_policy()
        p = self.policy
        if (
            request.graph_id != p.expected_graph_id
            or request.graph_version != p.expected_graph_version
            or request.graph_sha256.casefold() != p.expected_graph_sha256.casefold()
            or request.p8d_assessment_evidence_sha256.casefold() != p.expected_p8d_assessment_evidence_sha256.casefold()
            or request.p8f_assessment_evidence_sha256.casefold() != p.expected_p8f_assessment_evidence_sha256.casefold()
            or request.p8g_assessment_evidence_sha256.casefold() != p.expected_p8g_assessment_evidence_sha256.casefold()
        ):
            _reject(StateRejectReason.REQUEST_INVALID, "request binding invalid")
        if len(request.transition_ids) != len(set(request.transition_ids)) or set(request.transition_ids) != set(p.required_transition_ids):
            _reject(StateRejectReason.COVERAGE_MISMATCH, "request transition coverage mismatch")

        facts, final_versions, final_hashes = self.derive(
            manifest, p8d, p8f, p8g, request.evaluated_at_epoch
        )
        denied = tuple(sorted(f.transition_id for f in facts if f.decision == TransitionDecision.DENY))
        if tuple(sorted(request.declared_denied_transition_ids)) != denied:
            _reject(StateRejectReason.DECLARED_DECISION_MISMATCH, "caller denial summary mismatch")
        if set(request.declared_risks_by_transition) != set(p.required_transition_ids):
            _reject(StateRejectReason.DECLARED_RISK_MISMATCH, "caller risk-map coverage mismatch")
        by_id = {f.transition_id: f for f in facts}
        for transition_id, declared in request.declared_risks_by_transition.items():
            if tuple(declared) != by_id[transition_id].risks:
                _reject(StateRejectReason.DECLARED_RISK_MISMATCH, "caller risk summary mismatch", transition_id)
        if dict(request.declared_final_versions) != final_versions:
            _reject(StateRejectReason.DECLARED_DECISION_MISMATCH, "caller final-version summary mismatch")

        replay_set = {
            TransitionRisk.DUPLICATE_EXECUTION,
            TransitionRisk.IDEMPOTENCY_REUSE_MISMATCH,
            TransitionRisk.IRREVERSIBLE_REPLAY,
            TransitionRisk.DUPLICATE_SIDE_EFFECT,
        }
        stale_set = {
            TransitionRisk.STALE_EXPECTED_VERSION,
            TransitionRisk.EXPECTED_STATE_MISMATCH,
            TransitionRisk.LOST_UPDATE,
            TransitionRisk.CONCURRENT_CONFLICT,
            TransitionRisk.VERSION_NON_MONOTONIC,
        }
        lease_set = {
            TransitionRisk.LEASE_REQUIRED,
            TransitionRisk.LEASE_EXPIRED,
            TransitionRisk.LEASE_OWNER_MISMATCH,
            TransitionRisk.LEASE_OBJECT_MISMATCH,
        }
        cancel_set = {
            TransitionRisk.CANCEL_EXECUTE_RACE,
            TransitionRisk.ROLLBACK_RACE,
        }
        toctou_set = {
            TransitionRisk.APPROVAL_TO_USE_RACE,
            TransitionRisk.TOCTOU_STATE_CHANGE,
        }
        upstream_set = {
            TransitionRisk.UPSTREAM_MESSAGE_UNSAFE,
            TransitionRisk.UPSTREAM_APPROVAL_UNSAFE,
            TransitionRisk.UPSTREAM_OBSERVATION_UNSAFE,
        }
        return VerifiedAgentStateTransitionAssessment(
            graph_id=manifest.graph_id,
            graph_version=manifest.version,
            graph_sha256=agent_state_transition_manifest_digest(manifest),
            p8d_assessment_evidence_sha256=p.expected_p8d_assessment_evidence_sha256,
            p8f_assessment_evidence_sha256=p.expected_p8f_assessment_evidence_sha256,
            p8g_assessment_evidence_sha256=p.expected_p8g_assessment_evidence_sha256,
            transition_count=len(facts),
            allowed_transition_count=len(facts) - len(denied),
            denied_transition_count=len(denied),
            duplicate_or_replay_denial_count=sum(bool(replay_set.intersection(f.risks)) for f in facts),
            stale_or_lost_update_denial_count=sum(bool(stale_set.intersection(f.risks)) for f in facts),
            lease_denial_count=sum(bool(lease_set.intersection(f.risks)) for f in facts),
            cancellation_or_rollback_race_denial_count=sum(bool(cancel_set.intersection(f.risks)) for f in facts),
            approval_or_toctou_denial_count=sum(bool(toctou_set.intersection(f.risks)) for f in facts),
            upstream_safety_denial_count=sum(bool(upstream_set.intersection(f.risks)) for f in facts),
            maximum_risk_score=max((f.risk_score for f in facts), default=0),
            final_versions=dict(final_versions),
            final_state_sha256=dict(final_hashes),
            transitions=facts,
            assessment_evidence_sha256=_assessment_digest(facts, manifest, final_versions, final_hashes),
        )
