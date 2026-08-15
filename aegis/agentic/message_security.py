from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, is_dataclass
from enum import StrEnum
from typing import Mapping

P8G_MESSAGE_POLICY_VERSION = "agent-communications-message-protocol-security-v1"
P8G_MESSAGE_SCHEMA_VERSION = "aegis-agent-message-manifest-v1"
P8G_ASSESSMENT_SCHEMA_VERSION = "aegis-agent-message-assessment-v1"
P8G_ASSESSMENT_MODE = "deterministic-evidence-bound-agent-message-security-v1"


class MessageChannelType(StrEnum):
    DIRECT = "direct"
    BUS = "bus"
    BROKERED = "brokered"
    BROADCAST = "broadcast"
    EXTERNAL = "external"


class MessageIntent(StrEnum):
    INFORMATION = "information"
    REQUEST = "request"
    COMMAND = "command"
    RESULT = "result"
    APPROVAL_NOTICE = "approval_notice"


class MessageTrust(StrEnum):
    UNTRUSTED = "untrusted"
    AUTHENTICATED = "authenticated"
    VERIFIED = "verified"


class MessageDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class MessageRisk(StrEnum):
    SENDER_IDENTITY_MISMATCH = "sender_identity_mismatch"
    RECEIVER_UNAUTHORIZED = "receiver_unauthorized"
    SENDER_UNAUTHORIZED = "sender_unauthorized"
    CHANNEL_UNAUTHORIZED = "channel_unauthorized"
    TENANT_MISMATCH = "tenant_mismatch"
    PRINCIPAL_MISMATCH = "principal_mismatch"
    TASK_MISMATCH = "task_mismatch"
    GOAL_MISMATCH = "goal_mismatch"
    STEP_MISMATCH = "step_mismatch"
    DELEGATION_MISMATCH = "delegation_mismatch"
    MESSAGE_REPLAY = "message_replay"
    MESSAGE_STALE = "message_stale"
    MESSAGE_FUTURE = "message_future"
    MESSAGE_TIME_INVALID = "message_time_invalid"
    SCHEMA_MISMATCH = "schema_mismatch"
    PROTOCOL_DOWNGRADE = "protocol_downgrade"
    INTENT_UNAUTHORIZED = "intent_unauthorized"
    CAPABILITY_NEGOTIATION_MISMATCH = "capability_negotiation_mismatch"
    CAPABILITY_ESCALATION = "capability_escalation"
    PARENT_CHAIN_BROKEN = "parent_chain_broken"
    PROVENANCE_DISCONTINUITY = "provenance_discontinuity"
    COMMAND_LAUNDERING = "command_laundering"
    EXTERNAL_COMMAND_ESCALATION = "external_command_escalation"
    REQUIRED_APPROVAL_MISSING = "required_approval_missing"
    UPSTREAM_DELEGATION_UNSAFE = "upstream_delegation_unsafe"
    UPSTREAM_PLAN_UNSAFE = "upstream_plan_unsafe"
    UPSTREAM_APPROVAL_UNSAFE = "upstream_approval_unsafe"


class MessageRejectReason(StrEnum):
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


class AgentMessageSecurityRejected(ValueError):
    def __init__(self, reason: MessageRejectReason, message: str, *, item_id: str | None = None):
        super().__init__(message)
        self.reason = reason
        self.item_id = item_id


@dataclass(frozen=True)
class MessageChannelPolicy:
    channel_id: str
    channel_type: MessageChannelType
    owner_id: str
    allowed_sender_ids: tuple[str, ...]
    allowed_receiver_ids: tuple[str, ...]
    allowed_intents: tuple[MessageIntent, ...]
    tenant_scope: str
    required_schema_version: str
    protocol_version: int
    allowed_capability_ids: tuple[str, ...]
    command_requires_approval: bool
    required_approval_action_id: str | None
    max_message_age_seconds: int
    description: str


@dataclass(frozen=True)
class AgentMessage:
    message_id: str
    channel_id: str
    sender_agent_id: str
    receiver_agent_id: str
    sender_identity_sha256: str
    original_principal_id: str
    tenant_id: str
    task_id: str
    goal_id: str
    step_id: str
    delegation_id: str | None
    approval_action_id: str | None
    intent: MessageIntent
    schema_version: str
    protocol_version: int
    capability_ids: tuple[str, ...]
    payload_sha256: str
    parent_message_id: str | None
    nonce: str
    issued_at_epoch: int
    expires_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class AgentMessageManifest:
    graph_id: str
    version: str
    p8a_assessment_evidence_sha256: str
    p8c_assessment_evidence_sha256: str
    p8f_assessment_evidence_sha256: str
    created_at_epoch: int
    channels: tuple[MessageChannelPolicy, ...]
    messages: tuple[AgentMessage, ...]
    schema_version: str = P8G_MESSAGE_SCHEMA_VERSION


@dataclass(frozen=True)
class AgentMessagePolicy:
    expected_graph_id: str
    expected_graph_version: str
    expected_graph_sha256: str
    expected_p8a_assessment_evidence_sha256: str
    expected_p8c_assessment_evidence_sha256: str
    expected_p8f_assessment_evidence_sha256: str
    required_channel_ids: frozenset[str]
    required_message_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    trusted_internal_agent_ids: frozenset[str]
    known_external_sender_ids: frozenset[str]
    expected_sender_identity_sha256: Mapping[str, str]
    expected_channel_profiles: Mapping[str, tuple[object, ...]]
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class AgentMessageRequest:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8a_assessment_evidence_sha256: str
    p8c_assessment_evidence_sha256: str
    p8f_assessment_evidence_sha256: str
    evaluated_at_epoch: int
    message_ids: tuple[str, ...]
    declared_denied_message_ids: tuple[str, ...]
    declared_risks_by_message: Mapping[str, tuple[MessageRisk, ...]]


@dataclass(frozen=True)
class AgentMessageFact:
    message_id: str
    channel_id: str
    sender_agent_id: str
    receiver_agent_id: str
    intent: MessageIntent
    decision: MessageDecision
    risks: tuple[MessageRisk, ...]
    derived_trust: MessageTrust
    parent_message_id: str | None
    tenant_id: str
    goal_id: str
    delegation_id: str | None
    capability_ids: tuple[str, ...]
    risk_score: int


@dataclass(frozen=True)
class VerifiedAgentMessageAssessment:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8a_assessment_evidence_sha256: str
    p8c_assessment_evidence_sha256: str
    p8f_assessment_evidence_sha256: str
    message_count: int
    allowed_message_count: int
    denied_message_count: int
    replay_or_freshness_denial_count: int
    identity_or_channel_denial_count: int
    provenance_denial_count: int
    capability_denial_count: int
    command_laundering_denial_count: int
    upstream_safety_denial_count: int
    maximum_risk_score: int
    messages: tuple[AgentMessageFact, ...]
    assessment_evidence_sha256: str
    exact_agent_message_graph_binding_verified: bool = True
    exact_p8a_delegation_binding_verified: bool = True
    exact_p8c_goal_plan_binding_verified: bool = True
    exact_p8f_human_approval_binding_verified: bool = True
    sender_receiver_channel_authorization_verified: bool = True
    message_freshness_and_replay_checked: bool = True
    schema_and_protocol_version_checked: bool = True
    capability_negotiation_non_amplification_verified: bool = True
    chained_message_provenance_verified: bool = True
    external_command_laundering_detection_enabled: bool = True
    caller_declared_message_safety_trusted: bool = False
    production_message_broker_enforcement: bool = False
    production_workload_identity_attestation: bool = False
    cryptographic_message_signature_verification: bool = False
    production_mtls_enforcement: bool = False
    exhaustive_protocol_semantics_proof: bool = False
    network_operations: int = 0
    schema_version: str = P8G_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P8G_MESSAGE_POLICY_VERSION
    assessment_mode: str = P8G_ASSESSMENT_MODE


def _reject(reason: MessageRejectReason, message: str, item_id: str | None = None) -> None:
    raise AgentMessageSecurityRejected(reason, message, item_id=item_id)


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


def canonical_agent_message_manifest_bytes(manifest: AgentMessageManifest) -> bytes:
    return json.dumps(_norm(manifest), sort_keys=True, separators=(",", ":")).encode()


def agent_message_manifest_digest(manifest: AgentMessageManifest) -> str:
    return hashlib.sha256(canonical_agent_message_manifest_bytes(manifest)).hexdigest()


def _channel_profile(channel: MessageChannelPolicy) -> tuple[object, ...]:
    return (
        channel.channel_type,
        tuple(channel.allowed_sender_ids),
        tuple(channel.allowed_receiver_ids),
        tuple(channel.allowed_intents),
        channel.tenant_scope,
        channel.required_schema_version,
        channel.protocol_version,
        tuple(channel.allowed_capability_ids),
        channel.command_requires_approval,
        channel.required_approval_action_id,
        channel.max_message_age_seconds,
    )


_RISK_SCORE = {
    MessageRisk.SENDER_IDENTITY_MISMATCH: 110,
    MessageRisk.RECEIVER_UNAUTHORIZED: 102,
    MessageRisk.SENDER_UNAUTHORIZED: 104,
    MessageRisk.CHANNEL_UNAUTHORIZED: 100,
    MessageRisk.TENANT_MISMATCH: 105,
    MessageRisk.PRINCIPAL_MISMATCH: 106,
    MessageRisk.TASK_MISMATCH: 96,
    MessageRisk.GOAL_MISMATCH: 100,
    MessageRisk.STEP_MISMATCH: 98,
    MessageRisk.DELEGATION_MISMATCH: 107,
    MessageRisk.MESSAGE_REPLAY: 112,
    MessageRisk.MESSAGE_STALE: 90,
    MessageRisk.MESSAGE_FUTURE: 92,
    MessageRisk.MESSAGE_TIME_INVALID: 94,
    MessageRisk.SCHEMA_MISMATCH: 97,
    MessageRisk.PROTOCOL_DOWNGRADE: 109,
    MessageRisk.INTENT_UNAUTHORIZED: 103,
    MessageRisk.CAPABILITY_NEGOTIATION_MISMATCH: 104,
    MessageRisk.CAPABILITY_ESCALATION: 114,
    MessageRisk.PARENT_CHAIN_BROKEN: 106,
    MessageRisk.PROVENANCE_DISCONTINUITY: 111,
    MessageRisk.COMMAND_LAUNDERING: 116,
    MessageRisk.EXTERNAL_COMMAND_ESCALATION: 118,
    MessageRisk.REQUIRED_APPROVAL_MISSING: 110,
    MessageRisk.UPSTREAM_DELEGATION_UNSAFE: 108,
    MessageRisk.UPSTREAM_PLAN_UNSAFE: 108,
    MessageRisk.UPSTREAM_APPROVAL_UNSAFE: 113,
}


def _assessment_digest(facts: tuple[AgentMessageFact, ...], manifest: AgentMessageManifest) -> str:
    doc = {
        "graph_sha256": agent_message_manifest_digest(manifest),
        "messages": [
            {
                "id": f.message_id,
                "decision": f.decision.value,
                "risks": [r.value for r in f.risks],
                "trust": f.derived_trust.value,
                "caps": list(f.capability_ids),
                "score": f.risk_score,
            }
            for f in facts
        ],
    }
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AgentMessageProtocolSecurityAnalyzer:
    def __init__(self, policy: AgentMessagePolicy):
        self.policy = policy

    def _validate_policy(self) -> None:
        p = self.policy
        if not p.expected_graph_id or not p.expected_graph_version or not p.trusted_owner_ids:
            _reject(MessageRejectReason.POLICY_INVALID, "missing graph or owner policy")
        if not all(_sha(x) for x in (
            p.expected_graph_sha256,
            p.expected_p8a_assessment_evidence_sha256,
            p.expected_p8c_assessment_evidence_sha256,
            p.expected_p8f_assessment_evidence_sha256,
        )):
            _reject(MessageRejectReason.POLICY_INVALID, "invalid digest pin")
        if p.max_manifest_age_seconds <= 0 or p.max_future_skew_seconds < 0:
            _reject(MessageRejectReason.POLICY_INVALID, "invalid freshness policy")
        all_senders = p.trusted_internal_agent_ids | p.known_external_sender_ids
        if not all_senders or set(p.expected_sender_identity_sha256) != set(all_senders):
            _reject(MessageRejectReason.POLICY_INVALID, "sender identity policy coverage mismatch")
        if not all(_sha(v) for v in p.expected_sender_identity_sha256.values()):
            _reject(MessageRejectReason.POLICY_INVALID, "invalid sender identity digest")

    def _validate_upstreams(self, manifest: AgentMessageManifest, p8a: object, p8c: object, p8f: object) -> None:
        checks = (
            (p8a, self.policy.expected_p8a_assessment_evidence_sha256, manifest.p8a_assessment_evidence_sha256, "exact_delegation_graph_binding_verified", "caller_declared_delegation_authorization_trusted"),
            (p8c, self.policy.expected_p8c_assessment_evidence_sha256, manifest.p8c_assessment_evidence_sha256, "exact_goal_plan_graph_binding_verified", "caller_declared_goal_safety_trusted"),
            (p8f, self.policy.expected_p8f_assessment_evidence_sha256, manifest.p8f_assessment_evidence_sha256, "exact_human_approval_graph_binding_verified", "caller_declared_approval_safety_trusted"),
        )
        for obj, pin, manifest_pin, verified_flag, caller_flag in checks:
            if _digest(obj) != pin.casefold() or manifest_pin.casefold() != pin.casefold():
                _reject(MessageRejectReason.UPSTREAM_INVALID, "upstream digest mismatch")
            if not bool(getattr(obj, verified_flag, False)) or bool(getattr(obj, caller_flag, True)):
                _reject(MessageRejectReason.UPSTREAM_INVALID, "upstream verification boundary invalid")

    def _map(self, items: tuple[object, ...], attr: str) -> dict[str, object]:
        out: dict[str, object] = {}
        for item in items:
            key = str(getattr(item, attr))
            if key in out:
                _reject(MessageRejectReason.COVERAGE_MISMATCH, "duplicate identifier", key)
            out[key] = item
        return out

    def _validate_manifest(self, manifest: AgentMessageManifest, now: int):
        p = self.policy
        if manifest.schema_version != P8G_MESSAGE_SCHEMA_VERSION or manifest.graph_id != p.expected_graph_id or manifest.version != p.expected_graph_version:
            _reject(MessageRejectReason.MANIFEST_INVALID, "manifest identity invalid")
        if agent_message_manifest_digest(manifest) != p.expected_graph_sha256.casefold():
            _reject(MessageRejectReason.MANIFEST_INVALID, "manifest digest mismatch")
        if now - manifest.created_at_epoch > p.max_manifest_age_seconds or manifest.created_at_epoch - now > p.max_future_skew_seconds:
            _reject(MessageRejectReason.MANIFEST_INVALID, "manifest freshness invalid")
        channels = self._map(manifest.channels, "channel_id")
        messages = self._map(manifest.messages, "message_id")
        if set(channels) != set(p.required_channel_ids) or set(messages) != set(p.required_message_ids):
            _reject(MessageRejectReason.COVERAGE_MISMATCH, "manifest coverage mismatch")
        for channel_id, channel in channels.items():
            if channel.owner_id not in p.trusted_owner_ids:
                _reject(MessageRejectReason.OWNER_UNTRUSTED, "channel owner untrusted", channel_id)
            if _channel_profile(channel) != p.expected_channel_profiles.get(channel_id):
                _reject(MessageRejectReason.POLICY_DRIFT, "channel policy drift", channel_id)
            if not channel.allowed_sender_ids or not channel.allowed_receiver_ids or not channel.allowed_intents or channel.protocol_version <= 0 or channel.max_message_age_seconds <= 0:
                _reject(MessageRejectReason.POLICY_INVALID, "invalid channel", channel_id)
            if channel.command_requires_approval and not channel.required_approval_action_id:
                _reject(MessageRejectReason.POLICY_INVALID, "approval-bound channel missing required approval action", channel_id)
            if not channel.command_requires_approval and channel.required_approval_action_id is not None:
                _reject(MessageRejectReason.POLICY_INVALID, "non-approval channel pins approval action", channel_id)
        for message_id, message in messages.items():
            if message.owner_id not in p.trusted_owner_ids:
                _reject(MessageRejectReason.OWNER_UNTRUSTED, "message owner untrusted", message_id)
            if message.channel_id not in channels:
                _reject(MessageRejectReason.REFERENCE_INVALID, "unknown channel", message_id)
            if not _sha(message.sender_identity_sha256) or not _sha(message.payload_sha256) or not message.nonce:
                _reject(MessageRejectReason.REFERENCE_INVALID, "invalid message evidence", message_id)
            if message.parent_message_id is not None and message.parent_message_id not in messages:
                _reject(MessageRejectReason.REFERENCE_INVALID, "unknown parent", message_id)
            if len(message.capability_ids) != len(set(message.capability_ids)):
                _reject(MessageRejectReason.REFERENCE_INVALID, "duplicate negotiated capability", message_id)
        for message_id in messages:
            seen: set[str] = set()
            cursor = message_id
            while cursor is not None:
                if cursor in seen:
                    _reject(MessageRejectReason.REFERENCE_INVALID, "message parent cycle", message_id)
                seen.add(cursor)
                cursor = messages[cursor].parent_message_id if cursor in messages else None
        return channels, messages

    def derive(self, manifest: AgentMessageManifest, p8a: object, p8c: object, p8f: object, evaluated_at_epoch: int) -> tuple[AgentMessageFact, ...]:
        self._validate_policy()
        self._validate_upstreams(manifest, p8a, p8c, p8f)
        channels, messages = self._validate_manifest(manifest, evaluated_at_epoch)
        delegations = {str(getattr(x, "delegation_id", "")): x for x in getattr(p8a, "delegations", ())}
        steps = {str(getattr(x, "step_id", "")): x for x in getattr(p8c, "steps", ())}
        approvals = {str(getattr(x, "action_id", "")): x for x in getattr(p8f, "actions", ())}
        nonce_count: dict[str, int] = {}
        for message in messages.values():
            nonce_count[message.nonce] = nonce_count.get(message.nonce, 0) + 1

        facts: list[AgentMessageFact] = []
        for message_id in sorted(messages):
            message: AgentMessage = messages[message_id]
            channel: MessageChannelPolicy = channels[message.channel_id]
            risks: set[MessageRisk] = set()

            expected_identity = self.policy.expected_sender_identity_sha256.get(message.sender_agent_id)
            if expected_identity is None or message.sender_identity_sha256.casefold() != expected_identity.casefold():
                risks.add(MessageRisk.SENDER_IDENTITY_MISMATCH)
            if message.sender_agent_id not in channel.allowed_sender_ids:
                risks.add(MessageRisk.SENDER_UNAUTHORIZED)
            if message.receiver_agent_id not in channel.allowed_receiver_ids:
                risks.add(MessageRisk.RECEIVER_UNAUTHORIZED)
            if message.intent not in channel.allowed_intents:
                risks.add(MessageRisk.INTENT_UNAUTHORIZED)
            if message.schema_version != channel.required_schema_version:
                risks.add(MessageRisk.SCHEMA_MISMATCH)
            if message.protocol_version < channel.protocol_version:
                risks.add(MessageRisk.PROTOCOL_DOWNGRADE)
            elif message.protocol_version != channel.protocol_version:
                risks.add(MessageRisk.SCHEMA_MISMATCH)
            if not set(message.capability_ids).issubset(set(channel.allowed_capability_ids)):
                risks.add(MessageRisk.CAPABILITY_NEGOTIATION_MISMATCH)
            if channel.tenant_scope not in {"shared", "system", "external"} and message.tenant_id != channel.tenant_scope:
                risks.add(MessageRisk.TENANT_MISMATCH)
            if channel.channel_type == MessageChannelType.EXTERNAL and message.intent == MessageIntent.COMMAND:
                risks.add(MessageRisk.EXTERNAL_COMMAND_ESCALATION)

            if message.issued_at_epoch > evaluated_at_epoch + self.policy.max_future_skew_seconds:
                risks.add(MessageRisk.MESSAGE_FUTURE)
            if message.expires_at_epoch < message.issued_at_epoch:
                risks.add(MessageRisk.MESSAGE_TIME_INVALID)
            if message.expires_at_epoch < evaluated_at_epoch or evaluated_at_epoch - message.issued_at_epoch > channel.max_message_age_seconds:
                risks.add(MessageRisk.MESSAGE_STALE)
            if nonce_count[message.nonce] > 1:
                risks.add(MessageRisk.MESSAGE_REPLAY)

            step = steps.get(message.step_id)
            if step is None or not _safe(step):
                risks.add(MessageRisk.UPSTREAM_PLAN_UNSAFE)
            else:
                step_goal = str(getattr(step, "goal_id", message.goal_id))
                if step_goal != message.goal_id:
                    risks.add(MessageRisk.GOAL_MISMATCH)

            if message.delegation_id is not None:
                delegation = delegations.get(message.delegation_id)
                if delegation is None or not _safe(delegation):
                    risks.add(MessageRisk.UPSTREAM_DELEGATION_UNSAFE)
                else:
                    if str(getattr(delegation, "original_principal_id", message.original_principal_id)) != message.original_principal_id:
                        risks.add(MessageRisk.PRINCIPAL_MISMATCH)
                    if str(getattr(delegation, "tenant_id", message.tenant_id)) != message.tenant_id:
                        risks.add(MessageRisk.TENANT_MISMATCH)
                    delegation_caps = set(getattr(delegation, "requested_capability_ids", ()))
                    if not set(message.capability_ids).issubset(delegation_caps):
                        risks.add(MessageRisk.CAPABILITY_ESCALATION)
            elif message.sender_agent_id in self.policy.trusted_internal_agent_ids and message.intent in {MessageIntent.REQUEST, MessageIntent.COMMAND}:
                risks.add(MessageRisk.DELEGATION_MISMATCH)

            if channel.command_requires_approval and message.intent == MessageIntent.COMMAND:
                if message.approval_action_id != channel.required_approval_action_id:
                    risks.add(MessageRisk.REQUIRED_APPROVAL_MISSING)
                approval = approvals.get(message.approval_action_id or "")
                if approval is None:
                    risks.add(MessageRisk.REQUIRED_APPROVAL_MISSING)
                elif not _safe(approval):
                    risks.add(MessageRisk.UPSTREAM_APPROVAL_UNSAFE)

            if message.parent_message_id is not None:
                parent: AgentMessage = messages[message.parent_message_id]
                if parent.receiver_agent_id != message.sender_agent_id:
                    risks.add(MessageRisk.PARENT_CHAIN_BROKEN)
                continuity = (
                    parent.original_principal_id == message.original_principal_id
                    and parent.tenant_id == message.tenant_id
                    and parent.task_id == message.task_id
                    and parent.goal_id == message.goal_id
                )
                delegation_continuity = parent.delegation_id == message.delegation_id
                if not delegation_continuity and message.delegation_id is not None:
                    child_delegation = delegations.get(message.delegation_id)
                    delegation_continuity = str(getattr(child_delegation, "parent_delegation_id", "")) == str(parent.delegation_id)
                if not continuity or not delegation_continuity:
                    risks.add(MessageRisk.PROVENANCE_DISCONTINUITY)
                if message.issued_at_epoch < parent.issued_at_epoch or message.expires_at_epoch > parent.expires_at_epoch:
                    risks.add(MessageRisk.PROVENANCE_DISCONTINUITY)
                parent_channel: MessageChannelPolicy = channels[parent.channel_id]
                if message.intent == MessageIntent.COMMAND and (
                    parent.intent == MessageIntent.INFORMATION
                    or parent_channel.channel_type == MessageChannelType.EXTERNAL
                    or parent.sender_agent_id in self.policy.known_external_sender_ids
                ):
                    risks.add(MessageRisk.COMMAND_LAUNDERING)

            if message.sender_agent_id in self.policy.trusted_internal_agent_ids and MessageRisk.SENDER_IDENTITY_MISMATCH not in risks:
                trust = MessageTrust.VERIFIED
            elif message.sender_agent_id in self.policy.known_external_sender_ids and MessageRisk.SENDER_IDENTITY_MISMATCH not in risks:
                trust = MessageTrust.AUTHENTICATED
            else:
                trust = MessageTrust.UNTRUSTED
            decision = MessageDecision.DENY if risks else MessageDecision.ALLOW
            facts.append(
                AgentMessageFact(
                    message_id=message_id,
                    channel_id=message.channel_id,
                    sender_agent_id=message.sender_agent_id,
                    receiver_agent_id=message.receiver_agent_id,
                    intent=message.intent,
                    decision=decision,
                    risks=tuple(sorted(risks, key=lambda r: r.value)),
                    derived_trust=trust,
                    parent_message_id=message.parent_message_id,
                    tenant_id=message.tenant_id,
                    goal_id=message.goal_id,
                    delegation_id=message.delegation_id,
                    capability_ids=tuple(sorted(message.capability_ids)),
                    risk_score=max((_RISK_SCORE[r] for r in risks), default=0),
                )
            )
        return tuple(facts)

    def evaluate(self, request: AgentMessageRequest, manifest: AgentMessageManifest, p8a: object, p8c: object, p8f: object) -> VerifiedAgentMessageAssessment:
        self._validate_policy()
        p = self.policy
        if (
            request.graph_id != p.expected_graph_id
            or request.graph_version != p.expected_graph_version
            or request.graph_sha256.casefold() != p.expected_graph_sha256.casefold()
            or request.p8a_assessment_evidence_sha256.casefold() != p.expected_p8a_assessment_evidence_sha256.casefold()
            or request.p8c_assessment_evidence_sha256.casefold() != p.expected_p8c_assessment_evidence_sha256.casefold()
            or request.p8f_assessment_evidence_sha256.casefold() != p.expected_p8f_assessment_evidence_sha256.casefold()
        ):
            _reject(MessageRejectReason.REQUEST_INVALID, "request binding invalid")
        if len(request.message_ids) != len(set(request.message_ids)) or set(request.message_ids) != set(p.required_message_ids):
            _reject(MessageRejectReason.COVERAGE_MISMATCH, "request message coverage mismatch")
        facts = self.derive(manifest, p8a, p8c, p8f, request.evaluated_at_epoch)
        denied = tuple(sorted(f.message_id for f in facts if f.decision == MessageDecision.DENY))
        if tuple(sorted(request.declared_denied_message_ids)) != denied:
            _reject(MessageRejectReason.DECLARED_DECISION_MISMATCH, "caller denial summary mismatch")
        if set(request.declared_risks_by_message) != set(p.required_message_ids):
            _reject(MessageRejectReason.DECLARED_RISK_MISMATCH, "caller risk-map coverage mismatch")
        by_id = {f.message_id: f for f in facts}
        for message_id, declared in request.declared_risks_by_message.items():
            if tuple(declared) != by_id[message_id].risks:
                _reject(MessageRejectReason.DECLARED_RISK_MISMATCH, "caller risk summary mismatch", message_id)
        allowed = len(facts) - len(denied)
        replay_set = {MessageRisk.MESSAGE_REPLAY, MessageRisk.MESSAGE_STALE, MessageRisk.MESSAGE_FUTURE, MessageRisk.MESSAGE_TIME_INVALID}
        identity_set = {MessageRisk.SENDER_IDENTITY_MISMATCH, MessageRisk.SENDER_UNAUTHORIZED, MessageRisk.RECEIVER_UNAUTHORIZED, MessageRisk.CHANNEL_UNAUTHORIZED}
        provenance_set = {MessageRisk.TENANT_MISMATCH, MessageRisk.PRINCIPAL_MISMATCH, MessageRisk.TASK_MISMATCH, MessageRisk.GOAL_MISMATCH, MessageRisk.STEP_MISMATCH, MessageRisk.DELEGATION_MISMATCH, MessageRisk.PARENT_CHAIN_BROKEN, MessageRisk.PROVENANCE_DISCONTINUITY}
        capability_set = {MessageRisk.CAPABILITY_NEGOTIATION_MISMATCH, MessageRisk.CAPABILITY_ESCALATION, MessageRisk.SCHEMA_MISMATCH, MessageRisk.PROTOCOL_DOWNGRADE, MessageRisk.INTENT_UNAUTHORIZED}
        upstream_set = {MessageRisk.UPSTREAM_DELEGATION_UNSAFE, MessageRisk.UPSTREAM_PLAN_UNSAFE, MessageRisk.UPSTREAM_APPROVAL_UNSAFE, MessageRisk.REQUIRED_APPROVAL_MISSING}
        return VerifiedAgentMessageAssessment(
            graph_id=manifest.graph_id,
            graph_version=manifest.version,
            graph_sha256=agent_message_manifest_digest(manifest),
            p8a_assessment_evidence_sha256=p.expected_p8a_assessment_evidence_sha256,
            p8c_assessment_evidence_sha256=p.expected_p8c_assessment_evidence_sha256,
            p8f_assessment_evidence_sha256=p.expected_p8f_assessment_evidence_sha256,
            message_count=len(facts),
            allowed_message_count=allowed,
            denied_message_count=len(denied),
            replay_or_freshness_denial_count=sum(bool(replay_set.intersection(f.risks)) for f in facts),
            identity_or_channel_denial_count=sum(bool(identity_set.intersection(f.risks)) for f in facts),
            provenance_denial_count=sum(bool(provenance_set.intersection(f.risks)) for f in facts),
            capability_denial_count=sum(bool(capability_set.intersection(f.risks)) for f in facts),
            command_laundering_denial_count=sum(bool({MessageRisk.COMMAND_LAUNDERING, MessageRisk.EXTERNAL_COMMAND_ESCALATION}.intersection(f.risks)) for f in facts),
            upstream_safety_denial_count=sum(bool(upstream_set.intersection(f.risks)) for f in facts),
            maximum_risk_score=max((f.risk_score for f in facts), default=0),
            messages=facts,
            assessment_evidence_sha256=_assessment_digest(facts, manifest),
        )
