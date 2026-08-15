from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, is_dataclass
from enum import StrEnum
from typing import Mapping

P8F_APPROVAL_POLICY_VERSION = "human-handoff-autonomy-boundary-v1"
P8F_APPROVAL_SCHEMA_VERSION = "aegis-human-approval-manifest-v1"
P8F_ASSESSMENT_SCHEMA_VERSION = "aegis-human-approval-assessment-v1"
P8F_ASSESSMENT_MODE = "deterministic-evidence-bound-human-approval-v1"


class AutonomyLevel(StrEnum):
    SUPERVISED = "supervised"
    BOUNDED = "bounded"
    CONDITIONAL = "conditional"
    UNSUPERVISED = "unsupervised"


class ActionRisk(StrEnum):
    LOW = "low"
    SENSITIVE = "sensitive"
    HIGH = "high"
    IRREVERSIBLE = "irreversible"


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    EDIT = "edit"


class ApprovalOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    PAUSE = "pause"


class ApprovalRisk(StrEnum):
    REQUIRED_APPROVAL_MISSING = "required_approval_missing"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_FUTURE = "approval_future"
    APPROVER_UNAUTHORIZED = "approver_unauthorized"
    SELF_APPROVAL = "self_approval"
    ACTION_BINDING_MISMATCH = "action_binding_mismatch"
    PLAN_BINDING_MISMATCH = "plan_binding_mismatch"
    APPROVAL_REPLAY = "approval_replay"
    EDIT_NOT_ALLOWED = "edit_not_allowed"
    EDIT_BINDING_MISMATCH = "edit_binding_mismatch"
    INSUFFICIENT_APPROVER_COUNT = "insufficient_approver_count"
    APPROVER_SEPARATION_VIOLATION = "approver_separation_violation"
    AUTONOMY_LEVEL_EXCEEDED = "autonomy_level_exceeded"
    HUMAN_STOP_BYPASS = "human_stop_bypass"
    UPSTREAM_PLAN_UNSAFE = "upstream_plan_unsafe"
    UPSTREAM_OBSERVATION_UNSAFE = "upstream_observation_unsafe"
    UPSTREAM_BUDGET_UNSAFE = "upstream_budget_unsafe"
    TENANT_MISMATCH = "tenant_mismatch"
    PRINCIPAL_MISMATCH = "principal_mismatch"
    GOAL_STEP_MISMATCH = "goal_step_mismatch"


class ApprovalRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    UPSTREAM_INVALID = "upstream_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    COVERAGE_MISMATCH = "coverage_mismatch"
    OWNER_UNTRUSTED = "owner_untrusted"
    POLICY_DRIFT = "policy_drift"
    REFERENCE_INVALID = "reference_invalid"
    DECLARED_OUTCOME_MISMATCH = "declared_outcome_mismatch"
    DECLARED_RISK_MISMATCH = "declared_risk_mismatch"


class HumanApprovalSecurityRejected(ValueError):
    def __init__(self, reason: ApprovalRejectReason, message: str, *, item_id: str | None = None):
        super().__init__(message)
        self.reason = reason
        self.item_id = item_id


@dataclass(frozen=True)
class HumanApprovalRule:
    rule_id: str
    action_class: str
    risk: ActionRisk
    maximum_autonomy: AutonomyLevel
    requires_human: bool
    required_reviewer_roles: tuple[str, ...]
    minimum_approver_count: int
    requires_independent_approvers: bool
    allow_edit: bool
    max_approval_age_seconds: int
    description: str


@dataclass(frozen=True)
class PendingHumanAction:
    action_id: str
    run_id: str
    goal_id: str
    step_id: str
    delegation_id: str | None
    original_principal_id: str
    tenant_id: str
    actor_agent_id: str
    action_class: str
    args_sha256: str
    plan_sha256: str
    requested_autonomy: AutonomyLevel
    requester_identity_id: str
    irreversible: bool
    created_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class HumanApprovalRecord:
    approval_id: str
    action_id: str
    reviewer_identity_id: str
    reviewer_role: str
    reviewer_group_id: str
    decision: ApprovalDecision
    bound_args_sha256: str
    bound_plan_sha256: str
    edited_args_sha256: str | None
    approval_nonce: str
    issued_at_epoch: int
    expires_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class HumanApprovalManifest:
    graph_id: str
    version: str
    p8c_assessment_evidence_sha256: str
    p8d_assessment_evidence_sha256: str
    p8e_assessment_evidence_sha256: str
    created_at_epoch: int
    rules: tuple[HumanApprovalRule, ...]
    actions: tuple[PendingHumanAction, ...]
    approvals: tuple[HumanApprovalRecord, ...]
    schema_version: str = P8F_APPROVAL_SCHEMA_VERSION


@dataclass(frozen=True)
class HumanApprovalPolicy:
    expected_graph_id: str
    expected_graph_version: str
    expected_graph_sha256: str
    expected_p8c_assessment_evidence_sha256: str
    expected_p8d_assessment_evidence_sha256: str
    expected_p8e_assessment_evidence_sha256: str
    required_rule_ids: frozenset[str]
    required_action_ids: frozenset[str]
    required_approval_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    reviewer_roles_by_identity: Mapping[str, frozenset[str]]
    reviewer_group_by_identity: Mapping[str, str]
    expected_rule_profiles: Mapping[str, tuple[object, ...]]
    expected_action_bindings: Mapping[str, tuple[object, ...]]
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class HumanApprovalRequest:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8c_assessment_evidence_sha256: str
    p8d_assessment_evidence_sha256: str
    p8e_assessment_evidence_sha256: str
    evaluated_at_epoch: int
    action_ids: tuple[str, ...]
    declared_allowed_action_ids: tuple[str, ...]
    declared_denied_action_ids: tuple[str, ...]
    declared_paused_action_ids: tuple[str, ...]
    declared_risks_by_action: Mapping[str, tuple[ApprovalRisk, ...]]


@dataclass(frozen=True)
class HumanApprovalFact:
    action_id: str
    action_class: str
    outcome: ApprovalOutcome
    risks: tuple[ApprovalRisk, ...]
    approval_ids: tuple[str, ...]
    valid_approval_ids: tuple[str, ...]
    reviewer_identity_ids: tuple[str, ...]
    requested_autonomy: AutonomyLevel
    maximum_autonomy: AutonomyLevel
    human_review_required: bool
    risk_score: int


@dataclass(frozen=True)
class VerifiedHumanApprovalAssessment:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8c_assessment_evidence_sha256: str
    p8d_assessment_evidence_sha256: str
    p8e_assessment_evidence_sha256: str
    action_count: int
    allowed_action_count: int
    denied_action_count: int
    paused_action_count: int
    approval_required_count: int
    self_approval_denial_count: int
    replay_or_stale_approval_denial_count: int
    approval_binding_denial_count: int
    autonomy_boundary_denial_count: int
    upstream_safety_denial_count: int
    maximum_risk_score: int
    actions: tuple[HumanApprovalFact, ...]
    assessment_evidence_sha256: str
    exact_human_approval_graph_binding_verified: bool = True
    exact_p8c_goal_plan_binding_verified: bool = True
    exact_p8d_tool_observation_binding_verified: bool = True
    exact_p8e_execution_budget_binding_verified: bool = True
    action_to_approval_binding_verified: bool = True
    approval_freshness_checked: bool = True
    approval_replay_checked: bool = True
    autonomy_boundary_enforced: bool = True
    independent_approver_separation_checked: bool = True
    caller_declared_approval_safety_trusted: bool = False
    production_human_identity_attestation: bool = False
    production_approval_workflow_enforcement: bool = False
    production_pam_or_iam_integration: bool = False
    cryptographic_human_signature_verification: bool = False
    legal_consent_or_compliance_certification: bool = False
    network_operations: int = 0
    schema_version: str = P8F_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P8F_APPROVAL_POLICY_VERSION
    assessment_mode: str = P8F_ASSESSMENT_MODE


def _reject(reason: ApprovalRejectReason, message: str, item_id: str | None = None) -> None:
    raise HumanApprovalSecurityRejected(reason, message, item_id=item_id)


def _sha(value: str | None) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value.casefold())


def _digest(value: object) -> str:
    return str(getattr(value, "assessment_evidence_sha256", "")).casefold()


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


def canonical_human_approval_manifest_bytes(manifest: HumanApprovalManifest) -> bytes:
    return json.dumps(_norm(manifest), sort_keys=True, separators=(",", ":")).encode()


def human_approval_manifest_digest(manifest: HumanApprovalManifest) -> str:
    return hashlib.sha256(canonical_human_approval_manifest_bytes(manifest)).hexdigest()


def _rule_profile(rule: HumanApprovalRule) -> tuple[object, ...]:
    return (
        rule.action_class,
        rule.risk,
        rule.maximum_autonomy,
        rule.requires_human,
        tuple(rule.required_reviewer_roles),
        rule.minimum_approver_count,
        rule.requires_independent_approvers,
        rule.allow_edit,
        rule.max_approval_age_seconds,
    )


def _action_binding(action: PendingHumanAction) -> tuple[object, ...]:
    return (
        action.run_id,
        action.goal_id,
        action.step_id,
        action.delegation_id,
        action.original_principal_id,
        action.tenant_id,
        action.actor_agent_id,
        action.action_class,
        action.requested_autonomy,
        action.requester_identity_id,
        action.irreversible,
    )


def _state(value: object) -> str:
    raw = getattr(value, "decision", getattr(value, "state", ""))
    return str(getattr(raw, "value", raw)).casefold()


def _safe_state(value: object) -> bool:
    return _state(value) in {"allow", "allowed", "safe", "holds"}


def _assessment_digest(facts: tuple[HumanApprovalFact, ...], manifest: HumanApprovalManifest) -> str:
    doc = {
        "graph_sha256": human_approval_manifest_digest(manifest),
        "actions": [
            {
                "id": fact.action_id,
                "outcome": fact.outcome.value,
                "risks": [r.value for r in fact.risks],
                "valid_approvals": list(fact.valid_approval_ids),
                "score": fact.risk_score,
            }
            for fact in facts
        ],
    }
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


_RISK_SCORE = {
    ApprovalRisk.REQUIRED_APPROVAL_MISSING: 85,
    ApprovalRisk.APPROVAL_REJECTED: 80,
    ApprovalRisk.APPROVAL_EXPIRED: 88,
    ApprovalRisk.APPROVAL_FUTURE: 92,
    ApprovalRisk.APPROVER_UNAUTHORIZED: 95,
    ApprovalRisk.SELF_APPROVAL: 110,
    ApprovalRisk.ACTION_BINDING_MISMATCH: 105,
    ApprovalRisk.PLAN_BINDING_MISMATCH: 108,
    ApprovalRisk.APPROVAL_REPLAY: 112,
    ApprovalRisk.EDIT_NOT_ALLOWED: 100,
    ApprovalRisk.EDIT_BINDING_MISMATCH: 102,
    ApprovalRisk.INSUFFICIENT_APPROVER_COUNT: 98,
    ApprovalRisk.APPROVER_SEPARATION_VIOLATION: 106,
    ApprovalRisk.AUTONOMY_LEVEL_EXCEEDED: 104,
    ApprovalRisk.HUMAN_STOP_BYPASS: 114,
    ApprovalRisk.UPSTREAM_PLAN_UNSAFE: 96,
    ApprovalRisk.UPSTREAM_OBSERVATION_UNSAFE: 97,
    ApprovalRisk.UPSTREAM_BUDGET_UNSAFE: 99,
    ApprovalRisk.TENANT_MISMATCH: 101,
    ApprovalRisk.PRINCIPAL_MISMATCH: 101,
    ApprovalRisk.GOAL_STEP_MISMATCH: 103,
}

_AUTONOMY_ORDER = {
    AutonomyLevel.SUPERVISED: 0,
    AutonomyLevel.BOUNDED: 1,
    AutonomyLevel.CONDITIONAL: 2,
    AutonomyLevel.UNSUPERVISED: 3,
}


class HumanHandoffAutonomySecurityAnalyzer:
    def __init__(self, policy: HumanApprovalPolicy):
        self.policy = policy

    def _validate_policy(self) -> None:
        p = self.policy
        if not p.expected_graph_id or not p.expected_graph_version:
            _reject(ApprovalRejectReason.POLICY_INVALID, "graph identity missing")
        if not all(_sha(x) for x in (p.expected_graph_sha256, p.expected_p8c_assessment_evidence_sha256, p.expected_p8d_assessment_evidence_sha256, p.expected_p8e_assessment_evidence_sha256)):
            _reject(ApprovalRejectReason.POLICY_INVALID, "invalid digest pin")
        if not p.trusted_owner_ids or p.max_manifest_age_seconds <= 0 or p.max_future_skew_seconds < 0:
            _reject(ApprovalRejectReason.POLICY_INVALID, "invalid trust/freshness policy")
        if set(p.reviewer_roles_by_identity) != set(p.reviewer_group_by_identity):
            _reject(ApprovalRejectReason.POLICY_INVALID, "reviewer maps differ")

    def _validate_upstreams(self, manifest: HumanApprovalManifest, p8c: object, p8d: object, p8e: object) -> None:
        checks = (
            (p8c, self.policy.expected_p8c_assessment_evidence_sha256, manifest.p8c_assessment_evidence_sha256, "exact_goal_plan_graph_binding_verified", "caller_declared_goal_safety_trusted"),
            (p8d, self.policy.expected_p8d_assessment_evidence_sha256, manifest.p8d_assessment_evidence_sha256, "exact_tool_observation_graph_binding_verified", "caller_declared_tool_observation_safety_trusted"),
            (p8e, self.policy.expected_p8e_assessment_evidence_sha256, manifest.p8e_assessment_evidence_sha256, "exact_execution_budget_graph_binding_verified", "caller_declared_resource_safety_trusted"),
        )
        for obj, pin, manifest_pin, verified_flag, caller_flag in checks:
            if _digest(obj) != pin.casefold() or manifest_pin.casefold() != pin.casefold():
                _reject(ApprovalRejectReason.UPSTREAM_INVALID, "upstream digest mismatch")
            if not bool(getattr(obj, verified_flag, False)) or bool(getattr(obj, caller_flag, True)):
                _reject(ApprovalRejectReason.UPSTREAM_INVALID, "upstream verification boundary invalid")

    def _map(self, items: tuple[object, ...], attr: str) -> dict[str, object]:
        out: dict[str, object] = {}
        for item in items:
            key = str(getattr(item, attr))
            if key in out:
                _reject(ApprovalRejectReason.COVERAGE_MISMATCH, "duplicate id", key)
            out[key] = item
        return out

    def _validate_manifest(self, manifest: HumanApprovalManifest, now: int):
        p = self.policy
        if manifest.schema_version != P8F_APPROVAL_SCHEMA_VERSION or manifest.graph_id != p.expected_graph_id or manifest.version != p.expected_graph_version:
            _reject(ApprovalRejectReason.MANIFEST_INVALID, "manifest identity invalid")
        if human_approval_manifest_digest(manifest) != p.expected_graph_sha256.casefold():
            _reject(ApprovalRejectReason.MANIFEST_INVALID, "manifest digest mismatch")
        if now - manifest.created_at_epoch > p.max_manifest_age_seconds or manifest.created_at_epoch - now > p.max_future_skew_seconds:
            _reject(ApprovalRejectReason.MANIFEST_INVALID, "manifest freshness invalid")
        rules = self._map(manifest.rules, "rule_id")
        actions = self._map(manifest.actions, "action_id")
        approvals = self._map(manifest.approvals, "approval_id")
        if set(rules) != set(p.required_rule_ids) or set(actions) != set(p.required_action_ids) or set(approvals) != set(p.required_approval_ids):
            _reject(ApprovalRejectReason.COVERAGE_MISMATCH, "required coverage mismatch")
        for rule_id, rule in rules.items():
            if _rule_profile(rule) != p.expected_rule_profiles.get(rule_id):
                _reject(ApprovalRejectReason.POLICY_DRIFT, "rule drift", rule_id)
            if rule.minimum_approver_count < 0 or rule.max_approval_age_seconds <= 0 or not rule.required_reviewer_roles:
                _reject(ApprovalRejectReason.POLICY_INVALID, "invalid rule", rule_id)
        for action_id, action in actions.items():
            if action.owner_id not in p.trusted_owner_ids:
                _reject(ApprovalRejectReason.OWNER_UNTRUSTED, "action owner", action_id)
            if _action_binding(action) != p.expected_action_bindings.get(action_id) or not _sha(action.args_sha256) or not _sha(action.plan_sha256):
                _reject(ApprovalRejectReason.POLICY_DRIFT, "action binding drift", action_id)
            if not any(rule.action_class == action.action_class for rule in rules.values()):
                _reject(ApprovalRejectReason.REFERENCE_INVALID, "no action rule", action_id)
        for approval_id, approval in approvals.items():
            if approval.owner_id not in p.trusted_owner_ids:
                _reject(ApprovalRejectReason.OWNER_UNTRUSTED, "approval owner", approval_id)
            if approval.action_id not in actions or not _sha(approval.bound_args_sha256) or not _sha(approval.bound_plan_sha256):
                _reject(ApprovalRejectReason.REFERENCE_INVALID, "approval reference invalid", approval_id)
            if approval.edited_args_sha256 is not None and not _sha(approval.edited_args_sha256):
                _reject(ApprovalRejectReason.REFERENCE_INVALID, "edited args digest invalid", approval_id)
            if not approval.approval_nonce:
                _reject(ApprovalRejectReason.REFERENCE_INVALID, "approval nonce empty", approval_id)
        return rules, actions, approvals

    def derive(self, manifest: HumanApprovalManifest, p8c: object, p8d: object, p8e: object, evaluated_at_epoch: int) -> tuple[HumanApprovalFact, ...]:
        self._validate_policy()
        self._validate_upstreams(manifest, p8c, p8d, p8e)
        rules, actions, approvals = self._validate_manifest(manifest, evaluated_at_epoch)
        rule_by_action_class = {rule.action_class: rule for rule in rules.values()}
        approvals_by_action: dict[str, list[HumanApprovalRecord]] = {action_id: [] for action_id in actions}
        nonce_count: dict[str, int] = {}
        for approval in approvals.values():
            approvals_by_action[approval.action_id].append(approval)
            nonce_count[approval.approval_nonce] = nonce_count.get(approval.approval_nonce, 0) + 1

        p8c_steps = {str(getattr(x, "step_id", "")): x for x in getattr(p8c, "steps", ())}
        p8d_observations = {str(getattr(x, "observation_id", "")): x for x in getattr(p8d, "observations", ())}
        p8e_runs = {str(getattr(x, "run_id", "")): x for x in getattr(p8e, "runs", ())}

        facts: list[HumanApprovalFact] = []
        for action_id in sorted(actions):
            action: PendingHumanAction = actions[action_id]
            rule: HumanApprovalRule = rule_by_action_class[action.action_class]
            risks: set[ApprovalRisk] = set()
            action_approvals = approvals_by_action[action_id]
            valid: list[HumanApprovalRecord] = []

            if _AUTONOMY_ORDER[action.requested_autonomy] > _AUTONOMY_ORDER[rule.maximum_autonomy]:
                risks.add(ApprovalRisk.AUTONOMY_LEVEL_EXCEEDED)
            if rule.requires_human and not action_approvals:
                risks.add(ApprovalRisk.REQUIRED_APPROVAL_MISSING)
            if action.irreversible and not rule.requires_human:
                risks.add(ApprovalRisk.HUMAN_STOP_BYPASS)

            step = p8c_steps.get(action.step_id)
            if step is None or not _safe_state(step):
                risks.add(ApprovalRisk.UPSTREAM_PLAN_UNSAFE)
            else:
                if str(getattr(step, "goal_id", action.goal_id)) != action.goal_id:
                    risks.add(ApprovalRisk.GOAL_STEP_MISMATCH)
            run = p8e_runs.get(action.run_id)
            if run is None or not _safe_state(run):
                risks.add(ApprovalRisk.UPSTREAM_BUDGET_UNSAFE)
            if getattr(run, "goal_id", action.goal_id) != action.goal_id:
                risks.add(ApprovalRisk.GOAL_STEP_MISMATCH)
            if getattr(run, "original_principal_id", action.original_principal_id) != action.original_principal_id:
                risks.add(ApprovalRisk.PRINCIPAL_MISMATCH)
            if getattr(run, "tenant_id", action.tenant_id) != action.tenant_id:
                risks.add(ApprovalRisk.TENANT_MISMATCH)
            related_observations = [o for o in p8d_observations.values() if str(getattr(o, "step_id", "")) == action.step_id]
            if related_observations and not all(_safe_state(o) for o in related_observations):
                risks.add(ApprovalRisk.UPSTREAM_OBSERVATION_UNSAFE)

            for approval in action_approvals:
                local_risks: set[ApprovalRisk] = set()
                roles = self.policy.reviewer_roles_by_identity.get(approval.reviewer_identity_id, frozenset())
                group = self.policy.reviewer_group_by_identity.get(approval.reviewer_identity_id)
                if approval.reviewer_role not in roles or approval.reviewer_role not in rule.required_reviewer_roles or group != approval.reviewer_group_id:
                    local_risks.add(ApprovalRisk.APPROVER_UNAUTHORIZED)
                if approval.reviewer_identity_id in {action.requester_identity_id, action.actor_agent_id, action.original_principal_id}:
                    local_risks.add(ApprovalRisk.SELF_APPROVAL)
                if approval.bound_args_sha256.casefold() != action.args_sha256.casefold():
                    local_risks.add(ApprovalRisk.ACTION_BINDING_MISMATCH)
                if approval.bound_plan_sha256.casefold() != action.plan_sha256.casefold():
                    local_risks.add(ApprovalRisk.PLAN_BINDING_MISMATCH)
                if approval.issued_at_epoch > evaluated_at_epoch + self.policy.max_future_skew_seconds:
                    local_risks.add(ApprovalRisk.APPROVAL_FUTURE)
                if approval.expires_at_epoch < evaluated_at_epoch or evaluated_at_epoch - approval.issued_at_epoch > rule.max_approval_age_seconds:
                    local_risks.add(ApprovalRisk.APPROVAL_EXPIRED)
                if approval.expires_at_epoch < approval.issued_at_epoch:
                    local_risks.add(ApprovalRisk.APPROVAL_EXPIRED)
                if nonce_count[approval.approval_nonce] > 1:
                    local_risks.add(ApprovalRisk.APPROVAL_REPLAY)
                if approval.decision == ApprovalDecision.REJECT:
                    local_risks.add(ApprovalRisk.APPROVAL_REJECTED)
                if approval.decision == ApprovalDecision.EDIT:
                    if not rule.allow_edit:
                        local_risks.add(ApprovalRisk.EDIT_NOT_ALLOWED)
                    if approval.edited_args_sha256 is None or approval.edited_args_sha256.casefold() == action.args_sha256.casefold():
                        local_risks.add(ApprovalRisk.EDIT_BINDING_MISMATCH)
                elif approval.edited_args_sha256 is not None:
                    local_risks.add(ApprovalRisk.EDIT_BINDING_MISMATCH)
                risks.update(local_risks)
                if not local_risks and approval.decision in {ApprovalDecision.APPROVE, ApprovalDecision.EDIT}:
                    valid.append(approval)

            if rule.requires_human and len(valid) < rule.minimum_approver_count:
                risks.add(ApprovalRisk.INSUFFICIENT_APPROVER_COUNT)
            if rule.requires_independent_approvers and rule.minimum_approver_count > 1 and len(valid) >= rule.minimum_approver_count:
                groups = {approval.reviewer_group_id for approval in valid}
                reviewers = {approval.reviewer_identity_id for approval in valid}
                if len(groups) < rule.minimum_approver_count or len(reviewers) < rule.minimum_approver_count:
                    risks.add(ApprovalRisk.APPROVER_SEPARATION_VIOLATION)

            pause_only = bool(risks) and risks.issubset({ApprovalRisk.REQUIRED_APPROVAL_MISSING, ApprovalRisk.INSUFFICIENT_APPROVER_COUNT})
            if pause_only:
                outcome = ApprovalOutcome.PAUSE
            elif risks:
                outcome = ApprovalOutcome.DENY
            else:
                outcome = ApprovalOutcome.ALLOW
            risk_score = max((_RISK_SCORE[r] for r in risks), default=0)
            facts.append(
                HumanApprovalFact(
                    action_id=action_id,
                    action_class=action.action_class,
                    outcome=outcome,
                    risks=tuple(sorted(risks, key=lambda r: r.value)),
                    approval_ids=tuple(sorted(a.approval_id for a in action_approvals)),
                    valid_approval_ids=tuple(sorted(a.approval_id for a in valid)),
                    reviewer_identity_ids=tuple(sorted({a.reviewer_identity_id for a in action_approvals})),
                    requested_autonomy=action.requested_autonomy,
                    maximum_autonomy=rule.maximum_autonomy,
                    human_review_required=rule.requires_human,
                    risk_score=risk_score,
                )
            )
        return tuple(facts)

    def evaluate(self, request: HumanApprovalRequest, manifest: HumanApprovalManifest, p8c: object, p8d: object, p8e: object) -> VerifiedHumanApprovalAssessment:
        self._validate_policy()
        p = self.policy
        if (
            request.graph_id != p.expected_graph_id
            or request.graph_version != p.expected_graph_version
            or request.graph_sha256.casefold() != p.expected_graph_sha256.casefold()
            or request.p8c_assessment_evidence_sha256.casefold() != p.expected_p8c_assessment_evidence_sha256.casefold()
            or request.p8d_assessment_evidence_sha256.casefold() != p.expected_p8d_assessment_evidence_sha256.casefold()
            or request.p8e_assessment_evidence_sha256.casefold() != p.expected_p8e_assessment_evidence_sha256.casefold()
        ):
            _reject(ApprovalRejectReason.REQUEST_INVALID, "request binding invalid")
        if len(request.action_ids) != len(set(request.action_ids)) or set(request.action_ids) != set(p.required_action_ids):
            _reject(ApprovalRejectReason.COVERAGE_MISMATCH, "request action coverage mismatch")
        facts = self.derive(manifest, p8c, p8d, p8e, request.evaluated_at_epoch)
        allowed = tuple(sorted(f.action_id for f in facts if f.outcome == ApprovalOutcome.ALLOW))
        denied = tuple(sorted(f.action_id for f in facts if f.outcome == ApprovalOutcome.DENY))
        paused = tuple(sorted(f.action_id for f in facts if f.outcome == ApprovalOutcome.PAUSE))
        if tuple(sorted(request.declared_allowed_action_ids)) != allowed or tuple(sorted(request.declared_denied_action_ids)) != denied or tuple(sorted(request.declared_paused_action_ids)) != paused:
            _reject(ApprovalRejectReason.DECLARED_OUTCOME_MISMATCH, "caller outcome summary mismatch")
        if set(request.declared_risks_by_action) != set(p.required_action_ids):
            _reject(ApprovalRejectReason.DECLARED_RISK_MISMATCH, "caller risk-map coverage mismatch")
        by_id = {f.action_id: f for f in facts}
        for action_id, declared in request.declared_risks_by_action.items():
            if tuple(declared) != by_id[action_id].risks:
                _reject(ApprovalRejectReason.DECLARED_RISK_MISMATCH, "caller risk summary mismatch", action_id)
        max_score = max((f.risk_score for f in facts), default=0)
        return VerifiedHumanApprovalAssessment(
            graph_id=manifest.graph_id,
            graph_version=manifest.version,
            graph_sha256=human_approval_manifest_digest(manifest),
            p8c_assessment_evidence_sha256=p.expected_p8c_assessment_evidence_sha256,
            p8d_assessment_evidence_sha256=p.expected_p8d_assessment_evidence_sha256,
            p8e_assessment_evidence_sha256=p.expected_p8e_assessment_evidence_sha256,
            action_count=len(facts),
            allowed_action_count=len(allowed),
            denied_action_count=len(denied),
            paused_action_count=len(paused),
            approval_required_count=sum(f.human_review_required for f in facts),
            self_approval_denial_count=sum(ApprovalRisk.SELF_APPROVAL in f.risks for f in facts),
            replay_or_stale_approval_denial_count=sum(bool({ApprovalRisk.APPROVAL_REPLAY, ApprovalRisk.APPROVAL_EXPIRED, ApprovalRisk.APPROVAL_FUTURE}.intersection(f.risks)) for f in facts),
            approval_binding_denial_count=sum(bool({ApprovalRisk.ACTION_BINDING_MISMATCH, ApprovalRisk.PLAN_BINDING_MISMATCH, ApprovalRisk.EDIT_BINDING_MISMATCH}.intersection(f.risks)) for f in facts),
            autonomy_boundary_denial_count=sum(bool({ApprovalRisk.AUTONOMY_LEVEL_EXCEEDED, ApprovalRisk.HUMAN_STOP_BYPASS}.intersection(f.risks)) for f in facts),
            upstream_safety_denial_count=sum(bool({ApprovalRisk.UPSTREAM_PLAN_UNSAFE, ApprovalRisk.UPSTREAM_OBSERVATION_UNSAFE, ApprovalRisk.UPSTREAM_BUDGET_UNSAFE}.intersection(f.risks)) for f in facts),
            maximum_risk_score=max_score,
            actions=facts,
            assessment_evidence_sha256=_assessment_digest(facts, manifest),
        )
