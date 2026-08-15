from __future__ import annotations

import hashlib
import json
import posixpath
from dataclasses import asdict, dataclass, is_dataclass
from enum import StrEnum
from typing import Mapping

P8I_ARTIFACT_POLICY_VERSION = "agent-artifact-workspace-generated-code-integrity-v1"
P8I_ARTIFACT_SCHEMA_VERSION = "aegis-agent-artifact-workspace-manifest-v1"
P8I_ASSESSMENT_SCHEMA_VERSION = "aegis-agent-artifact-workspace-assessment-v1"
P8I_ASSESSMENT_MODE = "deterministic-evidence-bound-agent-artifact-integrity-v1"


class ArtifactKind(StrEnum):
    SOURCE = "source"
    PATCH = "patch"
    DEPENDENCY_MANIFEST = "dependency_manifest"
    LOCKFILE = "lockfile"
    BUILD_CONFIG = "build_config"
    CI_WORKFLOW = "ci_workflow"
    STARTUP_HOOK = "startup_hook"
    ARCHIVE = "archive"
    EXECUTABLE = "executable"
    MODEL_ARTIFACT = "model_artifact"
    DOCUMENT = "document"


class ArtifactOperation(StrEnum):
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"
    EXTRACT = "extract"
    EXECUTE = "execute"
    PUBLISH = "publish"


class ArtifactTrust(StrEnum):
    UNTRUSTED_INPUT = "untrusted_input"
    GENERATED = "generated"
    VERIFIED = "verified"
    TRUSTED_CONTROL = "trusted_control"


class ArchiveMemberType(StrEnum):
    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    HARDLINK = "hardlink"


class ArtifactDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class ArtifactRisk(StrEnum):
    ABSOLUTE_PATH = "absolute_path"
    PATH_ESCAPE = "path_escape"
    OUT_OF_SCOPE_WRITE = "out_of_scope_write"
    SYMLINK_ESCAPE = "symlink_escape"
    HARDLINK_ESCAPE = "hardlink_escape"
    ARCHIVE_TRAVERSAL = "archive_traversal"
    ARCHIVE_LINK_ESCAPE = "archive_link_escape"
    ARCHIVE_LIMIT_EXCEEDED = "archive_limit_exceeded"
    CROSS_TENANT = "cross_tenant"
    WORKSPACE_MISMATCH = "workspace_mismatch"
    OPERATION_UNAUTHORIZED = "operation_unauthorized"
    KIND_UNAUTHORIZED = "kind_unauthorized"
    CONTENT_DIGEST_MISMATCH = "content_digest_mismatch"
    BASE_DIGEST_MISMATCH = "base_digest_mismatch"
    PROVENANCE_MISSING = "provenance_missing"
    PROVENANCE_MISMATCH = "provenance_mismatch"
    GENERATED_CODE_LAUNDERING = "generated_code_laundering"
    DEPENDENCY_PERSISTENCE = "dependency_persistence"
    CONTROL_PATH_PERSISTENCE = "control_path_persistence"
    BUILD_CONTEXT_POISONING = "build_context_poisoning"
    EXECUTABLE_WRITE = "executable_write"
    EXECUTION_UNAPPROVED = "execution_unapproved"
    UPSTREAM_PLAN_UNSAFE = "upstream_plan_unsafe"
    UPSTREAM_APPROVAL_UNSAFE = "upstream_approval_unsafe"
    UPSTREAM_STATE_UNSAFE = "upstream_state_unsafe"


class ArtifactRejectReason(StrEnum):
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
    DECLARED_RESULT_MISMATCH = "declared_result_mismatch"


class AgentArtifactSecurityRejected(ValueError):
    def __init__(self, reason: ArtifactRejectReason, message: str, *, item_id: str | None = None):
        super().__init__(message)
        self.reason = reason
        self.item_id = item_id


@dataclass(frozen=True)
class WorkspaceRoot:
    workspace_id: str
    tenant_id: str
    root_path: str
    allowed_write_prefixes: tuple[str, ...]
    allowed_execute_prefixes: tuple[str, ...]
    build_context_prefixes: tuple[str, ...]
    owner_id: str
    description: str


@dataclass(frozen=True)
class WorkspaceArtifact:
    artifact_id: str
    workspace_id: str
    tenant_id: str
    relative_path: str
    kind: ArtifactKind
    trust: ArtifactTrust
    content_sha256: str
    executable: bool
    symlink_target: str | None
    hardlink_target: str | None
    owner_id: str
    description: str


@dataclass(frozen=True)
class ArchiveMember:
    member_path: str
    member_type: ArchiveMemberType
    size_bytes: int
    link_target: str | None = None


@dataclass(frozen=True)
class ArtifactAction:
    action_id: str
    artifact_id: str
    operation: ArtifactOperation
    actor_agent_id: str
    original_principal_id: str
    tenant_id: str
    plan_step_id: str
    approval_action_id: str | None
    state_transition_id: str | None
    message_id: str
    target_relative_path: str
    expected_base_sha256: str
    proposed_content_sha256: str
    source_artifact_ids: tuple[str, ...]
    source_request_sha256: str
    patch_sha256: str
    proposed_kind: ArtifactKind
    proposed_trust: ArtifactTrust
    proposed_executable: bool
    proposed_symlink_target: str | None
    proposed_hardlink_target: str | None
    archive_members: tuple[ArchiveMember, ...]
    issued_at_epoch: int
    owner_id: str
    description: str


@dataclass(frozen=True)
class AgentArtifactManifest:
    graph_id: str
    version: str
    p8c_assessment_evidence_sha256: str
    p8f_assessment_evidence_sha256: str
    p8h_assessment_evidence_sha256: str
    created_at_epoch: int
    workspaces: tuple[WorkspaceRoot, ...]
    artifacts: tuple[WorkspaceArtifact, ...]
    actions: tuple[ArtifactAction, ...]
    schema_version: str = P8I_ARTIFACT_SCHEMA_VERSION


@dataclass(frozen=True)
class AgentArtifactPolicy:
    expected_graph_id: str
    expected_graph_version: str
    expected_graph_sha256: str
    expected_p8c_assessment_evidence_sha256: str
    expected_p8f_assessment_evidence_sha256: str
    expected_p8h_assessment_evidence_sha256: str
    required_workspace_ids: frozenset[str]
    required_artifact_ids: frozenset[str]
    required_action_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    expected_workspace_profiles: Mapping[str, tuple[object, ...]]
    expected_artifact_profiles: Mapping[str, tuple[object, ...]]
    allowed_operations_by_kind: Mapping[ArtifactKind, frozenset[ArtifactOperation]]
    allowed_kinds_by_workspace: Mapping[str, frozenset[ArtifactKind]]
    approval_required_kinds: frozenset[ArtifactKind]
    control_path_prefixes: tuple[str, ...]
    dependency_path_prefixes: tuple[str, ...]
    state_required_operations: frozenset[ArtifactOperation]
    provenance_required_operations: frozenset[ArtifactOperation]
    max_archive_members: int = 128
    max_archive_total_bytes: int = 16_777_216
    max_manifest_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class AgentArtifactRequest:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8c_assessment_evidence_sha256: str
    p8f_assessment_evidence_sha256: str
    p8h_assessment_evidence_sha256: str
    evaluated_at_epoch: int
    action_ids: tuple[str, ...]
    declared_denied_action_ids: tuple[str, ...]
    declared_risks_by_action: Mapping[str, tuple[ArtifactRisk, ...]]
    declared_result_sha256_by_artifact: Mapping[str, str]


@dataclass(frozen=True)
class ArtifactActionFact:
    action_id: str
    artifact_id: str
    operation: ArtifactOperation
    decision: ArtifactDecision
    risks: tuple[ArtifactRisk, ...]
    target_relative_path: str
    resulting_content_sha256: str
    proposed_kind: ArtifactKind
    proposed_trust: ArtifactTrust
    proposed_executable: bool
    risk_score: int


@dataclass(frozen=True)
class VerifiedAgentArtifactAssessment:
    graph_id: str
    graph_version: str
    graph_sha256: str
    p8c_assessment_evidence_sha256: str
    p8f_assessment_evidence_sha256: str
    p8h_assessment_evidence_sha256: str
    action_count: int
    allowed_action_count: int
    denied_action_count: int
    path_or_link_denial_count: int
    archive_denial_count: int
    persistence_denial_count: int
    executable_denial_count: int
    provenance_denial_count: int
    upstream_safety_denial_count: int
    maximum_risk_score: int
    resulting_sha256_by_artifact: Mapping[str, str]
    actions: tuple[ArtifactActionFact, ...]
    assessment_evidence_sha256: str
    exact_artifact_graph_binding_verified: bool = True
    exact_p8c_goal_plan_binding_verified: bool = True
    exact_p8f_human_approval_binding_verified: bool = True
    exact_p8h_state_transition_binding_verified: bool = True
    path_scope_confinement_checked: bool = True
    link_and_archive_escape_checked: bool = True
    generated_artifact_provenance_checked: bool = True
    sensitive_persistence_paths_checked: bool = True
    executable_artifact_approval_checked: bool = True
    caller_declared_artifact_safety_trusted: bool = False
    production_filesystem_enforcement: bool = False
    production_sandbox_enforcement: bool = False
    semantic_malware_detection: bool = False
    cryptographic_artifact_signing: bool = False
    formal_filesystem_confinement_proof: bool = False
    exhaustive_supply_chain_coverage: bool = False
    network_operations: int = 0
    schema_version: str = P8I_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P8I_ARTIFACT_POLICY_VERSION
    assessment_mode: str = P8I_ASSESSMENT_MODE


def _reject(reason: ArtifactRejectReason, message: str, item_id: str | None = None) -> None:
    raise AgentArtifactSecurityRejected(reason, message, item_id=item_id)


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


def canonical_agent_artifact_manifest_bytes(manifest: AgentArtifactManifest) -> bytes:
    return json.dumps(_norm(manifest), sort_keys=True, separators=(",", ":")).encode()


def agent_artifact_manifest_digest(manifest: AgentArtifactManifest) -> str:
    return hashlib.sha256(canonical_agent_artifact_manifest_bytes(manifest)).hexdigest()


def _workspace_profile(workspace: WorkspaceRoot) -> tuple[object, ...]:
    return (
        workspace.tenant_id,
        workspace.root_path,
        workspace.allowed_write_prefixes,
        workspace.allowed_execute_prefixes,
        workspace.build_context_prefixes,
    )


def _artifact_profile(artifact: WorkspaceArtifact) -> tuple[object, ...]:
    return (
        artifact.workspace_id,
        artifact.tenant_id,
        artifact.relative_path,
        artifact.kind,
        artifact.trust,
        artifact.content_sha256.casefold(),
        artifact.executable,
        artifact.symlink_target,
        artifact.hardlink_target,
    )


def _path_reason(path: str) -> ArtifactRisk | None:
    if not isinstance(path, str) or not path or "\x00" in path:
        return ArtifactRisk.PATH_ESCAPE
    if path.startswith(("/", "\\")) or (len(path) >= 2 and path[1] == ":"):
        return ArtifactRisk.ABSOLUTE_PATH
    if "\\" in path:
        return ArtifactRisk.PATH_ESCAPE
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return ArtifactRisk.PATH_ESCAPE
    normalized = posixpath.normpath(path)
    if normalized != path or normalized == ".." or normalized.startswith("../"):
        return ArtifactRisk.PATH_ESCAPE
    return None


def _under(path: str, prefix: str) -> bool:
    p = prefix.rstrip("/")
    return path == p or path.startswith(p + "/")


def _link_escapes(source_path: str, target: str | None) -> bool:
    if target is None:
        return False
    if _path_reason(target) == ArtifactRisk.ABSOLUTE_PATH:
        return True
    if "\\" in target or "\x00" in target:
        return True
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(source_path), target))
    return joined == ".." or joined.startswith("../") or joined.startswith("/")


def _requires_approval(action: ArtifactAction, policy: AgentArtifactPolicy) -> bool:
    if action.proposed_kind in policy.approval_required_kinds:
        return True
    if action.operation in {ArtifactOperation.EXECUTE, ArtifactOperation.PUBLISH} or action.proposed_executable:
        return True
    return any(_under(action.target_relative_path, p) for p in policy.control_path_prefixes + policy.dependency_path_prefixes)


_RISK_SCORE = {
    ArtifactRisk.ABSOLUTE_PATH: 120,
    ArtifactRisk.PATH_ESCAPE: 120,
    ArtifactRisk.OUT_OF_SCOPE_WRITE: 118,
    ArtifactRisk.SYMLINK_ESCAPE: 121,
    ArtifactRisk.HARDLINK_ESCAPE: 121,
    ArtifactRisk.ARCHIVE_TRAVERSAL: 122,
    ArtifactRisk.ARCHIVE_LINK_ESCAPE: 123,
    ArtifactRisk.ARCHIVE_LIMIT_EXCEEDED: 108,
    ArtifactRisk.CROSS_TENANT: 120,
    ArtifactRisk.WORKSPACE_MISMATCH: 112,
    ArtifactRisk.OPERATION_UNAUTHORIZED: 110,
    ArtifactRisk.KIND_UNAUTHORIZED: 108,
    ArtifactRisk.CONTENT_DIGEST_MISMATCH: 115,
    ArtifactRisk.BASE_DIGEST_MISMATCH: 117,
    ArtifactRisk.PROVENANCE_MISSING: 112,
    ArtifactRisk.PROVENANCE_MISMATCH: 116,
    ArtifactRisk.GENERATED_CODE_LAUNDERING: 124,
    ArtifactRisk.DEPENDENCY_PERSISTENCE: 120,
    ArtifactRisk.CONTROL_PATH_PERSISTENCE: 125,
    ArtifactRisk.BUILD_CONTEXT_POISONING: 119,
    ArtifactRisk.EXECUTABLE_WRITE: 123,
    ArtifactRisk.EXECUTION_UNAPPROVED: 126,
    ArtifactRisk.UPSTREAM_PLAN_UNSAFE: 116,
    ArtifactRisk.UPSTREAM_APPROVAL_UNSAFE: 120,
    ArtifactRisk.UPSTREAM_STATE_UNSAFE: 118,
}


def _assessment_digest(
    facts: tuple[ArtifactActionFact, ...],
    manifest: AgentArtifactManifest,
    results: Mapping[str, str],
) -> str:
    doc = {
        "graph_sha256": agent_artifact_manifest_digest(manifest),
        "results": dict(sorted(results.items())),
        "actions": [
            {
                "id": f.action_id,
                "decision": f.decision.value,
                "risks": [r.value for r in f.risks],
                "result": f.resulting_content_sha256,
                "score": f.risk_score,
            }
            for f in facts
        ],
    }
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AgentArtifactWorkspaceSecurityAnalyzer:
    def __init__(self, policy: AgentArtifactPolicy):
        self.policy = policy

    def _validate_policy(self) -> None:
        p = self.policy
        if not p.expected_graph_id or not p.expected_graph_version or not p.trusted_owner_ids:
            _reject(ArtifactRejectReason.POLICY_INVALID, "missing graph or trust policy")
        if not all(
            _sha(x)
            for x in (
                p.expected_graph_sha256,
                p.expected_p8c_assessment_evidence_sha256,
                p.expected_p8f_assessment_evidence_sha256,
                p.expected_p8h_assessment_evidence_sha256,
            )
        ):
            _reject(ArtifactRejectReason.POLICY_INVALID, "invalid digest pin")
        if p.max_archive_members <= 0 or p.max_archive_total_bytes <= 0:
            _reject(ArtifactRejectReason.POLICY_INVALID, "invalid archive policy")
        if p.max_manifest_age_seconds <= 0 or p.max_future_skew_seconds < 0:
            _reject(ArtifactRejectReason.POLICY_INVALID, "invalid freshness policy")
        if set(p.expected_workspace_profiles) != set(p.required_workspace_ids):
            _reject(ArtifactRejectReason.POLICY_INVALID, "workspace profile coverage mismatch")
        if set(p.expected_artifact_profiles) != set(p.required_artifact_ids):
            _reject(ArtifactRejectReason.POLICY_INVALID, "artifact profile coverage mismatch")
        if set(p.allowed_kinds_by_workspace) != set(p.required_workspace_ids):
            _reject(ArtifactRejectReason.POLICY_INVALID, "workspace kind policy coverage mismatch")
        if not p.allowed_operations_by_kind:
            _reject(ArtifactRejectReason.POLICY_INVALID, "missing kind operation policy")

    def _validate_upstreams(self, manifest: AgentArtifactManifest, p8c: object, p8f: object, p8h: object) -> None:
        checks = (
            (
                p8c,
                self.policy.expected_p8c_assessment_evidence_sha256,
                manifest.p8c_assessment_evidence_sha256,
                "exact_goal_plan_graph_binding_verified",
                "caller_declared_goal_safety_trusted",
            ),
            (
                p8f,
                self.policy.expected_p8f_assessment_evidence_sha256,
                manifest.p8f_assessment_evidence_sha256,
                "exact_human_approval_graph_binding_verified",
                "caller_declared_approval_safety_trusted",
            ),
            (
                p8h,
                self.policy.expected_p8h_assessment_evidence_sha256,
                manifest.p8h_assessment_evidence_sha256,
                "exact_state_transition_graph_binding_verified",
                "caller_declared_state_safety_trusted",
            ),
        )
        for obj, pin, manifest_pin, verified_flag, caller_flag in checks:
            if _digest(obj) != pin.casefold() or manifest_pin.casefold() != pin.casefold():
                _reject(ArtifactRejectReason.UPSTREAM_INVALID, "upstream digest mismatch")
            if not bool(getattr(obj, verified_flag, False)) or bool(getattr(obj, caller_flag, True)):
                _reject(ArtifactRejectReason.UPSTREAM_INVALID, "upstream verification boundary invalid")

    @staticmethod
    def _map(items: tuple[object, ...], attr: str) -> dict[str, object]:
        out: dict[str, object] = {}
        for item in items:
            key = str(getattr(item, attr))
            if key in out:
                _reject(ArtifactRejectReason.COVERAGE_MISMATCH, "duplicate identifier", key)
            out[key] = item
        return out

    def _validate_manifest(self, manifest: AgentArtifactManifest, now: int):
        p = self.policy
        if (
            manifest.schema_version != P8I_ARTIFACT_SCHEMA_VERSION
            or manifest.graph_id != p.expected_graph_id
            or manifest.version != p.expected_graph_version
        ):
            _reject(ArtifactRejectReason.MANIFEST_INVALID, "manifest identity invalid")
        if agent_artifact_manifest_digest(manifest) != p.expected_graph_sha256.casefold():
            _reject(ArtifactRejectReason.MANIFEST_INVALID, "manifest digest mismatch")
        if now - manifest.created_at_epoch > p.max_manifest_age_seconds or manifest.created_at_epoch - now > p.max_future_skew_seconds:
            _reject(ArtifactRejectReason.MANIFEST_INVALID, "manifest freshness invalid")

        workspaces = self._map(manifest.workspaces, "workspace_id")
        artifacts = self._map(manifest.artifacts, "artifact_id")
        actions = self._map(manifest.actions, "action_id")
        if (
            set(workspaces) != set(p.required_workspace_ids)
            or set(artifacts) != set(p.required_artifact_ids)
            or set(actions) != set(p.required_action_ids)
        ):
            _reject(ArtifactRejectReason.COVERAGE_MISMATCH, "manifest coverage mismatch")

        for workspace_id, workspace in workspaces.items():
            if workspace.owner_id not in p.trusted_owner_ids:
                _reject(ArtifactRejectReason.OWNER_UNTRUSTED, "workspace owner untrusted", workspace_id)
            if not workspace.root_path.startswith("/") or posixpath.normpath(workspace.root_path) != workspace.root_path:
                _reject(ArtifactRejectReason.REFERENCE_INVALID, "workspace root invalid", workspace_id)
            if _workspace_profile(workspace) != p.expected_workspace_profiles.get(workspace_id):
                _reject(ArtifactRejectReason.POLICY_DRIFT, "workspace profile drift", workspace_id)
            for prefix in workspace.allowed_write_prefixes + workspace.allowed_execute_prefixes + workspace.build_context_prefixes:
                if _path_reason(prefix) is not None:
                    _reject(ArtifactRejectReason.REFERENCE_INVALID, "workspace prefix invalid", workspace_id)

        for artifact_id, artifact in artifacts.items():
            if artifact.owner_id not in p.trusted_owner_ids:
                _reject(ArtifactRejectReason.OWNER_UNTRUSTED, "artifact owner untrusted", artifact_id)
            if artifact.workspace_id not in workspaces or not _sha(artifact.content_sha256):
                _reject(ArtifactRejectReason.REFERENCE_INVALID, "artifact reference invalid", artifact_id)
            if _path_reason(artifact.relative_path) is not None:
                _reject(ArtifactRejectReason.REFERENCE_INVALID, "artifact path invalid", artifact_id)
            if _artifact_profile(artifact) != p.expected_artifact_profiles.get(artifact_id):
                _reject(ArtifactRejectReason.POLICY_DRIFT, "artifact profile drift", artifact_id)
            workspace = workspaces[artifact.workspace_id]
            if artifact.tenant_id != workspace.tenant_id:
                _reject(ArtifactRejectReason.POLICY_DRIFT, "artifact tenant drift", artifact_id)
            if artifact.kind not in p.allowed_kinds_by_workspace[artifact.workspace_id]:
                _reject(ArtifactRejectReason.POLICY_DRIFT, "artifact kind not allowed in workspace", artifact_id)
            if _link_escapes(artifact.relative_path, artifact.symlink_target) or _link_escapes(artifact.relative_path, artifact.hardlink_target):
                _reject(ArtifactRejectReason.REFERENCE_INVALID, "artifact link escapes workspace", artifact_id)

        for action_id, action in actions.items():
            if action.owner_id not in p.trusted_owner_ids:
                _reject(ArtifactRejectReason.OWNER_UNTRUSTED, "action owner untrusted", action_id)
            if action.artifact_id not in artifacts or not action.plan_step_id or not action.message_id:
                _reject(ArtifactRejectReason.REFERENCE_INVALID, "action reference invalid", action_id)
            if not all(_sha(v) for v in (action.expected_base_sha256, action.proposed_content_sha256, action.source_request_sha256, action.patch_sha256)):
                _reject(ArtifactRejectReason.REFERENCE_INVALID, "action digest invalid", action_id)
            if action.issued_at_epoch > now + p.max_future_skew_seconds:
                _reject(ArtifactRejectReason.REFERENCE_INVALID, "action future skew invalid", action_id)
            if any(source_id not in artifacts for source_id in action.source_artifact_ids):
                _reject(ArtifactRejectReason.REFERENCE_INVALID, "unknown source artifact", action_id)
            if action.proposed_kind not in p.allowed_operations_by_kind:
                _reject(ArtifactRejectReason.REFERENCE_INVALID, "unknown proposed kind", action_id)
            for member in action.archive_members:
                if member.size_bytes < 0:
                    _reject(ArtifactRejectReason.REFERENCE_INVALID, "archive member size invalid", action_id)
                if member.member_type in {ArchiveMemberType.SYMLINK, ArchiveMemberType.HARDLINK} and member.link_target is None:
                    _reject(ArtifactRejectReason.REFERENCE_INVALID, "archive link missing target", action_id)
        return workspaces, artifacts, actions

    def derive(
        self,
        manifest: AgentArtifactManifest,
        p8c: object,
        p8f: object,
        p8h: object,
        evaluated_at_epoch: int,
    ) -> tuple[tuple[ArtifactActionFact, ...], dict[str, str]]:
        self._validate_policy()
        self._validate_upstreams(manifest, p8c, p8f, p8h)
        workspaces, artifacts, actions = self._validate_manifest(manifest, evaluated_at_epoch)

        steps = {str(getattr(x, "step_id", "")): x for x in getattr(p8c, "steps", ())}
        approvals = {str(getattr(x, "action_id", "")): x for x in getattr(p8f, "actions", ())}
        transitions = {str(getattr(x, "transition_id", "")): x for x in getattr(p8h, "transitions", ())}

        current_sha = {artifact_id: artifact.content_sha256.casefold() for artifact_id, artifact in artifacts.items()}
        current_trust = {artifact_id: artifact.trust for artifact_id, artifact in artifacts.items()}
        facts: list[ArtifactActionFact] = []

        for action_id in [a.action_id for a in manifest.actions]:
            action = actions[action_id]
            artifact = artifacts[action.artifact_id]
            workspace = workspaces[artifact.workspace_id]
            risks: set[ArtifactRisk] = set()

            path_reason = _path_reason(action.target_relative_path)
            if path_reason is not None:
                risks.add(path_reason)
            elif not any(_under(action.target_relative_path, prefix) for prefix in workspace.allowed_write_prefixes):
                risks.add(ArtifactRisk.OUT_OF_SCOPE_WRITE)

            if action.tenant_id != artifact.tenant_id or action.tenant_id != workspace.tenant_id:
                risks.add(ArtifactRisk.CROSS_TENANT)
            if action.proposed_kind not in self.policy.allowed_kinds_by_workspace[artifact.workspace_id]:
                risks.add(ArtifactRisk.KIND_UNAUTHORIZED)
            if action.operation not in self.policy.allowed_operations_by_kind.get(action.proposed_kind, frozenset()):
                risks.add(ArtifactRisk.OPERATION_UNAUTHORIZED)
            if action.expected_base_sha256.casefold() != current_sha[action.artifact_id]:
                risks.add(ArtifactRisk.BASE_DIGEST_MISMATCH)
            if not _sha(action.proposed_content_sha256):
                risks.add(ArtifactRisk.CONTENT_DIGEST_MISMATCH)

            step = steps.get(action.plan_step_id)
            if step is None or not _safe(step):
                risks.add(ArtifactRisk.UPSTREAM_PLAN_UNSAFE)
            elif str(getattr(step, "agent_id", "")) != action.actor_agent_id:
                risks.add(ArtifactRisk.PROVENANCE_MISMATCH)

            if action.operation in self.policy.state_required_operations:
                transition = transitions.get(action.state_transition_id or "")
                if transition is None or not _safe(transition):
                    risks.add(ArtifactRisk.UPSTREAM_STATE_UNSAFE)

            approval_ok = False
            if action.approval_action_id is not None:
                approval = approvals.get(action.approval_action_id)
                approval_ok = approval is not None and _safe(approval)
            if _requires_approval(action, self.policy) and not approval_ok:
                risks.add(ArtifactRisk.UPSTREAM_APPROVAL_UNSAFE)

            if action.operation in self.policy.provenance_required_operations:
                if not _sha(action.source_request_sha256) or not _sha(action.patch_sha256):
                    risks.add(ArtifactRisk.PROVENANCE_MISSING)
                if not action.actor_agent_id or not action.original_principal_id or not action.message_id:
                    risks.add(ArtifactRisk.PROVENANCE_MISSING)

            if _link_escapes(action.target_relative_path, action.proposed_symlink_target):
                risks.add(ArtifactRisk.SYMLINK_ESCAPE)
            if _link_escapes(action.target_relative_path, action.proposed_hardlink_target):
                risks.add(ArtifactRisk.HARDLINK_ESCAPE)

            if action.archive_members:
                if len(action.archive_members) > self.policy.max_archive_members or sum(m.size_bytes for m in action.archive_members) > self.policy.max_archive_total_bytes:
                    risks.add(ArtifactRisk.ARCHIVE_LIMIT_EXCEEDED)
                for member in action.archive_members:
                    if _path_reason(member.member_path) is not None:
                        risks.add(ArtifactRisk.ARCHIVE_TRAVERSAL)
                    if member.member_type == ArchiveMemberType.SYMLINK and _link_escapes(member.member_path, member.link_target):
                        risks.add(ArtifactRisk.ARCHIVE_LINK_ESCAPE)
                    if member.member_type == ArchiveMemberType.HARDLINK and _link_escapes(member.member_path, member.link_target):
                        risks.add(ArtifactRisk.ARCHIVE_LINK_ESCAPE)

            source_trusts = [current_trust[source_id] for source_id in action.source_artifact_ids]
            if source_trusts and any(t in {ArtifactTrust.UNTRUSTED_INPUT, ArtifactTrust.GENERATED} for t in source_trusts):
                if action.proposed_trust in {ArtifactTrust.VERIFIED, ArtifactTrust.TRUSTED_CONTROL}:
                    risks.add(ArtifactRisk.GENERATED_CODE_LAUNDERING)

            control_path = any(_under(action.target_relative_path, p) for p in self.policy.control_path_prefixes)
            dependency_path = any(_under(action.target_relative_path, p) for p in self.policy.dependency_path_prefixes)
            if control_path and not approval_ok:
                risks.add(ArtifactRisk.CONTROL_PATH_PERSISTENCE)
            if dependency_path and not approval_ok:
                risks.add(ArtifactRisk.DEPENDENCY_PERSISTENCE)
            if any(_under(action.target_relative_path, p) for p in workspace.build_context_prefixes):
                if action.proposed_trust in {ArtifactTrust.UNTRUSTED_INPUT, ArtifactTrust.GENERATED} and not approval_ok:
                    risks.add(ArtifactRisk.BUILD_CONTEXT_POISONING)
            if action.proposed_executable:
                execute_path_ok = any(_under(action.target_relative_path, prefix) for prefix in workspace.allowed_execute_prefixes)
                if not approval_ok or not execute_path_ok:
                    risks.add(ArtifactRisk.EXECUTABLE_WRITE)
            if action.operation == ArtifactOperation.EXECUTE and not approval_ok:
                risks.add(ArtifactRisk.EXECUTION_UNAPPROVED)

            ordered_risks = tuple(sorted(risks, key=lambda r: r.value))
            decision = ArtifactDecision.DENY if ordered_risks else ArtifactDecision.ALLOW
            result_sha = current_sha[action.artifact_id]
            if decision == ArtifactDecision.ALLOW and action.operation in {
                ArtifactOperation.CREATE,
                ArtifactOperation.MODIFY,
                ArtifactOperation.EXTRACT,
                ArtifactOperation.DELETE,
                ArtifactOperation.PUBLISH,
            }:
                result_sha = action.proposed_content_sha256.casefold()
                current_sha[action.artifact_id] = result_sha
                current_trust[action.artifact_id] = action.proposed_trust

            facts.append(
                ArtifactActionFact(
                    action_id=action.action_id,
                    artifact_id=action.artifact_id,
                    operation=action.operation,
                    decision=decision,
                    risks=ordered_risks,
                    target_relative_path=action.target_relative_path,
                    resulting_content_sha256=result_sha,
                    proposed_kind=action.proposed_kind,
                    proposed_trust=action.proposed_trust,
                    proposed_executable=action.proposed_executable,
                    risk_score=max((_RISK_SCORE[r] for r in ordered_risks), default=0),
                )
            )

        return tuple(facts), current_sha

    def evaluate(
        self,
        request: AgentArtifactRequest,
        manifest: AgentArtifactManifest,
        p8c: object,
        p8f: object,
        p8h: object,
    ) -> VerifiedAgentArtifactAssessment:
        p = self.policy
        if (
            request.graph_id != p.expected_graph_id
            or request.graph_version != p.expected_graph_version
            or request.graph_sha256.casefold() != p.expected_graph_sha256.casefold()
        ):
            _reject(ArtifactRejectReason.REQUEST_INVALID, "request graph binding invalid")
        if (
            request.p8c_assessment_evidence_sha256.casefold() != p.expected_p8c_assessment_evidence_sha256.casefold()
            or request.p8f_assessment_evidence_sha256.casefold() != p.expected_p8f_assessment_evidence_sha256.casefold()
            or request.p8h_assessment_evidence_sha256.casefold() != p.expected_p8h_assessment_evidence_sha256.casefold()
        ):
            _reject(ArtifactRejectReason.REQUEST_INVALID, "request upstream binding invalid")
        if tuple(request.action_ids) != tuple(a.action_id for a in manifest.actions):
            _reject(ArtifactRejectReason.COVERAGE_MISMATCH, "request action coverage/order mismatch")

        facts, results = self.derive(manifest, p8c, p8f, p8h, request.evaluated_at_epoch)
        denied = tuple(f.action_id for f in facts if f.decision == ArtifactDecision.DENY)
        if tuple(request.declared_denied_action_ids) != denied:
            _reject(ArtifactRejectReason.DECLARED_DECISION_MISMATCH, "declared denied actions disagree with derived evidence")
        derived_risks = {f.action_id: f.risks for f in facts}
        declared_risks = {k: tuple(v) for k, v in request.declared_risks_by_action.items() if tuple(v)}
        expected_risks = {k: v for k, v in derived_risks.items() if v}
        if declared_risks != expected_risks:
            _reject(ArtifactRejectReason.DECLARED_RISK_MISMATCH, "declared risks disagree with derived evidence")
        declared_results = {k: v.casefold() for k, v in request.declared_result_sha256_by_artifact.items()}
        if declared_results != results:
            _reject(ArtifactRejectReason.DECLARED_RESULT_MISMATCH, "declared artifact results disagree with derived evidence")

        path_link = {
            ArtifactRisk.ABSOLUTE_PATH,
            ArtifactRisk.PATH_ESCAPE,
            ArtifactRisk.OUT_OF_SCOPE_WRITE,
            ArtifactRisk.SYMLINK_ESCAPE,
            ArtifactRisk.HARDLINK_ESCAPE,
        }
        archive = {ArtifactRisk.ARCHIVE_TRAVERSAL, ArtifactRisk.ARCHIVE_LINK_ESCAPE, ArtifactRisk.ARCHIVE_LIMIT_EXCEEDED}
        persistence = {
            ArtifactRisk.DEPENDENCY_PERSISTENCE,
            ArtifactRisk.CONTROL_PATH_PERSISTENCE,
            ArtifactRisk.BUILD_CONTEXT_POISONING,
            ArtifactRisk.GENERATED_CODE_LAUNDERING,
        }
        executable = {ArtifactRisk.EXECUTABLE_WRITE, ArtifactRisk.EXECUTION_UNAPPROVED}
        provenance = {ArtifactRisk.PROVENANCE_MISSING, ArtifactRisk.PROVENANCE_MISMATCH, ArtifactRisk.GENERATED_CODE_LAUNDERING}
        upstream = {ArtifactRisk.UPSTREAM_PLAN_UNSAFE, ArtifactRisk.UPSTREAM_APPROVAL_UNSAFE, ArtifactRisk.UPSTREAM_STATE_UNSAFE}

        return VerifiedAgentArtifactAssessment(
            graph_id=request.graph_id,
            graph_version=request.graph_version,
            graph_sha256=request.graph_sha256.casefold(),
            p8c_assessment_evidence_sha256=request.p8c_assessment_evidence_sha256.casefold(),
            p8f_assessment_evidence_sha256=request.p8f_assessment_evidence_sha256.casefold(),
            p8h_assessment_evidence_sha256=request.p8h_assessment_evidence_sha256.casefold(),
            action_count=len(facts),
            allowed_action_count=sum(f.decision == ArtifactDecision.ALLOW for f in facts),
            denied_action_count=sum(f.decision == ArtifactDecision.DENY for f in facts),
            path_or_link_denial_count=sum(bool(set(f.risks) & path_link) for f in facts),
            archive_denial_count=sum(bool(set(f.risks) & archive) for f in facts),
            persistence_denial_count=sum(bool(set(f.risks) & persistence) for f in facts),
            executable_denial_count=sum(bool(set(f.risks) & executable) for f in facts),
            provenance_denial_count=sum(bool(set(f.risks) & provenance) for f in facts),
            upstream_safety_denial_count=sum(bool(set(f.risks) & upstream) for f in facts),
            maximum_risk_score=max((f.risk_score for f in facts), default=0),
            resulting_sha256_by_artifact=dict(sorted(results.items())),
            actions=facts,
            assessment_evidence_sha256=_assessment_digest(facts, manifest, results),
        )
