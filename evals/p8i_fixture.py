from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace

from aegis.agentic.artifact_security import (
    AgentArtifactManifest,
    AgentArtifactPolicy,
    AgentArtifactRequest,
    AgentArtifactWorkspaceSecurityAnalyzer,
    ArchiveMember,
    ArchiveMemberType,
    ArtifactAction,
    ArtifactKind,
    ArtifactOperation,
    ArtifactTrust,
    WorkspaceArtifact,
    WorkspaceRoot,
    agent_artifact_manifest_digest,
)

NOW = 1_786_797_600
GRAPH_ID = "aegis-agent-artifact-workspace-graph"
GRAPH_VERSION = "1"
OWNER = "platform-security"

P8C_DIGEST = hashlib.sha256(b"p8c-artifact-evidence").hexdigest()
P8F_DIGEST = hashlib.sha256(b"p8f-artifact-evidence").hexdigest()
P8H_DIGEST = hashlib.sha256(b"p8h-artifact-evidence").hexdigest()


def sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


WORKSPACE_IDS = ("workspace-tenant-a", "workspace-repo")
ARTIFACT_IDS = (
    "artifact-generated-source",
    "artifact-dependency-manifest",
    "artifact-lockfile",
    "artifact-ci",
    "artifact-startup",
    "artifact-archive",
    "artifact-release",
    "artifact-build-config",
    "artifact-document",
)
ACTION_IDS = (
    "artifact-action-source",
    "artifact-action-deps",
    "artifact-action-lock",
    "artifact-action-ci",
    "artifact-action-startup-modify",
    "artifact-action-archive-extract",
    "artifact-action-release-publish",
    "artifact-action-startup-execute",
    "artifact-action-build",
)

SENSITIVE_APPROVAL_IDS = (
    "approval-deps",
    "approval-lock",
    "approval-ci",
    "approval-startup-modify",
    "approval-release",
    "approval-startup-execute",
    "approval-build",
)


def make_upstreams(
    *,
    denied_steps=frozenset(),
    denied_approvals=frozenset(),
    denied_transitions=frozenset(),
    p8c_digest=P8C_DIGEST,
    p8f_digest=P8F_DIGEST,
    p8h_digest=P8H_DIGEST,
    verified=True,
):
    step_specs = (
        ("step-source", "agent-coder"),
        ("step-deps", "agent-release"),
        ("step-lock", "agent-release"),
        ("step-ci", "agent-security"),
        ("step-startup-modify", "agent-security"),
        ("step-archive", "agent-tool"),
        ("step-release", "agent-release"),
        ("step-startup-execute", "agent-security"),
        ("step-build", "agent-release"),
    )
    steps = tuple(
        SimpleNamespace(step_id=sid, agent_id=agent, decision="deny" if sid in denied_steps else "allow")
        for sid, agent in step_specs
    )
    approvals = tuple(
        SimpleNamespace(action_id=aid, outcome="deny" if aid in denied_approvals else "allow")
        for aid in SENSITIVE_APPROVAL_IDS
    )
    transitions = tuple(
        SimpleNamespace(transition_id=f"transition-{suffix}", decision="deny" if f"transition-{suffix}" in denied_transitions else "allow")
        for suffix in (
            "source",
            "deps",
            "lock",
            "ci",
            "startup-modify",
            "archive",
            "release",
            "startup-execute",
            "build",
        )
    )
    return {
        "p8c": SimpleNamespace(
            assessment_evidence_sha256=p8c_digest,
            exact_goal_plan_graph_binding_verified=verified,
            caller_declared_goal_safety_trusted=False,
            steps=steps,
        ),
        "p8f": SimpleNamespace(
            assessment_evidence_sha256=p8f_digest,
            exact_human_approval_graph_binding_verified=verified,
            caller_declared_approval_safety_trusted=False,
            actions=approvals,
        ),
        "p8h": SimpleNamespace(
            assessment_evidence_sha256=p8h_digest,
            exact_state_transition_graph_binding_verified=verified,
            caller_declared_state_safety_trusted=False,
            transitions=transitions,
        ),
    }


def _workspaces() -> tuple[WorkspaceRoot, ...]:
    return (
        WorkspaceRoot(
            "workspace-tenant-a",
            "tenant-A",
            "/workspaces/tenant-a",
            ("src/generated", "scratch"),
            ("src/generated",),
            ("build/context",),
            OWNER,
            "Tenant-A agent workspace with confined generated-source and scratch paths.",
        ),
        WorkspaceRoot(
            "workspace-repo",
            "platform",
            "/repo",
            (
                "pyproject.toml",
                "requirements.lock",
                ".github/workflows",
                "scripts",
                "incoming",
                "scratch",
                "dist",
                "Dockerfile",
                "docs",
            ),
            ("scripts", "dist"),
            ("build/context",),
            OWNER,
            "Repository workspace with explicit control, release, and scratch paths.",
        ),
    )


def _artifacts() -> tuple[WorkspaceArtifact, ...]:
    return (
        WorkspaceArtifact("artifact-generated-source", "workspace-tenant-a", "tenant-A", "src/generated/summary.py", ArtifactKind.SOURCE, ArtifactTrust.GENERATED, sha("source-v1"), False, None, None, OWNER, "Generated tenant source file."),
        WorkspaceArtifact("artifact-dependency-manifest", "workspace-repo", "platform", "pyproject.toml", ArtifactKind.DEPENDENCY_MANIFEST, ArtifactTrust.TRUSTED_CONTROL, sha("deps-v1"), False, None, None, OWNER, "Python dependency manifest."),
        WorkspaceArtifact("artifact-lockfile", "workspace-repo", "platform", "requirements.lock", ArtifactKind.LOCKFILE, ArtifactTrust.TRUSTED_CONTROL, sha("lock-v1"), False, None, None, OWNER, "Pinned dependency lock state."),
        WorkspaceArtifact("artifact-ci", "workspace-repo", "platform", ".github/workflows/ci.yml", ArtifactKind.CI_WORKFLOW, ArtifactTrust.TRUSTED_CONTROL, sha("ci-v1"), False, None, None, OWNER, "CI workflow control file."),
        WorkspaceArtifact("artifact-startup", "workspace-repo", "platform", "scripts/startup.sh", ArtifactKind.STARTUP_HOOK, ArtifactTrust.TRUSTED_CONTROL, sha("startup-v1"), True, None, None, OWNER, "Startup hook executable."),
        WorkspaceArtifact("artifact-archive", "workspace-repo", "platform", "incoming/bundle.tar", ArtifactKind.ARCHIVE, ArtifactTrust.UNTRUSTED_INPUT, sha("archive-v1"), False, None, None, OWNER, "Untrusted inbound archive."),
        WorkspaceArtifact("artifact-release", "workspace-repo", "platform", "dist/model.tar", ArtifactKind.MODEL_ARTIFACT, ArtifactTrust.VERIFIED, sha("release-v1"), False, None, None, OWNER, "Verified release artifact."),
        WorkspaceArtifact("artifact-build-config", "workspace-repo", "platform", "Dockerfile", ArtifactKind.BUILD_CONFIG, ArtifactTrust.TRUSTED_CONTROL, sha("build-v1"), False, None, None, OWNER, "Build configuration."),
        WorkspaceArtifact("artifact-document", "workspace-repo", "platform", "docs/generated-report.md", ArtifactKind.DOCUMENT, ArtifactTrust.GENERATED, sha("doc-v1"), False, None, None, OWNER, "Generated report document."),
    )


def _action(
    action_id: str,
    artifact_id: str,
    operation: ArtifactOperation,
    agent: str,
    principal: str,
    tenant: str,
    step: str,
    approval: str | None,
    transition: str,
    target: str,
    base: str,
    proposed: str,
    kind: ArtifactKind,
    trust: ArtifactTrust,
    executable: bool,
    *,
    archive_members: tuple[ArchiveMember, ...] = (),
) -> ArtifactAction:
    return ArtifactAction(
        action_id=action_id,
        artifact_id=artifact_id,
        operation=operation,
        actor_agent_id=agent,
        original_principal_id=principal,
        tenant_id=tenant,
        plan_step_id=step,
        approval_action_id=approval,
        state_transition_id=transition,
        message_id=f"message-{action_id}",
        target_relative_path=target,
        expected_base_sha256=sha(base),
        proposed_content_sha256=sha(proposed),
        source_artifact_ids=(),
        source_request_sha256=sha(f"request-{action_id}"),
        patch_sha256=sha(f"patch-{action_id}"),
        proposed_kind=kind,
        proposed_trust=trust,
        proposed_executable=executable,
        proposed_symlink_target=None,
        proposed_hardlink_target=None,
        archive_members=archive_members,
        issued_at_epoch=NOW - 60,
        owner_id=OWNER,
        description=f"Canonical {action_id}.",
    )


def _actions() -> tuple[ArtifactAction, ...]:
    safe_members = (
        ArchiveMember("model/config.json", ArchiveMemberType.FILE, 512),
        ArchiveMember("model/weights.bin", ArchiveMemberType.FILE, 4096),
        ArchiveMember("README.md", ArchiveMemberType.FILE, 128),
    )
    return (
        _action("artifact-action-source", "artifact-generated-source", ArtifactOperation.MODIFY, "agent-coder", "user-a", "tenant-A", "step-source", None, "transition-source", "src/generated/summary.py", "source-v1", "source-v2", ArtifactKind.SOURCE, ArtifactTrust.GENERATED, False),
        _action("artifact-action-deps", "artifact-dependency-manifest", ArtifactOperation.MODIFY, "agent-release", "release-admin", "platform", "step-deps", "approval-deps", "transition-deps", "pyproject.toml", "deps-v1", "deps-v2", ArtifactKind.DEPENDENCY_MANIFEST, ArtifactTrust.TRUSTED_CONTROL, False),
        _action("artifact-action-lock", "artifact-lockfile", ArtifactOperation.MODIFY, "agent-release", "release-admin", "platform", "step-lock", "approval-lock", "transition-lock", "requirements.lock", "lock-v1", "lock-v2", ArtifactKind.LOCKFILE, ArtifactTrust.TRUSTED_CONTROL, False),
        _action("artifact-action-ci", "artifact-ci", ArtifactOperation.MODIFY, "agent-security", "security-admin", "platform", "step-ci", "approval-ci", "transition-ci", ".github/workflows/ci.yml", "ci-v1", "ci-v2", ArtifactKind.CI_WORKFLOW, ArtifactTrust.TRUSTED_CONTROL, False),
        _action("artifact-action-startup-modify", "artifact-startup", ArtifactOperation.MODIFY, "agent-security", "security-admin", "platform", "step-startup-modify", "approval-startup-modify", "transition-startup-modify", "scripts/startup.sh", "startup-v1", "startup-v2", ArtifactKind.STARTUP_HOOK, ArtifactTrust.TRUSTED_CONTROL, True),
        _action("artifact-action-archive-extract", "artifact-archive", ArtifactOperation.EXTRACT, "agent-tool", "release-admin", "platform", "step-archive", None, "transition-archive", "scratch/extracted", "archive-v1", "archive-extracted-v1", ArtifactKind.ARCHIVE, ArtifactTrust.UNTRUSTED_INPUT, False, archive_members=safe_members),
        _action("artifact-action-release-publish", "artifact-release", ArtifactOperation.PUBLISH, "agent-release", "release-admin", "platform", "step-release", "approval-release", "transition-release", "dist/model.tar", "release-v1", "release-v2", ArtifactKind.MODEL_ARTIFACT, ArtifactTrust.VERIFIED, False),
        _action("artifact-action-startup-execute", "artifact-startup", ArtifactOperation.EXECUTE, "agent-security", "security-admin", "platform", "step-startup-execute", "approval-startup-execute", "transition-startup-execute", "scripts/startup.sh", "startup-v2", "startup-v2", ArtifactKind.STARTUP_HOOK, ArtifactTrust.TRUSTED_CONTROL, True),
        _action("artifact-action-build", "artifact-build-config", ArtifactOperation.MODIFY, "agent-release", "release-admin", "platform", "step-build", "approval-build", "transition-build", "Dockerfile", "build-v1", "build-v2", ArtifactKind.BUILD_CONFIG, ArtifactTrust.TRUSTED_CONTROL, False),
    )


def _allowed_operations():
    return {
        ArtifactKind.SOURCE: frozenset({ArtifactOperation.CREATE, ArtifactOperation.MODIFY, ArtifactOperation.DELETE, ArtifactOperation.EXECUTE}),
        ArtifactKind.PATCH: frozenset({ArtifactOperation.CREATE, ArtifactOperation.MODIFY}),
        ArtifactKind.DEPENDENCY_MANIFEST: frozenset({ArtifactOperation.MODIFY}),
        ArtifactKind.LOCKFILE: frozenset({ArtifactOperation.MODIFY}),
        ArtifactKind.BUILD_CONFIG: frozenset({ArtifactOperation.MODIFY}),
        ArtifactKind.CI_WORKFLOW: frozenset({ArtifactOperation.MODIFY}),
        ArtifactKind.STARTUP_HOOK: frozenset({ArtifactOperation.MODIFY, ArtifactOperation.EXECUTE}),
        ArtifactKind.ARCHIVE: frozenset({ArtifactOperation.EXTRACT, ArtifactOperation.MODIFY}),
        ArtifactKind.EXECUTABLE: frozenset({ArtifactOperation.CREATE, ArtifactOperation.MODIFY, ArtifactOperation.EXECUTE, ArtifactOperation.PUBLISH}),
        ArtifactKind.MODEL_ARTIFACT: frozenset({ArtifactOperation.PUBLISH, ArtifactOperation.MODIFY}),
        ArtifactKind.DOCUMENT: frozenset({ArtifactOperation.CREATE, ArtifactOperation.MODIFY, ArtifactOperation.DELETE}),
    }


def build_fixture():
    upstreams = make_upstreams()
    manifest = AgentArtifactManifest(
        graph_id=GRAPH_ID,
        version=GRAPH_VERSION,
        p8c_assessment_evidence_sha256=P8C_DIGEST,
        p8f_assessment_evidence_sha256=P8F_DIGEST,
        p8h_assessment_evidence_sha256=P8H_DIGEST,
        created_at_epoch=NOW - 120,
        workspaces=_workspaces(),
        artifacts=_artifacts(),
        actions=_actions(),
    )
    graph_sha = agent_artifact_manifest_digest(manifest)
    workspace_profiles = {
        w.workspace_id: (
            w.tenant_id,
            w.root_path,
            w.allowed_write_prefixes,
            w.allowed_execute_prefixes,
            w.build_context_prefixes,
        )
        for w in manifest.workspaces
    }
    artifact_profiles = {
        a.artifact_id: (
            a.workspace_id,
            a.tenant_id,
            a.relative_path,
            a.kind,
            a.trust,
            a.content_sha256,
            a.executable,
            a.symlink_target,
            a.hardlink_target,
        )
        for a in manifest.artifacts
    }
    allowed_kinds = {
        "workspace-tenant-a": frozenset({ArtifactKind.SOURCE, ArtifactKind.DOCUMENT, ArtifactKind.ARCHIVE}),
        "workspace-repo": frozenset({
            ArtifactKind.SOURCE,
            ArtifactKind.PATCH,
            ArtifactKind.DEPENDENCY_MANIFEST,
            ArtifactKind.LOCKFILE,
            ArtifactKind.BUILD_CONFIG,
            ArtifactKind.CI_WORKFLOW,
            ArtifactKind.STARTUP_HOOK,
            ArtifactKind.ARCHIVE,
            ArtifactKind.EXECUTABLE,
            ArtifactKind.MODEL_ARTIFACT,
            ArtifactKind.DOCUMENT,
        }),
    }
    policy = AgentArtifactPolicy(
        expected_graph_id=GRAPH_ID,
        expected_graph_version=GRAPH_VERSION,
        expected_graph_sha256=graph_sha,
        expected_p8c_assessment_evidence_sha256=P8C_DIGEST,
        expected_p8f_assessment_evidence_sha256=P8F_DIGEST,
        expected_p8h_assessment_evidence_sha256=P8H_DIGEST,
        required_workspace_ids=frozenset(WORKSPACE_IDS),
        required_artifact_ids=frozenset(ARTIFACT_IDS),
        required_action_ids=frozenset(ACTION_IDS),
        trusted_owner_ids=frozenset({OWNER}),
        expected_workspace_profiles=workspace_profiles,
        expected_artifact_profiles=artifact_profiles,
        allowed_operations_by_kind=_allowed_operations(),
        allowed_kinds_by_workspace=allowed_kinds,
        approval_required_kinds=frozenset({ArtifactKind.DEPENDENCY_MANIFEST, ArtifactKind.LOCKFILE, ArtifactKind.BUILD_CONFIG, ArtifactKind.CI_WORKFLOW, ArtifactKind.STARTUP_HOOK, ArtifactKind.EXECUTABLE, ArtifactKind.MODEL_ARTIFACT}),
        control_path_prefixes=(".github/workflows", "scripts", "Dockerfile"),
        dependency_path_prefixes=("pyproject.toml", "requirements.lock"),
        state_required_operations=frozenset({ArtifactOperation.MODIFY, ArtifactOperation.DELETE, ArtifactOperation.EXTRACT, ArtifactOperation.EXECUTE, ArtifactOperation.PUBLISH}),
        provenance_required_operations=frozenset({ArtifactOperation.CREATE, ArtifactOperation.MODIFY, ArtifactOperation.EXTRACT, ArtifactOperation.PUBLISH}),
    )
    analyzer = AgentArtifactWorkspaceSecurityAnalyzer(policy)
    facts, results = analyzer.derive(manifest, upstreams["p8c"], upstreams["p8f"], upstreams["p8h"], NOW)
    assert all(f.decision.value == "allow" for f in facts)
    request = AgentArtifactRequest(
        graph_id=GRAPH_ID,
        graph_version=GRAPH_VERSION,
        graph_sha256=graph_sha,
        p8c_assessment_evidence_sha256=P8C_DIGEST,
        p8f_assessment_evidence_sha256=P8F_DIGEST,
        p8h_assessment_evidence_sha256=P8H_DIGEST,
        evaluated_at_epoch=NOW,
        action_ids=ACTION_IDS,
        declared_denied_action_ids=(),
        declared_risks_by_action={},
        declared_result_sha256_by_artifact=dict(sorted(results.items())),
    )
    return {"manifest": manifest, "policy": policy, "request": request, **upstreams}


def rebind_manifest(fixture, manifest, *, upstreams=None):
    upstreams = upstreams or {k: fixture[k] for k in ("p8c", "p8f", "p8h")}
    graph_sha = agent_artifact_manifest_digest(manifest)
    policy = replace(fixture["policy"], expected_graph_sha256=graph_sha)
    analyzer = AgentArtifactWorkspaceSecurityAnalyzer(policy)
    facts, results = analyzer.derive(manifest, upstreams["p8c"], upstreams["p8f"], upstreams["p8h"], fixture["request"].evaluated_at_epoch)
    denied = tuple(f.action_id for f in facts if f.decision.value == "deny")
    risks = {f.action_id: f.risks for f in facts if f.risks}
    request = replace(
        fixture["request"],
        graph_sha256=graph_sha,
        declared_denied_action_ids=denied,
        declared_risks_by_action=risks,
        declared_result_sha256_by_artifact=dict(sorted(results.items())),
    )
    return {**fixture, "manifest": manifest, "policy": policy, "request": request, **upstreams}
