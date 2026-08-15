from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace

from aegis.agentic.recovery_security import (
    AgentRecoveryManifest,
    AgentRecoveryPolicy,
    AgentRecoveryRequest,
    AgentRollbackRecoverySecurityAnalyzer,
    CheckpointTrust,
    PersistenceState,
    RecoveryAuthorization,
    RecoveryCheckpoint,
    RecoveryDecision,
    RecoveryItem,
    RecoveryItemKind,
    RecoveryMode,
    RecoveryOperation,
    agent_recovery_manifest_digest,
)

NOW = 1_786_798_400
GRAPH_ID = "aegis-agent-recovery-persistence-graph"
GRAPH_VERSION = "1"
OWNER = "platform-security"
TENANT = "tenant-A"
SESSION = "session-a"
PRINCIPAL = "user-a"

P8B_DIGEST = hashlib.sha256(b"p8b-recovery-evidence").hexdigest()
P8I_DIGEST = hashlib.sha256(b"p8i-recovery-evidence").hexdigest()
P8H_DIGEST = hashlib.sha256(b"p8h-recovery-evidence").hexdigest()


def sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


ITEM_IDS = (
    "item-state-task",
    "item-memory-current",
    "item-artifact-config",
    "item-policy-state",
    "item-message-safe",
    "item-message-rejected",
    "item-credential-stale",
    "item-artifact-poisoned",
)
CHECKPOINT_IDS = ("checkpoint-root", "checkpoint-safe-1", "checkpoint-safe-2", "checkpoint-compromised")
AUTHORIZATION_IDS = ("authorization-rollback", "authorization-restore")
RECOVERY_IDS = ("recovery-safe-resume", "recovery-compromise-rollback", "recovery-safe-restore")

SAFE_TARGET_ITEMS = (
    "item-state-task",
    "item-memory-current",
    "item-artifact-config",
    "item-policy-state",
    "item-message-safe",
)


def make_upstreams(
    *,
    p8b_digest=P8B_DIGEST,
    p8i_digest=P8I_DIGEST,
    p8h_digest=P8H_DIGEST,
    verified=True,
    memory_allowed=True,
    artifact_allowed=True,
    state_allowed=True,
):
    return {
        "p8b": SimpleNamespace(
            assessment_evidence_sha256=p8b_digest,
            exact_memory_graph_binding_verified=verified,
            revocation_and_supersession_enforced=verified,
            caller_declared_memory_safety_trusted=False,
            writes=(
                SimpleNamespace(memory_id="memory-current", decision="allow" if memory_allowed else "deny"),
            ),
            retrievals=(),
        ),
        "p8i": SimpleNamespace(
            assessment_evidence_sha256=p8i_digest,
            exact_artifact_graph_binding_verified=verified,
            sensitive_persistence_paths_checked=verified,
            caller_declared_artifact_safety_trusted=False,
            actions=(
                SimpleNamespace(artifact_id="artifact-config", decision="allow" if artifact_allowed else "deny"),
                SimpleNamespace(artifact_id="artifact-poisoned", decision="deny"),
            ),
        ),
        "p8h": SimpleNamespace(
            assessment_evidence_sha256=p8h_digest,
            exact_state_transition_graph_binding_verified=verified,
            cancellation_and_rollback_races_checked=verified,
            caller_declared_state_safety_trusted=False,
            transitions=(
                SimpleNamespace(object_id="state-task", decision="allow" if state_allowed else "deny"),
                SimpleNamespace(object_id="state-policy", decision="allow" if state_allowed else "deny"),
            ),
        ),
    }


def _items() -> tuple[RecoveryItem, ...]:
    return (
        RecoveryItem("item-state-task", RecoveryItemKind.TASK_STATE, TENANT, SESSION, PRINCIPAL, "state-task", sha("state-task-v3"), 0, PersistenceState.ACTIVE, NOW - 600, OWNER, "Task state at recovery root."),
        RecoveryItem("item-memory-current", RecoveryItemKind.MEMORY, TENANT, SESSION, PRINCIPAL, "memory-current", sha("memory-current"), 1, PersistenceState.ACTIVE, NOW - 500, OWNER, "Current tenant memory state."),
        RecoveryItem("item-artifact-config", RecoveryItemKind.ARTIFACT, TENANT, SESSION, PRINCIPAL, "artifact-config", sha("artifact-config"), 2, PersistenceState.ACTIVE, NOW - 400, OWNER, "Verified generated configuration artifact."),
        RecoveryItem("item-policy-state", RecoveryItemKind.POLICY_STATE, TENANT, SESSION, PRINCIPAL, "state-policy", sha("policy-state-v12"), 2, PersistenceState.ACTIVE, NOW - 390, OWNER, "Authorization policy state."),
        RecoveryItem("item-message-safe", RecoveryItemKind.MESSAGE, TENANT, SESSION, PRINCIPAL, "message-safe", sha("message-safe"), 2, PersistenceState.ACTIVE, NOW - 380, OWNER, "Safe persisted coordination message."),
        RecoveryItem("item-message-rejected", RecoveryItemKind.MESSAGE, TENANT, SESSION, PRINCIPAL, "message-rejected", sha("message-rejected"), 3, PersistenceState.QUARANTINED, NOW - 220, OWNER, "Rejected message retained only for quarantine evidence."),
        RecoveryItem("item-credential-stale", RecoveryItemKind.CREDENTIAL, TENANT, SESSION, PRINCIPAL, "credential-stale", sha("credential-stale"), 3, PersistenceState.REVOKED, NOW - 210, OWNER, "Revoked credential material must never be restored."),
        RecoveryItem("item-artifact-poisoned", RecoveryItemKind.ARTIFACT, TENANT, SESSION, PRINCIPAL, "artifact-poisoned", sha("artifact-poisoned"), 3, PersistenceState.QUARANTINED, NOW - 200, OWNER, "Rejected generated artifact retained for forensic evidence."),
    )


def _checkpoints() -> tuple[RecoveryCheckpoint, ...]:
    return (
        RecoveryCheckpoint("checkpoint-root", TENANT, SESSION, PRINCIPAL, None, 0, sha("checkpoint-root"), ("item-state-task",), CheckpointTrust.TRUSTED, NOW - 590, NOW + 7200, OWNER, "Trusted recovery root."),
        RecoveryCheckpoint("checkpoint-safe-1", TENANT, SESSION, PRINCIPAL, "checkpoint-root", 1, sha("checkpoint-safe-1"), ("item-state-task", "item-memory-current"), CheckpointTrust.TRUSTED, NOW - 480, NOW + 7200, OWNER, "Trusted checkpoint after memory commit."),
        RecoveryCheckpoint("checkpoint-safe-2", TENANT, SESSION, PRINCIPAL, "checkpoint-safe-1", 2, sha("checkpoint-safe-2"), SAFE_TARGET_ITEMS, CheckpointTrust.TRUSTED, NOW - 350, NOW + 7200, OWNER, "Last known-good checkpoint."),
        RecoveryCheckpoint("checkpoint-compromised", TENANT, SESSION, PRINCIPAL, "checkpoint-safe-2", 3, sha("checkpoint-compromised"), SAFE_TARGET_ITEMS + ("item-message-rejected", "item-credential-stale", "item-artifact-poisoned"), CheckpointTrust.COMPROMISED, NOW - 180, NOW + 7200, OWNER, "Compromised checkpoint retained for rollback source evidence."),
    )


def _authorizations() -> tuple[RecoveryAuthorization, ...]:
    all_rollback_items = frozenset(SAFE_TARGET_ITEMS + ("item-message-rejected", "item-credential-stale", "item-artifact-poisoned"))
    return (
        RecoveryAuthorization("authorization-rollback", "agent-recovery", PRINCIPAL, TENANT, frozenset({RecoveryMode.ROLLBACK}), all_rollback_items, 2, True, NOW - 60, NOW + 600, OWNER, "Bound authorization for compromised-state rollback."),
        RecoveryAuthorization("authorization-restore", "agent-recovery", PRINCIPAL, TENANT, frozenset({RecoveryMode.RESTORE}), frozenset(SAFE_TARGET_ITEMS), 0, False, NOW - 60, NOW + 600, OWNER, "Bound authorization for safe checkpoint restore."),
    )


def _recoveries() -> tuple[RecoveryOperation, ...]:
    return (
        RecoveryOperation("recovery-safe-resume", RecoveryMode.RESUME, "agent-orchestrator", PRINCIPAL, TENANT, SESSION, "checkpoint-safe-2", "checkpoint-safe-2", SAFE_TARGET_ITEMS, (), (), None, sha("checkpoint-safe-2"), sha("checkpoint-safe-2"), NOW - 20, OWNER, "Resume exact last-known-good state."),
        RecoveryOperation("recovery-compromise-rollback", RecoveryMode.ROLLBACK, "agent-recovery", PRINCIPAL, TENANT, SESSION, "checkpoint-compromised", "checkpoint-safe-2", SAFE_TARGET_ITEMS, ("item-message-rejected", "item-artifact-poisoned"), ("item-credential-stale",), "authorization-rollback", sha("checkpoint-compromised"), sha("checkpoint-safe-2"), NOW - 15, OWNER, "Rollback compromised state while quarantining and revoking source-only persistence."),
        RecoveryOperation("recovery-safe-restore", RecoveryMode.RESTORE, "agent-recovery", PRINCIPAL, TENANT, SESSION, "checkpoint-safe-1", "checkpoint-safe-2", SAFE_TARGET_ITEMS, (), (), "authorization-restore", sha("checkpoint-safe-1"), sha("checkpoint-safe-2"), NOW - 10, OWNER, "Restore a trusted newer checkpoint from durable backup material."),
    )


def build_manifest() -> AgentRecoveryManifest:
    return AgentRecoveryManifest(
        graph_id=GRAPH_ID,
        version=GRAPH_VERSION,
        p8b_assessment_evidence_sha256=P8B_DIGEST,
        p8i_assessment_evidence_sha256=P8I_DIGEST,
        p8h_assessment_evidence_sha256=P8H_DIGEST,
        created_at_epoch=NOW - 30,
        items=_items(),
        checkpoints=_checkpoints(),
        authorizations=_authorizations(),
        recoveries=_recoveries(),
    )


def build_policy(manifest: AgentRecoveryManifest) -> AgentRecoveryPolicy:
    return AgentRecoveryPolicy(
        expected_graph_id=GRAPH_ID,
        expected_graph_version=GRAPH_VERSION,
        expected_graph_sha256=agent_recovery_manifest_digest(manifest),
        expected_p8b_assessment_evidence_sha256=P8B_DIGEST,
        expected_p8i_assessment_evidence_sha256=P8I_DIGEST,
        expected_p8h_assessment_evidence_sha256=P8H_DIGEST,
        required_item_ids=frozenset(ITEM_IDS),
        required_checkpoint_ids=frozenset(CHECKPOINT_IDS),
        required_authorization_ids=frozenset(AUTHORIZATION_IDS),
        required_recovery_ids=frozenset(RECOVERY_IDS),
        trusted_owner_ids=frozenset({OWNER}),
        expected_item_profiles={
            item.item_id: (
                item.kind,
                item.tenant_id,
                item.session_id,
                item.original_principal_id,
                item.source_ref_id,
                item.content_sha256,
                item.generation,
                item.persistence_state,
            )
            for item in manifest.items
        },
        expected_checkpoint_profiles={
            cp.checkpoint_id: (
                cp.tenant_id,
                cp.session_id,
                cp.original_principal_id,
                cp.parent_checkpoint_id,
                cp.generation,
                cp.state_sha256,
                cp.item_ids,
                cp.trust,
            )
            for cp in manifest.checkpoints
        },
        recovery_floor_generation_by_tenant={TENANT: 1},
        non_restorable_item_ids=frozenset({"item-message-rejected", "item-artifact-poisoned"}),
        credential_refresh_required_item_ids=frozenset({"item-credential-stale"}),
        authorization_required_modes=frozenset({RecoveryMode.ROLLBACK, RecoveryMode.RESTORE}),
        destructive_modes=frozenset({RecoveryMode.ROLLBACK}),
    )


def build_request(manifest: AgentRecoveryManifest, policy: AgentRecoveryPolicy, upstreams: dict[str, object]) -> AgentRecoveryRequest:
    analyzer = AgentRollbackRecoverySecurityAnalyzer(policy)
    facts = analyzer.derive(manifest, upstreams["p8b"], upstreams["p8i"], upstreams["p8h"], NOW)
    return AgentRecoveryRequest(
        graph_id=GRAPH_ID,
        graph_version=GRAPH_VERSION,
        graph_sha256=policy.expected_graph_sha256,
        p8b_assessment_evidence_sha256=P8B_DIGEST,
        p8i_assessment_evidence_sha256=P8I_DIGEST,
        p8h_assessment_evidence_sha256=P8H_DIGEST,
        evaluated_at_epoch=NOW,
        recovery_ids=RECOVERY_IDS,
        declared_denied_recovery_ids=tuple(f.recovery_id for f in facts if f.decision == RecoveryDecision.DENY),
        declared_risks_by_recovery={f.recovery_id: f.risks for f in facts},
        declared_target_checkpoint_by_recovery={f.recovery_id: f.target_checkpoint_id for f in facts},
    )


def build_fixture() -> dict[str, object]:
    manifest = build_manifest()
    policy = build_policy(manifest)
    upstreams = make_upstreams()
    request = build_request(manifest, policy, upstreams)
    return {"manifest": manifest, "policy": policy, "request": request, **upstreams}


def with_manifest(fixture: dict[str, object], manifest: AgentRecoveryManifest) -> dict[str, object]:
    policy = replace(fixture["policy"], expected_graph_sha256=agent_recovery_manifest_digest(manifest))
    upstreams = {"p8b": fixture["p8b"], "p8i": fixture["p8i"], "p8h": fixture["p8h"]}
    request = build_request(manifest, policy, upstreams)
    return {"manifest": manifest, "policy": policy, "request": request, **upstreams}
