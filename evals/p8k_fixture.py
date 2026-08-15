from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace

from aegis.agentic.incident_forensics_security import (
    ZERO_SHA256,
    AgentIncidentForensicsManifest,
    AgentIncidentForensicsPolicy,
    AgentIncidentForensicsRequest,
    ContainmentAction,
    ContainmentKind,
    ForensicPackage,
    IncidentCase,
    IncidentEvent,
    IncidentEventKind,
    ReentryAuthorization,
    agent_incident_forensics_manifest_digest,
    evidence_scope_digest,
    forensic_package_digest,
    incident_event_digest,
    reconstruction_digest,
)

NOW = 2_000_000_000
GRAPH_ID = "p8k-agent-incident-forensics"
GRAPH_VERSION = "1"

P8G_SHA = hashlib.sha256(b"p8g-clean-assessment").hexdigest()
P8H_SHA = hashlib.sha256(b"p8h-clean-assessment").hexdigest()
P8I_SHA = hashlib.sha256(b"p8i-clean-assessment").hexdigest()
P8J_SHA = hashlib.sha256(b"p8j-clean-assessment").hexdigest()

EVENT_IDS = tuple(f"event-{i}" for i in range(1, 9))
ACTION_IDS = (
    "contain-quarantine-planner",
    "contain-quarantine-worker",
    "contain-isolate-channel",
    "contain-freeze-state",
    "contain-freeze-recovery",
    "contain-revoke-credential",
    "contain-preserve-evidence",
)
PACKAGE_IDS = ("forensic-package-1",)
REENTRY_IDS = ("reentry-planner", "reentry-worker")
INCIDENT_IDS = ("incident-1",)


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _event(
    *,
    event_id: str,
    sequence: int,
    agent_id: str,
    kind: IncidentEventKind,
    object_id: str,
    parent_event_ids: tuple[str, ...],
    previous_event_sha256: str,
    observed_at_epoch: int,
    description: str,
) -> IncidentEvent:
    event = IncidentEvent(
        event_id=event_id,
        sequence=sequence,
        agent_id=agent_id,
        original_principal_id="user-a",
        tenant_id="tenant-A",
        session_id="session-a",
        kind=kind,
        object_id=object_id,
        parent_event_ids=parent_event_ids,
        previous_event_sha256=previous_event_sha256,
        payload_sha256=sha(f"payload:{event_id}"),
        event_sha256=ZERO_SHA256,
        observed_at_epoch=observed_at_epoch,
        owner_id="forensic-recorder",
        description=description,
    )
    return replace(event, event_sha256=incident_event_digest(event))


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


def _upstream(digest: str, *, binding_attr: str, caller_attr: str, collection_attr: str):
    record = SimpleNamespace(decision="allow")
    return SimpleNamespace(
        assessment_evidence_sha256=digest,
        **{
            binding_attr: True,
            caller_attr: False,
            collection_attr: (record,),
        },
    )


def build_fixture() -> dict[str, object]:
    e1 = _event(
        event_id="event-1",
        sequence=1,
        agent_id="agent-planner",
        kind=IncidentEventKind.ALERT,
        object_id="indicator-prompt-injection",
        parent_event_ids=(),
        previous_event_sha256=ZERO_SHA256,
        observed_at_epoch=NOW - 100,
        description="Detection alert anchors the incident.",
    )
    e2 = _event(
        event_id="event-2",
        sequence=2,
        agent_id="agent-planner",
        kind=IncidentEventKind.MESSAGE,
        object_id="channel-ops",
        parent_event_ids=("event-1",),
        previous_event_sha256=e1.event_sha256,
        observed_at_epoch=NOW - 92,
        description="Planner forwards tainted instructions to worker.",
    )
    e3 = _event(
        event_id="event-3",
        sequence=3,
        agent_id="agent-worker",
        kind=IncidentEventKind.MESSAGE,
        object_id="channel-ops",
        parent_event_ids=("event-2",),
        previous_event_sha256=ZERO_SHA256,
        observed_at_epoch=NOW - 84,
        description="Worker receives the tainted message.",
    )
    e4 = _event(
        event_id="event-4",
        sequence=4,
        agent_id="agent-worker",
        kind=IncidentEventKind.ARTIFACT_WRITE,
        object_id="workspace/generated-report.py",
        parent_event_ids=("event-3",),
        previous_event_sha256=e3.event_sha256,
        observed_at_epoch=NOW - 76,
        description="Worker writes a generated executable artifact.",
    )
    e5 = _event(
        event_id="event-5",
        sequence=5,
        agent_id="agent-worker",
        kind=IncidentEventKind.CREDENTIAL_USE,
        object_id="credential-worker-old",
        parent_event_ids=("event-4",),
        previous_event_sha256=e4.event_sha256,
        observed_at_epoch=NOW - 68,
        description="Worker uses a credential after compromise.",
    )
    e6 = _event(
        event_id="event-6",
        sequence=6,
        agent_id="agent-worker",
        kind=IncidentEventKind.STATE_TRANSITION,
        object_id="state-task-42",
        parent_event_ids=("event-5",),
        previous_event_sha256=e5.event_sha256,
        observed_at_epoch=NOW - 60,
        description="Worker mutates task state.",
    )
    e7 = _event(
        event_id="event-7",
        sequence=7,
        agent_id="agent-planner",
        kind=IncidentEventKind.RECOVERY,
        object_id="checkpoint-compromised",
        parent_event_ids=("event-6",),
        previous_event_sha256=e2.event_sha256,
        observed_at_epoch=NOW - 52,
        description="Planner attempts recovery from compromised state.",
    )
    e8 = _event(
        event_id="event-8",
        sequence=8,
        agent_id="agent-planner",
        kind=IncidentEventKind.TOOL_INVOCATION,
        object_id="tool-deploy",
        parent_event_ids=("event-7",),
        previous_event_sha256=e7.event_sha256,
        observed_at_epoch=NOW - 44,
        description="Planner reaches an irreversible tool boundary.",
    )
    events = (e1, e2, e3, e4, e5, e6, e7, e8)
    event_map = {e.event_id: e for e in events}
    scope = EVENT_IDS
    evidence_digest = evidence_scope_digest(event_map, scope)

    actions = (
        ContainmentAction(
            action_id="contain-quarantine-planner",
            incident_id="incident-1",
            kind=ContainmentKind.QUARANTINE_AGENT,
            target_id="agent-planner",
            evidence_event_ids=("event-1", "event-2", "event-7", "event-8"),
            evidence_digest_sha256=sha("planner-quarantine-evidence"),
            issued_at_epoch=NOW - 39,
            owner_id="incident-controller",
            description="Quarantine planner.",
        ),
        ContainmentAction(
            action_id="contain-quarantine-worker",
            incident_id="incident-1",
            kind=ContainmentKind.QUARANTINE_AGENT,
            target_id="agent-worker",
            evidence_event_ids=("event-3", "event-4", "event-5", "event-6"),
            evidence_digest_sha256=sha("worker-quarantine-evidence"),
            issued_at_epoch=NOW - 38,
            owner_id="incident-controller",
            description="Quarantine worker.",
        ),
        ContainmentAction(
            action_id="contain-isolate-channel",
            incident_id="incident-1",
            kind=ContainmentKind.ISOLATE_CHANNEL,
            target_id="channel-ops",
            evidence_event_ids=("event-2", "event-3"),
            evidence_digest_sha256=sha("channel-isolation-evidence"),
            issued_at_epoch=NOW - 37,
            owner_id="incident-controller",
            description="Isolate compromised agent channel.",
        ),
        ContainmentAction(
            action_id="contain-freeze-state",
            incident_id="incident-1",
            kind=ContainmentKind.FREEZE_STATE,
            target_id="state-task-42",
            evidence_event_ids=("event-6",),
            evidence_digest_sha256=sha("state-freeze-evidence"),
            issued_at_epoch=NOW - 36,
            owner_id="incident-controller",
            description="Freeze compromised task state.",
        ),
        ContainmentAction(
            action_id="contain-freeze-recovery",
            incident_id="incident-1",
            kind=ContainmentKind.FREEZE_STATE,
            target_id="checkpoint-compromised",
            evidence_event_ids=("event-7",),
            evidence_digest_sha256=sha("recovery-freeze-evidence"),
            issued_at_epoch=NOW - 35,
            owner_id="incident-controller",
            description="Freeze compromised recovery target.",
        ),
        ContainmentAction(
            action_id="contain-revoke-credential",
            incident_id="incident-1",
            kind=ContainmentKind.REVOKE_CREDENTIAL,
            target_id="credential-worker-old",
            evidence_event_ids=("event-5",),
            evidence_digest_sha256=sha("credential-revocation-evidence"),
            issued_at_epoch=NOW - 34,
            owner_id="incident-controller",
            description="Revoke compromised worker credential.",
        ),
        ContainmentAction(
            action_id="contain-preserve-evidence",
            incident_id="incident-1",
            kind=ContainmentKind.PRESERVE_EVIDENCE,
            target_id="incident-1",
            evidence_event_ids=scope,
            evidence_digest_sha256=evidence_digest,
            issued_at_epoch=NOW - 33,
            owner_id="forensic-recorder",
            description="Preserve complete incident evidence.",
        ),
    )

    package = ForensicPackage(
        package_id="forensic-package-1",
        incident_id="incident-1",
        scope_event_ids=scope,
        reconstruction_event_ids=scope,
        root_event_ids=("event-1",),
        preserved_event_sha256_by_id={event_id: event_map[event_id].event_sha256 for event_id in scope},
        generated_at_epoch=NOW - 25,
        owner_id="forensic-recorder",
        description="Deterministic causal reconstruction package.",
    )
    package_sha = forensic_package_digest(package)

    reentries = (
        ReentryAuthorization(
            reentry_id="reentry-planner",
            incident_id="incident-1",
            agent_id="agent-planner",
            safe_checkpoint_id="checkpoint-safe-2",
            forensic_package_sha256=package_sha,
            replacement_credential_sha256=sha("planner-credential-rotated"),
            minimum_state_version=9,
            issued_at_epoch=NOW - 15,
            not_before_epoch=NOW - 15,
            expires_at_epoch=NOW + 600,
            owner_id="incident-controller",
            description="Controlled planner re-entry.",
        ),
        ReentryAuthorization(
            reentry_id="reentry-worker",
            incident_id="incident-1",
            agent_id="agent-worker",
            safe_checkpoint_id="checkpoint-safe-2",
            forensic_package_sha256=package_sha,
            replacement_credential_sha256=sha("worker-credential-rotated"),
            minimum_state_version=9,
            issued_at_epoch=NOW - 14,
            not_before_epoch=NOW - 14,
            expires_at_epoch=NOW + 600,
            owner_id="incident-controller",
            description="Controlled worker re-entry.",
        ),
    )

    incident = IncidentCase(
        incident_id="incident-1",
        trigger_event_ids=("event-1",),
        containment_action_ids=ACTION_IDS,
        forensic_package_id="forensic-package-1",
        reentry_authorization_ids=REENTRY_IDS,
        contained_at_epoch=NOW - 30,
        owner_id="incident-controller",
        description="Prompt-injection-derived multi-agent compromise.",
    )

    manifest = AgentIncidentForensicsManifest(
        graph_id=GRAPH_ID,
        version=GRAPH_VERSION,
        p8g_assessment_evidence_sha256=P8G_SHA,
        p8h_assessment_evidence_sha256=P8H_SHA,
        p8i_assessment_evidence_sha256=P8I_SHA,
        p8j_assessment_evidence_sha256=P8J_SHA,
        created_at_epoch=NOW - 5,
        events=events,
        containment_actions=actions,
        forensic_packages=(package,),
        reentry_authorizations=reentries,
        incidents=(incident,),
    )
    graph_sha = agent_incident_forensics_manifest_digest(manifest)

    policy = AgentIncidentForensicsPolicy(
        expected_graph_id=GRAPH_ID,
        expected_graph_version=GRAPH_VERSION,
        expected_graph_sha256=graph_sha,
        expected_p8g_assessment_evidence_sha256=P8G_SHA,
        expected_p8h_assessment_evidence_sha256=P8H_SHA,
        expected_p8i_assessment_evidence_sha256=P8I_SHA,
        expected_p8j_assessment_evidence_sha256=P8J_SHA,
        required_event_ids=frozenset(EVENT_IDS),
        required_containment_action_ids=frozenset(ACTION_IDS),
        required_forensic_package_ids=frozenset(PACKAGE_IDS),
        required_reentry_authorization_ids=frozenset(REENTRY_IDS),
        required_incident_ids=frozenset(INCIDENT_IDS),
        trusted_owner_ids=frozenset({"forensic-recorder", "incident-controller"}),
        expected_event_profiles={event.event_id: _event_profile(event) for event in events},
        expected_incident_profiles={"incident-1": _incident_profile(incident)},
        safe_checkpoint_id_by_agent={
            "agent-planner": "checkpoint-safe-2",
            "agent-worker": "checkpoint-safe-2",
        },
        replacement_credential_sha256_by_agent={
            "agent-planner": sha("planner-credential-rotated"),
            "agent-worker": sha("worker-credential-rotated"),
        },
        minimum_reentry_state_version_by_agent={
            "agent-planner": 9,
            "agent-worker": 9,
        },
        max_manifest_age_seconds=3_600,
        max_forensic_package_age_seconds=3_600,
        max_future_skew_seconds=30,
    )

    request = AgentIncidentForensicsRequest(
        graph_id=GRAPH_ID,
        graph_version=GRAPH_VERSION,
        graph_sha256=graph_sha,
        p8g_assessment_evidence_sha256=P8G_SHA,
        p8h_assessment_evidence_sha256=P8H_SHA,
        p8i_assessment_evidence_sha256=P8I_SHA,
        p8j_assessment_evidence_sha256=P8J_SHA,
        evaluated_at_epoch=NOW,
        incident_ids=INCIDENT_IDS,
        declared_complete_incident_ids=INCIDENT_IDS,
        declared_scope_event_ids_by_incident={"incident-1": scope},
        declared_reconstruction_sha256_by_incident={"incident-1": reconstruction_digest(scope)},
        declared_reentry_ids_by_incident={"incident-1": REENTRY_IDS},
    )

    return {
        "manifest": manifest,
        "policy": policy,
        "request": request,
        "p8g": _upstream(
            P8G_SHA,
            binding_attr="exact_agent_message_graph_binding_verified",
            caller_attr="caller_declared_message_safety_trusted",
            collection_attr="messages",
        ),
        "p8h": _upstream(
            P8H_SHA,
            binding_attr="exact_state_transition_graph_binding_verified",
            caller_attr="caller_declared_state_safety_trusted",
            collection_attr="transitions",
        ),
        "p8i": _upstream(
            P8I_SHA,
            binding_attr="exact_artifact_graph_binding_verified",
            caller_attr="caller_declared_artifact_safety_trusted",
            collection_attr="actions",
        ),
        "p8j": _upstream(
            P8J_SHA,
            binding_attr="exact_recovery_graph_binding_verified",
            caller_attr="caller_declared_recovery_safety_trusted",
            collection_attr="recoveries",
        ),
    }
