from __future__ import annotations

from dataclasses import replace
import hashlib

from aegis.inference.incident_response_types import *
from aegis.inference.replica_routing_types import *

NOW = 1_800_031_900
MANIFEST_ID = "p10i-incident-response-001"
P10H_CLEAN_ASSESSMENT_SHA256 = "05b72ff88bb41fa60bdea581b5ddd7fa49deb722f030e508b8d349344197d703"
P10H_MANIFEST_SHA256 = "d5b8d19be4fabf40a66b29109fd94f3392fd3877e9a717134dac486f31a3946e"
REQUEST_ID = "request-acme-0001"
TENANT_ID = "acme"
SESSION_ID = "tenant/acme/session/s-001"
TARGET_MODEL_ID = "aegisdesk-helpdesk-security"
TARGET_MODEL_REVISION = "rev-2026-08-p9h"
ADAPTER_IDS = ("adapter-security-policy", "adapter-acme-helpdesk")
ADAPTER_GENERATION = 12
PARTITION_IDS = ("partition-acme-mig-0", "partition-acme-exclusive-1")
STREAM_ID = "stream-acme-0001"
ROUTER_ID = "router-inference-01"
ROUTER_GENERATION = 42
REPLICA_IDS = ("replica-inference-a", "replica-inference-b", "replica-inference-c")
ROUTING_IDS = ("route-acme-0001",)
INCIDENT_ID = "incident-p10i-acme-0001"
COMPROMISED_REPLICA_ID = "replica-inference-a"
SIGNAL_IDS = ("signal-integrity-001", "signal-replay-002", "signal-tenant-003")
SIGNAL_TYPES = ("replica_integrity_failure", "idempotency_replay", "cross_tenant_request")
ACTION_IDS = ("contain-fence-001", "contain-router-002", "contain-stream-003")
ACTION_TYPES = ("fence_compromised_replica", "advance_router_generation", "revoke_stream")
RECOVERY_IDS = ("recover-replace-001", "recover-health-002", "recover-resume-003")
RECOVERY_TYPES = ("register_clean_replacement", "verify_replacement_health", "resume_safe_routing")
FORENSIC_IDS = ("forensic-router-log-001", "forensic-health-002", "forensic-report-003")
FORENSIC_KINDS = ("router_event_log", "replica_health_snapshot", "incident_lab_report")
EXIT_CONTROLS = ("p10a", "p10b", "p10c", "p10d", "p10e", "p10f", "p10g", "p10h", "p10i")
LOCAL_RUNTIME_GATES = ("p10g-streaming-loopback", "p10h-multiprocess-failover", "p10i-incident-response")
DEFERRED_MASTERY = ("p10f-live-nvidia-gpu-mig-cuda",)


def h(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def p10h_assessment() -> VerifiedInferenceReplicaRoutingAssessment:
    return VerifiedInferenceReplicaRoutingAssessment(
        "p10h-replica-routing-001",
        P10H_MANIFEST_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        ReplicaDecision.ALLOW,
        (),
        h("p10g-clean"),
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        PARTITION_IDS,
        STREAM_ID,
        ROUTER_ID,
        ROUTER_GENERATION,
        REPLICA_IDS,
        ROUTING_IDS,
        True, True, True, True, True, True, True, True,
        False, False, False, False, False, False, False, False, False,
        P10H_ASSESSMENT_SCHEMA_VERSION,
        P10H_ASSESSMENT_MODE,
        P10H_CLEAN_ASSESSMENT_SHA256,
    )


def _signals() -> tuple[IncidentSignalEvidence, ...]:
    previous = incident_seed_digest(INCIDENT_ID, REQUEST_ID, TENANT_ID, SESSION_ID)
    out = []
    for seq, (sid, stype, source, severity, offset) in enumerate((
        (SIGNAL_IDS[0], SIGNAL_TYPES[0], COMPROMISED_REPLICA_ID, "critical", 1),
        (SIGNAL_IDS[1], SIGNAL_TYPES[1], ROUTER_ID, "high", 2),
        (SIGNAL_IDS[2], SIGNAL_TYPES[2], ROUTER_ID, "high", 3),
    ), 1):
        signal = IncidentSignalEvidence(
            sid, seq, stype, source, REQUEST_ID, TENANT_ID, SESSION_ID,
            NOW + offset, severity, h(f"artifact:{sid}"), previous,
        )
        out.append(signal)
        previous = signal_digest(signal)
    return tuple(out)


def _actions(signals: tuple[IncidentSignalEvidence, ...]) -> tuple[ContainmentActionEvidence, ...]:
    previous = signal_digest(signals[-1])
    out = []
    targets = (COMPROMISED_REPLICA_ID, ROUTER_ID, STREAM_ID)
    for seq, (aid, atype, target) in enumerate(zip(ACTION_IDS, ACTION_TYPES, targets), 1):
        action = ContainmentActionEvidence(
            aid,
            seq,
            atype,
            target,
            NOW + 4 + seq,
            NOW + 5 + seq,
            containment_authorization_digest(INCIDENT_ID, aid, atype, target),
            h(f"result:{aid}"),
            previous,
        )
        out.append(action)
        previous = containment_digest(action)
    return tuple(out)


def _recovery(actions: tuple[ContainmentActionEvidence, ...]) -> tuple[RecoveryStepEvidence, ...]:
    previous = containment_digest(actions[-1])
    out = []
    values = (
        (RECOVERY_IDS[0], RECOVERY_TYPES[0], "replica-inference-c", ROUTER_GENERATION + 1),
        (RECOVERY_IDS[1], RECOVERY_TYPES[1], "replica-inference-c", ROUTER_GENERATION + 1),
        (RECOVERY_IDS[2], RECOVERY_TYPES[2], ROUTER_ID, ROUTER_GENERATION + 2),
    )
    for seq, (rid, rtype, target, gen) in enumerate(values, 1):
        step = RecoveryStepEvidence(
            rid, seq, rtype, target, gen, gen, True, NOW + 10 + seq,
            h(f"recovery:{rid}:{gen}"), previous,
        )
        out.append(step)
        previous = recovery_digest(step)
    return tuple(out)


def _forensics(recovery: tuple[RecoveryStepEvidence, ...]) -> tuple[ForensicArtifactEvidence, ...]:
    previous = recovery_digest(recovery[-1])
    out = []
    sources = (ROUTER_ID, COMPROMISED_REPLICA_ID, "p10i-local-ir-lab")
    for seq, (fid, kind, source) in enumerate(zip(FORENSIC_IDS, FORENSIC_KINDS, sources), 1):
        content = h(f"forensic-content:{fid}")
        custody = forensic_chain_digest(fid, kind, source, content, previous)
        item = ForensicArtifactEvidence(fid, kind, source, NOW + 20 + seq, content, True, previous, custody)
        out.append(item)
        previous = custody
    return tuple(out)


def _manifest() -> InferenceIncidentResponseManifest:
    signals = _signals()
    actions = _actions(signals)
    recovery = _recovery(actions)
    forensics = _forensics(recovery)
    gate = Phase10ExitGateEvidence(
        EXIT_CONTROLS,
        EXIT_CONTROLS,
        LOCAL_RUNTIME_GATES,
        DEFERRED_MASTERY,
        False,
        False,
        True,
        False,
        ExitGateStatus.PASS_WITH_DEFERRED,
    )
    return InferenceIncidentResponseManifest(
        P10I_SCHEMA_VERSION,
        MANIFEST_ID,
        NOW,
        P10H_CLEAN_ASSESSMENT_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        PARTITION_IDS,
        STREAM_ID,
        ROUTER_ID,
        ROUTER_GENERATION,
        REPLICA_IDS,
        ROUTING_IDS,
        INCIDENT_ID,
        COMPROMISED_REPLICA_ID,
        NOW,
        signals,
        actions,
        recovery,
        forensics,
        gate,
        0,
    )


def policy_for(m: InferenceIncidentResponseManifest) -> InferenceIncidentResponsePolicy:
    return InferenceIncidentResponsePolicy(
        P10I_POLICY_VERSION,
        m.manifest_id,
        inference_incident_response_manifest_digest(m),
        P10H_CLEAN_ASSESSMENT_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        PARTITION_IDS,
        STREAM_ID,
        ROUTER_ID,
        ROUTER_GENERATION,
        REPLICA_IDS,
        ROUTING_IDS,
        INCIDENT_ID,
        COMPROMISED_REPLICA_ID,
        SIGNAL_IDS,
        SIGNAL_TYPES,
        ACTION_IDS,
        ACTION_TYPES,
        RECOVERY_IDS,
        RECOVERY_TYPES,
        FORENSIC_IDS,
        FORENSIC_KINDS,
        EXIT_CONTROLS,
        LOCAL_RUNTIME_GATES,
        DEFERRED_MASTERY,
        10,
        30,
        300,
        5,
    )


def request_for(m: InferenceIncidentResponseManifest, *, safe: bool = True) -> InferenceIncidentResponseRequest:
    return InferenceIncidentResponseRequest(
        m.manifest_id,
        inference_incident_response_manifest_digest(m),
        m.created_at_epoch + 30,
        m.request_id,
        m.tenant_id,
        m.session_id,
        m.incident_id,
        m.compromised_replica_id,
        m.router_generation,
        True,
        safe,
        safe,
        safe,
        safe,
        safe,
        True,
        m.exit_gate.hosted_ci_execution_verified,
        m.exit_gate.production_validation_claimed,
        m.exit_gate.professional_mastery_complete,
        safe,
    )


def build_fixture():
    m = _manifest()
    return {"manifest": m, "policy": policy_for(m), "request": request_for(m), "p10h": p10h_assessment()}


def rebind(f, m, *, safe: bool | None = None, refresh_policy: bool = True):
    p = f["policy"]
    if refresh_policy:
        p = replace(p, expected_manifest_sha256=inference_incident_response_manifest_digest(m))
    if safe is None:
        safe = True
    return {"manifest": m, "policy": p, "request": request_for(m, safe=safe), "p10h": f["p10h"]}


def safe_wider_timing_fixture():
    f = build_fixture()
    p = replace(f["policy"], max_detection_latency_seconds=20, max_containment_latency_seconds=60)
    return {**f, "policy": p}


def safe_uppercase_digest_fixture():
    f = build_fixture()
    signals = list(f["manifest"].signals)
    signals[0] = replace(signals[0], artifact_sha256=signals[0].artifact_sha256.upper())
    # Artifact digest is opaque integrity evidence; chain binds the dataclass representation, so rechain downstream.
    previous = incident_seed_digest(INCIDENT_ID, REQUEST_ID, TENANT_ID, SESSION_ID)
    rebuilt = []
    for s in signals:
        s2 = replace(s, previous_signal_sha256=previous)
        rebuilt.append(s2)
        previous = signal_digest(s2)
    actions = []
    previous = signal_digest(rebuilt[-1])
    for a in f["manifest"].containment_actions:
        a2 = replace(a, previous_action_sha256=previous)
        actions.append(a2)
        previous = containment_digest(a2)
    recovery = []
    previous = containment_digest(actions[-1])
    for r in f["manifest"].recovery_steps:
        r2 = replace(r, previous_recovery_sha256=previous)
        recovery.append(r2)
        previous = recovery_digest(r2)
    forensics = []
    previous = recovery_digest(recovery[-1])
    for item in f["manifest"].forensic_artifacts:
        custody = forensic_chain_digest(item.artifact_id, item.artifact_kind, item.source_id, item.content_sha256, previous)
        item2 = replace(item, previous_artifact_sha256=previous, chain_of_custody_sha256=custody)
        forensics.append(item2)
        previous = custody
    m = replace(f["manifest"], signals=tuple(rebuilt), containment_actions=tuple(actions), recovery_steps=tuple(recovery), forensic_artifacts=tuple(forensics))
    return rebind(f, m)


def safe_delayed_evaluation_fixture():
    f = build_fixture()
    req = replace(f["request"], evaluated_at_epoch=f["manifest"].created_at_epoch + 120)
    return {**f, "request": req}
