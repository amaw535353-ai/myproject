from __future__ import annotations

from dataclasses import replace
import hashlib

from aegis.inference.streaming_security_types import *
from aegis.inference.replica_routing_types import *

NOW = 1_800_031_500
MANIFEST_ID = "p10h-replica-routing-001"
P10G_CLEAN_ASSESSMENT_SHA256 = "7e1f232b3f18120129629859c6ec7cfc6113f6e9d3a3d0c40eff3ab14f6ff268"
P10G_MANIFEST_SHA256 = "31803741d20e03590f4fb40f3f5e28a31de3732c6e3f8bd55d256100dc59ca78"
REQUEST_ID = "request-acme-0001"
TENANT_ID = "acme"
SESSION_ID = "tenant/acme/session/s-001"
TARGET_MODEL_ID = "aegisdesk-helpdesk-security"
TARGET_MODEL_REVISION = "rev-2026-08-p9h"
ADAPTER_IDS = ("adapter-security-policy", "adapter-acme-helpdesk")
ADAPTER_GENERATION = 12
PARTITION_IDS = ("partition-acme-mig-0", "partition-acme-exclusive-1")
STREAM_ID = "stream-acme-0001"
OUTPUT_CHANNEL_ID = "sse-channel-acme-0001"
FRAME_IDS = (
    "stream-frame-acme-0001",
    "stream-frame-acme-0002",
    "stream-frame-acme-0003",
    "stream-frame-acme-0004",
)
ROUTER_ID = "router-inference-01"
ROUTER_GENERATION = 42
REPLICA_IDS = ("replica-inference-a", "replica-inference-b", "replica-inference-c")
ROUTING_IDS = ("route-acme-0001",)
SCALE_IDS = ("scale-event-0001",)
FAILOVER_IDS = ("failover-event-0001",)


def h(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def p10g_assessment() -> VerifiedInferenceStreamingSecurityAssessment:
    return VerifiedInferenceStreamingSecurityAssessment(
        "p10g-streaming-security-001",
        P10G_MANIFEST_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        StreamDecision.ALLOW,
        (),
        h("p10f-clean"),
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        PARTITION_IDS,
        STREAM_ID,
        OUTPUT_CHANNEL_ID,
        FRAME_IDS,
        StreamFrameKind.CANCELLED,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        P10G_ASSESSMENT_SCHEMA_VERSION,
        P10G_ASSESSMENT_MODE,
        P10G_CLEAN_ASSESSMENT_SHA256,
    )


def _replicas() -> tuple[ReplicaEvidence, ...]:
    a = ReplicaEvidence(
        REPLICA_IDS[0],
        "process-replica-a-1001",
        "http://127.0.0.1:18081",
        7,
        41,
        ReplicaState.FAILED,
        False,
        False,
        True,
        0,
        8,
        NOW - 600,
        NOW - 2,
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        PARTITION_IDS,
        h("config:replica-a:v7"),
        "",
        "",
    )
    b = ReplicaEvidence(
        REPLICA_IDS[1],
        "process-replica-b-1002",
        "http://127.0.0.1:18082",
        9,
        ROUTER_GENERATION,
        ReplicaState.READY,
        True,
        True,
        False,
        2,
        8,
        NOW - 500,
        NOW - 1,
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        PARTITION_IDS,
        h("config:replica-b:v9"),
        "",
        "",
    )
    c = ReplicaEvidence(
        REPLICA_IDS[2],
        "process-replica-c-1003",
        "http://127.0.0.1:18083",
        8,
        ROUTER_GENERATION,
        ReplicaState.READY,
        True,
        True,
        False,
        1,
        8,
        NOW - 20,
        NOW,
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        PARTITION_IDS,
        h("config:replica-c:v8"),
        a.replica_id,
        replica_lineage_digest(a),
    )
    return (a, b, c)


def _manifest() -> InferenceReplicaRoutingManifest:
    replicas = _replicas()
    prior_keys = (h("request:prior:1"), h("request:prior:2"))
    ledger = prior_request_ledger_digest(prior_keys)
    key = request_idempotency_digest(REQUEST_ID, TENANT_ID, SESSION_ID, STREAM_ID)
    route = RoutingDecisionEvidence(
        ROUTING_IDS[0],
        1,
        ROUTER_GENERATION,
        replicas[1].replica_id,
        replicas[1].instance_generation,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        STREAM_ID,
        key,
        "failover",
        ledger,
    )
    scale = ScaleEventEvidence(
        SCALE_IDS[0],
        1,
        2,
        3,
        2,
        "replace_failed_replica",
        scale_authorization_digest(ROUTER_ID, 2, 3, "replace_failed_replica"),
        ledger,
    )
    failover = FailoverEvidence(
        FAILOVER_IDS[0],
        replicas[0].replica_id,
        replicas[1].replica_id,
        replicas[0].instance_generation,
        replicas[1].instance_generation,
        NOW - 6,
        NOW - 5,
        ROUTER_GENERATION - 1,
        ROUTER_GENERATION,
        failover_authorization_digest(
            ROUTER_ID, replicas[0].replica_id, replicas[1].replica_id, ROUTER_GENERATION
        ),
    )
    return InferenceReplicaRoutingManifest(
        P10H_SCHEMA_VERSION,
        MANIFEST_ID,
        NOW,
        P10G_CLEAN_ASSESSMENT_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        PARTITION_IDS,
        STREAM_ID,
        OUTPUT_CHANNEL_ID,
        FRAME_IDS,
        ROUTER_ID,
        ROUTER_GENERATION,
        replicas,
        (route,),
        (scale,),
        (failover,),
        prior_keys,
        ledger,
        0,
    )


def request_for(m: InferenceReplicaRoutingManifest) -> InferenceReplicaRoutingRequest:
    return InferenceReplicaRoutingRequest(
        m.manifest_id,
        inference_replica_routing_manifest_digest(m),
        m.created_at_epoch + 10,
        m.request_id,
        m.tenant_id,
        m.session_id,
        m.router_id,
        m.router_generation,
        tuple(r.replica_id for r in m.replicas),
        tuple(e.routing_id for e in m.routing_decisions),
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
    )


def policy_for(m: InferenceReplicaRoutingManifest) -> InferenceReplicaRoutingPolicy:
    replicas = {r.replica_id: r for r in m.replicas}
    return InferenceReplicaRoutingPolicy(
        P10H_POLICY_VERSION,
        m.manifest_id,
        inference_replica_routing_manifest_digest(m),
        P10G_CLEAN_ASSESSMENT_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        PARTITION_IDS,
        STREAM_ID,
        OUTPUT_CHANNEL_ID,
        FRAME_IDS,
        ROUTER_ID,
        ROUTER_GENERATION,
        ROUTER_GENERATION,
        tuple(replicas),
        {k: v.instance_generation for k, v in replicas.items()},
        {k: v.route_generation for k, v in replicas.items()},
        {k: v.config_sha256 for k, v in replicas.items()},
        {k: replica_identity_digest(v) for k, v in replicas.items()},
        {k: v.predecessor_replica_id for k, v in replicas.items()},
        {k: v.predecessor_lineage_sha256 for k, v in replicas.items()},
        tuple(e.routing_id for e in m.routing_decisions),
        ("failover", "rebalance"),
        tuple(e.scale_event_id for e in m.scale_events),
        tuple(e.failover_id for e in m.failovers),
        2,
        4,
        8,
        30,
        m.prior_request_ledger_sha256,
        300,
        5,
    )


def build_fixture():
    m = _manifest()
    return {
        "manifest": m,
        "policy": policy_for(m),
        "request": request_for(m),
        "p10g": p10g_assessment(),
    }


def rebind(f, m, *, refresh_manifest_pin: bool = True, refresh_security_pins: bool = False):
    p = f["policy"]
    if refresh_manifest_pin:
        p = replace(p, expected_manifest_sha256=inference_replica_routing_manifest_digest(m))
    if refresh_security_pins:
        replicas = {r.replica_id: r for r in m.replicas}
        p = replace(
            p,
            expected_router_generation=m.router_generation,
            expected_replica_ids=tuple(replicas),
            expected_instance_generation_by_replica={k: v.instance_generation for k, v in replicas.items()},
            expected_route_generation_by_replica={k: v.route_generation for k, v in replicas.items()},
            expected_config_sha256_by_replica={k: v.config_sha256 for k, v in replicas.items()},
            expected_replica_identity_sha256_by_replica={k: replica_identity_digest(v) for k, v in replicas.items()},
            expected_predecessor_by_replica={k: v.predecessor_replica_id for k, v in replicas.items()},
            expected_predecessor_lineage_sha256_by_replica={k: v.predecessor_lineage_sha256 for k, v in replicas.items()},
            expected_routing_ids=tuple(e.routing_id for e in m.routing_decisions),
            expected_scale_event_ids=tuple(e.scale_event_id for e in m.scale_events),
            expected_failover_ids=tuple(e.failover_id for e in m.failovers),
            expected_prior_request_ledger_sha256=m.prior_request_ledger_sha256,
        )
    return {"manifest": m, "policy": p, "request": request_for(m), "p10g": f["p10g"]}


def safe_lower_load_fixture():
    f = build_fixture()
    rs = list(f["manifest"].replicas)
    rs[1] = replace(rs[1], inflight_requests=0)
    rs[2] = replace(rs[2], inflight_requests=0)
    return rebind(f, replace(f["manifest"], replicas=tuple(rs)), refresh_security_pins=True)


def safe_fresh_heartbeat_fixture():
    f = build_fixture()
    rs = tuple(replace(r, heartbeat_epoch=NOW) for r in f["manifest"].replicas)
    return rebind(f, replace(f["manifest"], replicas=rs), refresh_security_pins=True)


def safe_extra_capacity_fixture():
    f = build_fixture()
    rs = list(f["manifest"].replicas)
    rs[1] = replace(rs[1], capacity_requests=12)
    rs[2] = replace(rs[2], capacity_requests=12)
    out = rebind(f, replace(f["manifest"], replicas=tuple(rs)), refresh_security_pins=True)
    out["policy"] = replace(out["policy"], max_inflight_per_replica=12)
    return out
