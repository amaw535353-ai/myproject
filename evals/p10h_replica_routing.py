from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

from aegis.inference.replica_routing_security import InferenceReplicaRoutingAnalyzer
from aegis.inference.replica_routing_types import *
from aegis.inference.streaming_security_types import StreamDecision, StreamRisk
from aegis.vulnerable.replica_routing import VulnerableCallerDeclaredReplicaRoutingSafety
from evals.p10h_fixture import (
    NOW,
    build_fixture,
    rebind,
    safe_extra_capacity_fixture,
    safe_fresh_heartbeat_fixture,
    safe_lower_load_fixture,
    h,
)


def safe_cases():
    return (
        ("canonical", build_fixture()),
        ("lower-load", safe_lower_load_fixture()),
        ("fresh-heartbeats", safe_fresh_heartbeat_fixture()),
        ("extra-capacity", safe_extra_capacity_fixture()),
    )


def _m(f, **changes):
    return rebind(f, replace(f["manifest"], **changes))


def _replica(f, index: int, **changes):
    xs = list(f["manifest"].replicas)
    xs[index] = replace(xs[index], **changes)
    return _m(f, replicas=tuple(xs))


def _route(f, index: int, **changes):
    xs = list(f["manifest"].routing_decisions)
    xs[index] = replace(xs[index], **changes)
    return _m(f, routing_decisions=tuple(xs))


def _scale(f, index: int, **changes):
    xs = list(f["manifest"].scale_events)
    xs[index] = replace(xs[index], **changes)
    return _m(f, scale_events=tuple(xs))


def _failover(f, index: int, **changes):
    xs = list(f["manifest"].failovers)
    xs[index] = replace(xs[index], **changes)
    return _m(f, failovers=tuple(xs))


def _p10g(f, **changes):
    out = dict(f)
    out["p10g"] = replace(f["p10g"], **changes)
    return out


def _request(f, **changes):
    out = dict(f)
    out["request"] = replace(f["request"], **changes)
    return out


def adversarial_cases():
    cases = []

    def add(name, fixture):
        cases.append((name, fixture))

    f = build_fixture()
    m = f["manifest"]
    add("manifest-schema", _m(f, schema_version="aegis-inference-replica-failover-manifest-v0"))
    add("manifest-id", _m(f, manifest_id="p10h-replica-routing-evil"))
    add("manifest-time-zero", _m(f, created_at_epoch=0))
    add("upstream-digest", _m(f, p10g_assessment_sha256=h("evil-p10g")))
    add("request-id", _m(f, request_id="request-acme-evil"))
    add("tenant", _m(f, tenant_id="beta", session_id="tenant/beta/session/s-001"))
    add("session", _m(f, session_id="tenant/acme/session/s-evil"))
    add("target-model", _m(f, target_model_id="aegisdesk-helpdesk-evil"))
    add("target-revision", _m(f, target_model_revision="rev-evil"))
    add("adapter-order", _m(f, adapter_ids=tuple(reversed(m.adapter_ids))))
    add("adapter-generation", _m(f, adapter_generation=m.adapter_generation - 1))
    add("partition-order", _m(f, partition_ids=tuple(reversed(m.partition_ids))))
    add("stream-id", _m(f, stream_id="stream-acme-evil"))
    add("output-channel", _m(f, output_channel_id="sse-channel-acme-evil"))
    add("frame-order", _m(f, frame_ids=tuple(reversed(m.frame_ids))))
    add("router-id", _m(f, router_id="router-inference-evil"))
    add("router-generation", _m(f, router_generation=m.router_generation - 1))
    add("network-operation", _m(f, network_operations=1))
    add("replica-order", _m(f, replicas=tuple(reversed(m.replicas))))
    add("route-drop", _m(f, routing_decisions=()))
    add("scale-drop", _m(f, scale_events=()))
    add("failover-drop", _m(f, failovers=()))

    for i, base in enumerate(m.replicas):
        prefix = f"replica-{i}"
        mutations = {
            "process": {"process_id": base.process_id + "-evil"},
            "endpoint": {"endpoint_id": base.endpoint_id + "/evil"},
            "instance-generation": {"instance_generation": base.instance_generation + 1},
            "route-generation": {"route_generation": max(0, base.route_generation - 1)},
            "healthy": {"healthy": not base.healthy},
            "accepting": {"accepting_requests": not base.accepting_requests},
            "fenced": {"fenced": not base.fenced},
            "inflight": {"inflight_requests": base.capacity_requests + 1},
            "capacity": {"capacity_requests": 0},
            "heartbeat-old": {"heartbeat_epoch": NOW - 1000},
            "heartbeat-future": {"heartbeat_epoch": NOW + 1000},
            "model": {"target_model_id": "aegisdesk-helpdesk-evil"},
            "revision": {"target_model_revision": "rev-evil"},
            "adapters": {"adapter_ids": tuple(reversed(base.adapter_ids))},
            "adapter-generation": {"adapter_generation": max(0, base.adapter_generation - 1)},
            "partitions": {"partition_ids": tuple(reversed(base.partition_ids))},
            "config": {"config_sha256": h(f"evil-config-{i}")},
            "predecessor": {"predecessor_replica_id": "replica-inference-evil"},
            "predecessor-lineage": {"predecessor_lineage_sha256": h(f"evil-lineage-{i}")},
        }
        if base.state == ReplicaState.READY:
            mutations["state-failed"] = {"state": ReplicaState.FAILED}
            mutations["state-draining"] = {"state": ReplicaState.DRAINING}
        else:
            mutations["state-ready"] = {"state": ReplicaState.READY}
            mutations["state-starting"] = {"state": ReplicaState.STARTING}
        for name, changes in mutations.items():
            add(prefix + "-" + name, _replica(f, i, **changes))

    rs = list(m.replicas)
    rs[2] = replace(rs[2], endpoint_id=rs[1].endpoint_id)
    add("endpoint-alias", _m(f, replicas=tuple(rs)))
    rs = list(m.replicas)
    rs[2] = replace(rs[2], process_id=rs[1].process_id)
    add("process-alias", _m(f, replicas=tuple(rs)))

    r = m.routing_decisions[0]
    route_mutations = {
        "id": {"routing_id": "route-acme-evil"},
        "sequence": {"sequence_no": 2},
        "router-generation": {"router_generation": r.router_generation - 1},
        "selected-replica": {"selected_replica_id": m.replicas[0].replica_id},
        "selected-generation": {"selected_instance_generation": r.selected_instance_generation - 1},
        "request": {"request_id": "request-acme-evil"},
        "tenant": {"tenant_id": "beta"},
        "session": {"session_id": "tenant/acme/session/s-evil"},
        "stream": {"stream_id": "stream-acme-evil"},
        "idempotency": {"idempotency_key_sha256": h("evil-idempotency")},
        "reason": {"reason_code": "stale_route"},
        "previous": {"previous_routing_sha256": h("evil-route-chain")},
    }
    for name, changes in route_mutations.items():
        add("routing-" + name, _route(f, 0, **changes))

    s = m.scale_events[0]
    scale_mutations = {
        "id": {"scale_event_id": "scale-event-evil"},
        "sequence": {"sequence_no": 2},
        "from-zero": {"from_desired_replicas": 0},
        "to-zero": {"to_desired_replicas": 0},
        "to-high": {"to_desired_replicas": 99},
        "observed-high": {"observed_ready_replicas": 4},
        "reason": {"reason_code": "attacker_scale"},
        "auth": {"authorization_sha256": h("evil-scale-auth")},
        "previous": {"previous_scale_event_sha256": h("evil-scale-chain")},
    }
    for name, changes in scale_mutations.items():
        add("scale-" + name, _scale(f, 0, **changes))

    fo = m.failovers[0]
    failover_mutations = {
        "id": {"failover_id": "failover-event-evil"},
        "failed": {"failed_replica_id": m.replicas[2].replica_id},
        "successor": {"successor_replica_id": m.replicas[0].replica_id},
        "failed-generation": {"failed_instance_generation": fo.failed_instance_generation + 1},
        "successor-generation": {"successor_instance_generation": fo.successor_instance_generation + 1},
        "failure-time": {"failure_epoch": NOW + 10},
        "fence-before-failure": {"fence_epoch": fo.failure_epoch - 1},
        "prior-router-generation": {"prior_router_generation": fo.new_router_generation},
        "new-router-generation": {"new_router_generation": fo.new_router_generation + 1},
        "auth": {"authorization_sha256": h("evil-failover-auth")},
    }
    for name, changes in failover_mutations.items():
        add("failover-" + name, _failover(f, 0, **changes))

    add("prior-ledger", _m(f, prior_request_ledger_sha256=h("evil-prior-ledger")))
    expected_key = request_idempotency_digest(m.request_id, m.tenant_id, m.session_id, m.stream_id)
    add(
        "request-replay",
        _m(
            f,
            prior_request_keys_sha256=m.prior_request_keys_sha256 + (expected_key,),
            prior_request_ledger_sha256=prior_request_ledger_digest(
                m.prior_request_keys_sha256 + (expected_key,)
            ),
        ),
    )

    upstream = f["p10g"]
    add("upstream-deny", _p10g(f, decision=StreamDecision.DENY))
    add("upstream-risk", _p10g(f, risks=(StreamRisk.UPSTREAM_P10F_INVALID,)))
    for field in (
        "upstream_p10f_bound",
        "output_channel_verified",
        "frame_integrity_verified",
        "backpressure_verified",
        "cancellation_verified",
        "tool_framing_verified",
        "replay_verified",
    ):
        add("upstream-flag-" + field, _p10g(f, **{field: False}))
    for field in (
        "caller_declared_safety_trusted",
        "production_streaming_gateway_integrated",
        "kernel_tcp_backpressure_validated",
        "distributed_cancellation_linearizability_validated",
        "production_tool_dispatch_integrated",
        "semantic_output_safety_validated",
        "remote_client_disconnect_semantics_validated",
    ):
        add("upstream-nonclaim-" + field, _p10g(f, **{field: True}))
    add("upstream-schema", _p10g(f, assessment_schema_version="aegis-inference-streaming-output-assessment-v0"))
    add("upstream-mode", _p10g(f, assessment_mode="caller-trusted"))
    add("upstream-evidence", _p10g(f, assessment_evidence_sha256=h("evil-upstream-assessment")))
    add("upstream-request", _p10g(f, request_id="request-acme-evil"))
    add("upstream-tenant", _p10g(f, tenant_id="beta"))
    add("upstream-session", _p10g(f, session_id="tenant/acme/session/s-evil"))
    add("upstream-model", _p10g(f, target_model_id="aegisdesk-helpdesk-evil"))
    add("upstream-revision", _p10g(f, target_model_revision="rev-evil"))
    add("upstream-adapters", _p10g(f, adapter_ids=tuple(reversed(upstream.adapter_ids))))
    add("upstream-adapter-generation", _p10g(f, adapter_generation=upstream.adapter_generation - 1))
    add("upstream-partitions", _p10g(f, partition_ids=tuple(reversed(upstream.partition_ids))))
    add("upstream-stream", _p10g(f, stream_id="stream-acme-evil"))
    add("upstream-channel", _p10g(f, output_channel_id="sse-channel-acme-evil"))
    add("upstream-frames", _p10g(f, frame_ids=tuple(reversed(upstream.frame_ids))))

    for field, value in (
        ("manifest_id", "p10h-replica-routing-evil"),
        ("manifest_sha256", h("evil-manifest")),
        ("evaluated_at_epoch", NOW + 1000),
        ("declared_request_id", "request-acme-evil"),
        ("declared_tenant_id", "beta"),
        ("declared_session_id", "tenant/acme/session/s-evil"),
        ("declared_router_id", "router-inference-evil"),
        ("declared_router_generation", m.router_generation - 1),
        ("declared_replica_ids", tuple(reversed(f["request"].declared_replica_ids))),
        ("declared_routing_ids", ("route-acme-evil",)),
    ):
        add("request-" + field, _request(f, **{field: value}))
    for field in (
        "declared_upstream_p10g_bound",
        "declared_replica_identity_safe",
        "declared_health_capacity_safe",
        "declared_routing_generation_safe",
        "declared_autoscaling_safe",
        "declared_failover_fencing_safe",
        "declared_replay_safe",
        "declared_lineage_safe",
    ):
        add("request-summary-" + field, _request(f, **{field: False}))

    p = f["policy"]
    policy_mutations = {
        "version": {"policy_version": "inference-replica-failover-routing-v0"},
        "manifest-sha": {"expected_manifest_sha256": h("evil-policy-manifest")},
        "upstream-sha": {"expected_p10g_assessment_sha256": h("evil-policy-upstream")},
        "router-id": {"expected_router_id": "router-inference-evil"},
        "router-generation": {"expected_router_generation": p.expected_router_generation - 1},
        "router-floor": {"minimum_router_generation": p.expected_router_generation + 1},
        "replica-coverage": {"expected_replica_ids": p.expected_replica_ids[:2]},
        "min-ready-high": {"min_ready_replicas": 4},
        "max-replicas-low": {"max_replicas": 2},
        "max-inflight-zero": {"max_inflight_per_replica": 0},
        "heartbeat-negative": {"max_heartbeat_age_seconds": -1},
        "ledger": {"expected_prior_request_ledger_sha256": h("evil-policy-ledger")},
        "age-negative": {"max_manifest_age_seconds": -1},
        "skew-negative": {"max_future_skew_seconds": -1},
    }
    for name, changes in policy_mutations.items():
        add("policy-" + name, {**f, "policy": replace(p, **changes)})

    return tuple(cases)


def _hardened_accepts(fixture) -> bool:
    try:
        a = InferenceReplicaRoutingAnalyzer(fixture["policy"]).evaluate(
            fixture["request"], fixture["manifest"], fixture["p10g"]
        )
        return a.decision == ReplicaDecision.ALLOW
    except InferenceReplicaRoutingRejected:
        return False


def run_eval():
    attacks = adversarial_cases()
    safe = safe_cases()
    vulnerable = VulnerableCallerDeclaredReplicaRoutingSafety()
    vulnerable_successes = sum(vulnerable.accepts(f["request"]) for _, f in attacks)
    hardened_successes = sum(_hardened_accepts(f) for _, f in attacks)
    false_positives = sum(not _hardened_accepts(f) for _, f in safe)
    safe_successes = len(safe) - false_positives
    clean = InferenceReplicaRoutingAnalyzer(safe[0][1]["policy"]).evaluate(
        safe[0][1]["request"], safe[0][1]["manifest"], safe[0][1]["p10g"]
    )
    root = Path(__file__).resolve().parents[1]
    fixture_eval_sha = hashlib.sha256(
        (root / "evals/p10h_fixture.py").read_bytes()
        + (root / "evals/p10h_replica_routing.py").read_bytes()
    ).hexdigest()
    dataset_sha = hashlib.sha256(
        json.dumps([name for name, _ in attacks], separators=(",", ":")).encode()
    ).hexdigest()
    report = {
        "phase": "P10-H",
        "attacks": len(attacks),
        "vulnerable_asr": f"{vulnerable_successes}/{len(attacks)}",
        "hardened_asr": f"{hardened_successes}/{len(attacks)}",
        "hardened_fpr": f"{false_positives}/{len(safe)}",
        "safe_task_rate": f"{safe_successes}/{len(safe)}",
        "manifest_sha256": inference_replica_routing_manifest_digest(safe[0][1]["manifest"]),
        "adversarial_dataset_sha256": dataset_sha,
        "fixture_evaluator_sha256": fixture_eval_sha,
        "clean_assessment_sha256": clean.assessment_evidence_sha256,
        "decision": clean.decision.value,
        "production_distributed_consensus_validated": clean.distributed_consensus_validated,
    }
    print(json.dumps(report, sort_keys=True))
    if vulnerable_successes != len(attacks) or hardened_successes or false_positives:
        raise SystemExit(1)
    return report


if __name__ == "__main__":
    run_eval()
