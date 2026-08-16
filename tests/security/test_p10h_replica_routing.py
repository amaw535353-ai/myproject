from __future__ import annotations

from dataclasses import replace
import pytest

from aegis.inference.replica_routing_security import InferenceReplicaRoutingAnalyzer
from aegis.inference.replica_routing_types import *
from aegis.vulnerable.replica_routing import VulnerableCallerDeclaredReplicaRoutingSafety
from evals.p10h_fixture import build_fixture
from evals.p10h_replica_routing import adversarial_cases, safe_cases


def hardened_accepts(f):
    try:
        assessment = InferenceReplicaRoutingAnalyzer(f["policy"]).evaluate(
            f["request"], f["manifest"], f["p10g"]
        )
        return assessment.decision == ReplicaDecision.ALLOW
    except InferenceReplicaRoutingRejected:
        return False


def test_clean_fixture_allows_and_preserves_nonclaims():
    f = build_fixture()
    a = InferenceReplicaRoutingAnalyzer(f["policy"]).evaluate(
        f["request"], f["manifest"], f["p10g"]
    )
    assert a.decision == ReplicaDecision.ALLOW
    assert not a.risks
    assert a.upstream_p10g_bound
    assert a.replica_identity_verified
    assert a.health_and_capacity_verified
    assert a.routing_generation_verified
    assert a.autoscaling_verified
    assert a.failover_fencing_verified
    assert a.idempotency_replay_verified
    assert a.lineage_verified
    assert not a.caller_declared_safety_trusted
    assert not a.production_service_mesh_integrated
    assert not a.production_orchestrator_integrated
    assert not a.distributed_consensus_validated
    assert not a.cross_zone_failover_validated
    assert not a.load_balancer_stickiness_validated
    assert not a.production_autoscaler_validated
    assert not a.network_partition_resistance_validated
    assert not a.exactly_once_delivery_validated


@pytest.mark.parametrize("name,f", safe_cases(), ids=lambda item: item if isinstance(item, str) else None)
def test_safe_corpus(name, f):
    assert hardened_accepts(f), name


ATTACKS = adversarial_cases()


@pytest.mark.parametrize("name,f", ATTACKS, ids=[name for name, _ in ATTACKS])
def test_hardened_blocks_adversarial_corpus(name, f):
    assert not hardened_accepts(f), name


@pytest.mark.parametrize("name,f", ATTACKS, ids=[name for name, _ in ATTACKS])
def test_vulnerable_baseline_accepts_adversarial_corpus(name, f):
    assert VulnerableCallerDeclaredReplicaRoutingSafety().accepts(f["request"]), name


def test_policy_constructor_fails_closed_on_bad_version():
    f = build_fixture()
    with pytest.raises(InferenceReplicaRoutingRejected) as exc:
        InferenceReplicaRoutingAnalyzer(
            replace(f["policy"], policy_version="inference-replica-failover-routing-v0")
        )
    assert exc.value.reason == ReplicaRejectReason.POLICY_INVALID


def test_manifest_digest_is_stable():
    f = build_fixture()
    first = inference_replica_routing_manifest_digest(f["manifest"])
    second = inference_replica_routing_manifest_digest(f["manifest"])
    assert first == second
    assert len(first) == 64


def test_request_idempotency_digest_binds_route_identity():
    f = build_fixture()
    m = f["manifest"]
    a = request_idempotency_digest(m.request_id, m.tenant_id, m.session_id, m.stream_id)
    b = request_idempotency_digest(m.request_id, m.tenant_id, m.session_id, m.stream_id + "-evil")
    assert a != b
