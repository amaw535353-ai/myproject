import copy
import json
from pathlib import Path

import pytest

from aegis.platform.serving_security import DrainState, FixedWindowLimiter, RequestContext, RequestPolicy, ServingDenied, canonical_bytes, evidence_is_sensitive_material_free
from evals.p11d_fixture import DEFERRED_MASTERY_ITEMS, LIVE_GATE_NAMES, fixture
from evals.p11d_serving_security import EvidenceRejected, assess, validate_evidence
from scripts.verify_phase11 import default_summary


def case(group, name): return next(c for c in assess(fixture())[group] and assess(fixture())["raw_observations"][group] if c["case"] == name)
def test_canonical_hashing(): assert canonical_bytes({"b": 1, "a": 2}) == canonical_bytes({"a": 2, "b": 1})
def test_deterministic_contract(): assert assess(fixture())["ASR"]["numerator"] == 0
@pytest.mark.parametrize("group,name", [
    ("tls", "wrong_server_identity"), ("tls", "untrusted_ca"), ("tls", "expired_server_cert"),
    ("mtls", "missing_client_cert"), ("mtls", "wrong_client_identity"), ("mtls", "untrusted_client_ca"),
    ("mtls", "plaintext_backend"), ("ingress", "direct_backend_exposure"),
    ("ingress", "trusted_header_spoof"), ("request_policy", "tenant_mismatch"),
    ("request_policy", "wrong_content_type"), ("request_policy", "oversized_body"),
    ("request_policy", "malformed_json"), ("rate_limit", "burst_above_limit"),
    ("rate_limit", "concurrency_exhaustion"), ("health_readiness", "readiness_while_draining"),
    ("graceful_shutdown", "new_request_during_drain"), ("network_policy", "attacker_backend_access"),
    ("runtime_policy", "privileged"), ("runtime_policy", "capabilities"),
    ("runtime_policy", "writable_rootfs"), ("runtime_policy", "missing_resource_limit"),
])
def test_attack_denied(group, name): assert case(group, name)["observed"] == "DENY"


def test_policy_rejects_internal_prefix_and_proxy_is_not_authority():
    policy = RequestPolicy(); ctx = RequestContext("client-acme", "acme", "req-12345678")
    base = dict(method="POST", route="/v1/infer", content_type="application/json", body=b"{}", claimed_tenant="acme", context=ctx)
    with pytest.raises(ServingDenied): policy.validate(headers={"X-Aegis-Internal-Role": "admin"}, **base)
    policy.validate(headers={"X-Forwarded-For": "203.0.113.1"}, **base)


def test_rate_and_concurrency_are_principal_scoped():
    limiter = FixedWindowLimiter(2, 60, 1); limiter.acquire("a", 0)
    with pytest.raises(ServingDenied, match="CONCURRENCY"): limiter.acquire("a", 0)
    limiter.acquire("b", 0); limiter.release("a"); limiter.release("b")
    limiter.acquire("a", 1); limiter.release("a")
    with pytest.raises(ServingDenied, match="RATE"): limiter.acquire("a", 2)


def test_health_readiness_and_drain_semantics():
    state = DrainState(); state.enter(); state.drain()
    assert state.healthy and not state.ready and state.in_flight == 1
    with pytest.raises(ServingDenied): state.enter()
    state.leave(); assert state.safe_to_stop


def test_tamper_rejected():
    value = fixture(); evidence = assess(value); evidence["assessment_sha256"] = "0" * 64
    with pytest.raises(EvidenceRejected, match="hash"): validate_evidence({**value, **evidence})


def test_summary_recomputed():
    value = fixture(); evidence = assess(value); evidence["ASR"] = {"numerator": 0, "denominator": 0, "value": 0}
    with pytest.raises(EvidenceRejected, match="caller summary"): validate_evidence({**value, **evidence})


def test_mastery_debt_and_claim_boundaries():
    value = fixture(); value["deferred_mastery_items"] = []
    with pytest.raises(EvidenceRejected, match="mastery"): assess(value)
    value = fixture(); value["production_serving_validation_claimed"] = True
    with pytest.raises(EvidenceRejected, match="forbidden"): assess(value)


def live_fixture():
    value = fixture(); value["execution_mode"] = "live"; value["environment_classification"] = "LIVE_LOCAL_K3D"
    value["observations"]["live_gates"] = {**{x: True for x in LIVE_GATE_NAMES},
        "ca_sha256": "a" * 64, "server_cert_sha256": "b" * 64, "client_cert_sha256": "c" * 64,
        "image_id": "sha256:" + "d" * 64, "rate_attempts": 4, "rate_allowed": 3, "rate_limited": 1}
    return value


def test_live_requires_every_gate_and_deterministic_cannot_claim_live():
    value = live_fixture(); assert assess(value)["live_local_serving_security_validated"]
    for gate in LIVE_GATE_NAMES:
        changed = copy.deepcopy(value); changed["observations"]["live_gates"][gate] = False
        assert not assess(changed)["live_local_serving_security_validated"], gate
    deterministic = fixture(); deterministic["observations"]["live_gates"] = value["observations"]["live_gates"]
    assert not assess(deterministic)["live_local_serving_security_validated"]


def test_private_key_material_rejected():
    value = fixture(); value["observations"]["tls"][0]["case"] = "-----BEGIN PRIVATE KEY-----"
    with pytest.raises(EvidenceRejected, match="sensitive"): assess(value)


@pytest.mark.parametrize("material", [
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "Authorization: Bearer redacted-credential-material",
    "Bearer eyJabcdefghijk.eyJabcdefghijk.signaturematerial",
])
def test_evidence_leak_scanner_rejects_sensitive_classes(material):
    assert not evidence_is_sensitive_material_free({"captured": material})


def test_false_sensitive_leak_gate_prevents_live_pass():
    value = live_fixture(); value["observations"]["live_gates"]["sensitive_leak_absent"] = False
    assert not assess(value)["live_local_serving_security_validated"]


def test_default_verifier_uses_latest_canonical_debt_without_obsolete_p11b_items():
    summary = default_summary()
    assert summary["deferred_mastery_items"] == list(DEFERRED_MASTERY_ITEMS)
    assert not any(item.startswith("p11b-production-") for item in summary["deferred_mastery_items"])
    assert summary["live_kubernetes_cluster_validated"] is False
    assert summary["live_local_cloud_security_validated"] is False
    assert summary["live_local_serving_security_validated"] is False


def test_debt_exact(): assert list(DEFERRED_MASTERY_ITEMS) == fixture()["deferred_mastery_items"]


def test_live_manifest_uses_distinct_readiness_and_drain_lifecycle():
    manifest = Path("deploy/p11d/resources.yaml").read_text()
    assert "httpGet: {path: /readyz, port: health}" in manifest
    assert "httpGet: {path: /healthz, port: health}" in manifest
    assert "127.0.0.1:8081/internal/drain" in manifest
    assert "readinessProbe: {tcpSocket" not in manifest


def test_gateway_builds_explicit_client_certificate_context():
    source = Path("apps/p11d_serving_gateway.py").read_text()
    assert "ssl.create_default_context" in source
    assert "load_cert_chain" in source
