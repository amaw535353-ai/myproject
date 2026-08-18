import copy
import base64
import json
import time

import pytest

from aegis.platform.cloud_security import (
    AuditTrail, Credential, IAM, IdentityBroker, LocalKMS, MetadataService,
    SecurityDenied, SyntheticTokenIssuer, canonical_bytes, digest,
)
from evals.p11c_cloud_security import EvidenceRejected, assess, validate_evidence
from evals.p11c_fixture import (
    DEFERRED_MASTERY_ITEMS, LIVE_GATE_NAMES, build_observations, fixture,
    run_control_plane_scenario,
)
from scripts import run_p11c_cloud_security_lab as live_lab
from scripts.run_p11c_cloud_security_lab import TOKEN_DURATION


def case(group, name):
    return next(x for x in assess(fixture())["raw_observations"][group] if x["case"] == name)


def live_fixture():
    value = fixture()
    value["execution_mode"] = "live"
    value["environment_classification"] = "PROVIDER_NEUTRAL_LOCAL_K3D"
    value["observations"]["live_gates"] = {
        **{name: True for name in LIVE_GATE_NAMES},
        "cluster_identity_sha256": "a" * 64,
        "intended_token_expiry_epoch": int(time.time()) + 300,
    }
    return value


def test_canonical_hash_is_stable(): assert canonical_bytes({"b": 1, "a": 2}) == canonical_bytes({"a": 2, "b": 1})
def test_deterministic_contract_passes(): assert assess(fixture())["ASR"]["numerator"] == 0
def test_wrong_audience_denied(): assert case("identity", "wrong_audience")["observed"] == "DENY"
def test_wrong_namespace_denied(): assert case("identity", "wrong_namespace")["observed"] == "DENY"
def test_wrong_service_account_denied(): assert case("identity", "wrong_service_account")["observed"] == "DENY"
def test_cross_tenant_identity_denied(): assert case("identity", "cross_tenant")["observed"] == "DENY"
def test_revoked_identity_denied(): assert case("identity", "revoked_identity")["observed"] == "DENY"
def test_scoped_iam_allowed(): assert case("iam", "scoped_encrypt")["observed"] == "ALLOW"
def test_cross_tenant_iam_denied(): assert case("iam", "cross_tenant_secret")["observed"] == "DENY"
def test_wildcard_escalation_denied(): assert case("iam", "wildcard_enumeration")["observed"] == "DENY"
def test_policy_mutation_denied(): assert case("iam", "policy_mutation")["observed"] == "DENY"
def test_delegation_denied(): assert case("iam", "credential_delegation")["observed"] == "DENY"
def test_kms_round_trip(): assert case("kms", "round_trip")["observed"] == "ALLOW"
def test_ciphertext_tamper_rejected(): assert case("kms", "ciphertext_tamper")["observed"] == "DENY"
def test_wrong_context_rejected(): assert case("kms", "wrong_resource_context")["observed"] == "DENY"
def test_cross_tenant_decrypt_rejected(): assert case("kms", "cross_tenant_key")["observed"] == "DENY"
def test_key_rotation_semantics():
    assert case("kms", "previous_decrypt_only")["observed"] == "ALLOW"
    assert case("kms", "revoked_version")["observed"] == "DENY"
def test_secret_retrieval(): assert case("secrets", "current_retrieval")["observed"] == "ALLOW"
def test_secret_rotation(): assert case("secrets", "authorized_rotation")["observed"] == "ALLOW"
def test_old_secret_denied(): assert case("secrets", "old_retired")["observed"] == "DENY"
def test_cross_tenant_secret_denied(): assert case("secrets", "cross_tenant")["observed"] == "DENY"
def test_plaintext_absent_from_evidence():
    text = json.dumps(assess(fixture()))
    assert "synthetic-secret-v1" not in text and "synthetic-secret-v2" not in text
def test_metadata_token_required(): assert case("metadata", "missing_token")["observed"] == "DENY"
def test_invalid_metadata_token_denied(): assert case("metadata", "invalid_token")["observed"] == "DENY"
def test_cross_workload_metadata_denied(): assert case("metadata", "cross_workload")["observed"] == "DENY"
def test_ssrf_credential_theft_denied(): assert case("metadata", "ssrf_untrusted")["observed"] == "DENY"
def test_incident_recovery_complete(): assert all(assess(fixture())["incident_response"].values())


def test_tampered_assessment_hash_rejected():
    value = fixture(); value["assessment_sha256"] = "0" * 64
    with pytest.raises(EvidenceRejected, match="assessment hash"): validate_evidence(value)


def test_caller_summary_recomputed():
    value = fixture(); value["ASR"] = {"numerator": 0, "denominator": 0, "value": 0}
    with pytest.raises(EvidenceRejected, match="caller summary"): validate_evidence(value)


def test_mastery_debt_preserved():
    value = fixture(); value["deferred_mastery_items"] = []
    with pytest.raises(EvidenceRejected, match="mastery debt"): assess(value)


def test_production_claim_rejected():
    value = fixture(); value["production_cloud_validation_claimed"] = True
    with pytest.raises(EvidenceRejected, match="forbidden"): assess(value)


def test_audit_chain_tamper_rejected():
    value = fixture(); value["audit"]["events"][0]["decision"] = "DENY"
    with pytest.raises(EvidenceRejected, match="audit"): assess(value)


def test_live_flag_requires_all_live_gates():
    value = live_fixture()
    assert assess(value)["live_local_cloud_security_validated"]
    for gate in LIVE_GATE_NAMES:
        missing = copy.deepcopy(value)
        missing["observations"]["live_gates"][gate] = False
        assert not assess(missing)["live_local_cloud_security_validated"], gate


def test_incomplete_containment_blocks_live():
    value = live_fixture()
    value["observations"]["incident_response"]["identity_revoked"] = False
    assert not assess(value)["live_local_cloud_security_validated"]


def test_live_token_duration_respects_k3s_minimum(): assert TOKEN_DURATION == "10m"


def test_broker_credential_expiry_is_bound_to_verified_token():
    now = int(time.time())
    claims = {"cluster": "cluster-uid", "namespace": "tenant-acme", "service_account": "inference",
              "tenant": "acme", "audience": "aegisdesk-cloud-broker",
              "subject": "system:serviceaccount:tenant-acme:inference", "expiry": now + 30}
    broker = IdentityBroker(AuditTrail(), lambda _: claims, expected_cluster="cluster-uid")
    assert broker.exchange("reviewed-token").expires_at == claims["expiry"]
    claims["expiry"] = now + 1000
    assert broker.exchange("reviewed-token-2").expires_at <= now + broker.MAX_CREDENTIAL_TTL_SECONDS + 1


def _jwt(payload):
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"header.{encoded}.signature"


def test_verified_identity_decodes_actual_expiry_only_after_tokenreview(monkeypatch):
    expiry = int(time.time()) + 300
    token = _jwt({"aud": [live_lab.EXPECTED_AUDIENCE], "exp": expiry,
                  "kubernetes.io": {"namespace": "tenant-acme", "serviceaccount": {"name": "inference"}}})
    monkeypatch.setattr(live_lab, "tokenreview", lambda *_: {
        "authenticated": True, "username": "system:serviceaccount:tenant-acme:inference",
        "audiences": [live_lab.EXPECTED_AUDIENCE]})
    identity = live_lab.verified_kubernetes_identity(token, "api-derived-cluster-uid")
    assert identity["expiry"] == expiry
    assert identity["cluster"] == "api-derived-cluster-uid"


def test_failed_tokenreview_is_never_locally_trusted(monkeypatch):
    monkeypatch.setattr(live_lab, "tokenreview", lambda *_: {"authenticated": False, "username": "", "audiences": []})
    monkeypatch.setattr(live_lab, "decode_payload_after_tokenreview",
                        lambda _: pytest.fail("JWT decoded before TokenReview authentication"))
    with pytest.raises(SecurityDenied, match="TOKENREVIEW_DENIED"):
        live_lab.verified_kubernetes_identity("header.payload.signature", "cluster-uid")


def test_deterministic_fixture_cannot_supply_live_identity_fallback():
    with pytest.raises(ValueError, match="TokenReview-backed broker"):
        build_observations(live_identity={})


def test_live_runner_has_no_synthetic_issuer_in_integrated_path():
    source = live_lab.Path(live_lab.__file__).read_text()
    assert "SyntheticTokenIssuer" not in source
    assert 'get", "namespace", "kube-system"' in source
    assert source.count('request_token("inference", "tenant-acme")') >= 2


def test_injected_credential_drives_services_and_replacement_generation_advances():
    audit = AuditTrail(); issuer = SyntheticTokenIssuer()
    broker = IdentityBroker(audit, issuer.verify)
    initial = broker.exchange(issuer.issue())

    def replacement():
        broker.recover(initial.principal_id)
        return broker.exchange(issuer.issue())

    gates = live_fixture()["observations"]["live_gates"]
    observations, _ = run_control_plane_scenario(
        broker=broker, initial_credential=initial, replacement_credential_factory=replacement,
        audit=audit, identity_cases=[], live_gates=gates)
    live = observations["live_gates"]
    assert all(live[name] for name in (
        "live_credential_used_for_iam", "live_credential_used_for_kms",
        "live_credential_used_for_secrets", "live_credential_used_for_metadata",
        "compromised_live_credential_revoked", "replacement_generation_advanced",
        "live_safe_operation_restored"))
    with pytest.raises(SecurityDenied, match="STALE_OR_REVOKED"):
        broker.authenticate(initial.token)


def test_cross_workload_live_gate_requires_authentication_and_broker_denial():
    value = live_fixture()
    for gate in ("attacker_token_authenticated", "broker_cross_workload_exchange_denied"):
        changed = copy.deepcopy(value)
        changed["observations"]["live_gates"][gate] = False
        assert not assess(changed)["live_local_cloud_security_validated"]
