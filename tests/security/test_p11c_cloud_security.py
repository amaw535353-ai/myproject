import copy
import json
import time

import pytest

from aegis.platform.cloud_security import (
    AuditTrail, Credential, IAM, IdentityBroker, LocalKMS, MetadataService,
    SecurityDenied, SyntheticTokenIssuer, canonical_bytes, digest,
)
from evals.p11c_cloud_security import EvidenceRejected, assess, validate_evidence
from evals.p11c_fixture import DEFERRED_MASTERY_ITEMS, fixture
from scripts.run_p11c_cloud_security_lab import TOKEN_DURATION


def case(group, name):
    return next(x for x in assess(fixture())["raw_observations"][group] if x["case"] == name)


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
    gates = {"cluster_created": True, "api_reached": True, "node_ready": True, "serviceaccount_token_obtained": True,
             "tokenreview_api_exercised": True, "valid_identity_accepted": True, "wrong_audience_denied": True, "cross_workload_denied": True}
    assert assess(fixture("live", gates))["live_local_cloud_security_validated"]
    gates["tokenreview_api_exercised"] = False
    assert not assess(fixture("live", gates))["live_local_cloud_security_validated"]


def test_incomplete_containment_blocks_live():
    value = fixture("live", {k: True for k in ("cluster_created", "api_reached", "node_ready", "serviceaccount_token_obtained", "tokenreview_api_exercised", "valid_identity_accepted", "wrong_audience_denied", "cross_workload_denied")})
    value["observations"]["incident_response"]["identity_revoked"] = False
    assert not assess(value)["live_local_cloud_security_validated"]


def test_live_token_duration_respects_k3s_minimum(): assert TOKEN_DURATION == "10m"
