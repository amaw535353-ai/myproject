from __future__ import annotations

import base64
import copy
import json

import pytest

from aegis.platform.supply_chain_security import (
    Ed25519EnvelopeSigner, LiveArtifactSafetyScanner, QuarantineRegistry, SignedEnvelope,
    SupplyChainDenied, cache_read, evidence_is_clean, evaluate_vulnerability_report,
    require_receipt_candidate, sha256, validate_sbom, validate_two_candidate_evidence,
    verify_envelope, verify_provenance, verify_receipt,
)
from evals.p11e_fixture import DEFERRED_MASTERY_ITEMS, LIVE_DATA_NAMES, LIVE_GATE_NAMES, fixture
from evals.p11e_supply_chain_security import EvidenceRejected, assess, validate_evidence

IMAGE = "registry.local/aegisdesk@sha256:" + "a" * 64

def sbom(image: str = IMAGE) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"externalReferences": [{"url": image}]}}, "components": [{"type": "library", "name": "aegisdesk", "version": "1"}]}

def test_deterministic_metrics_are_derived_from_raw_cases() -> None:
    out = assess(fixture())
    assert out["ASR"]["numerator"] == out["FPR"]["numerator"] == 0
    assert out["SafeTaskRate"]["numerator"] == out["SafeTaskRate"]["denominator"]
    assert out["ASR"]["denominator"] == 45
    assert out["SafeTaskRate"]["denominator"] == 15

def test_canonical_hashing_and_assessment_tamper_rejection() -> None:
    assert sha256({"b": 2, "a": 1}) == sha256({"a": 1, "b": 2})
    evidence = assess(fixture()); evidence["assessment_sha256"] = "0" * 64
    with pytest.raises(EvidenceRejected): validate_evidence(evidence)

def test_schema_summary_debt_and_claim_boundaries() -> None:
    for mutate in (
        lambda x: x.pop("observations"),
        lambda x: x.update(production_supply_chain_validation_claimed=True),
        lambda x: x.update(professional_mastery_complete=True),
        lambda x: x.update(deferred_mastery_items=[]),
    ):
        raw = fixture(); mutate(raw)
        with pytest.raises(EvidenceRejected): assess(raw)
    raw = fixture(); raw["observations"]["sbom"][0]["observed"] = "ALLOW"
    assert assess(raw)["ASR"]["numerator"] == 1

def test_sbom_subject_metadata_and_tamper_binding() -> None:
    assert validate_sbom(sbom(), expected_image_digest=IMAGE)["component_count"] == 1
    with pytest.raises(SupplyChainDenied): validate_sbom(sbom("other@sha256:" + "b"*64), expected_image_digest=IMAGE)
    bad = sbom(); bad["components"][0].pop("name")
    with pytest.raises(SupplyChainDenied): validate_sbom(bad, expected_image_digest=IMAGE)
    package_free = sbom(); package_free.pop("components")
    assert validate_sbom(package_free, expected_image_digest=IMAGE)["component_count"] == 0

def test_scanner_subject_db_and_policy() -> None:
    report = {"source": {"target": {"userInput": IMAGE}}, "matches": []}
    assert evaluate_vulnerability_report(report, expected_image_digest=IMAGE, db_usable=True)["admitted"] is True
    with pytest.raises(SupplyChainDenied): evaluate_vulnerability_report(report, expected_image_digest=IMAGE, db_usable=False)
    blocked = copy.deepcopy(report); blocked["matches"] = [{"vulnerability": {"id": "CVE-X", "severity": "High", "fix": {"versions": ["2"]}}}]
    assert evaluate_vulnerability_report(blocked, expected_image_digest=IMAGE, db_usable=True)["admitted"] is False

def test_signature_wrong_signer_unsigned_and_substitution() -> None:
    signer = Ed25519EnvelopeSigner(); envelope = signer.sign({"image": IMAGE})
    assert verify_envelope(envelope, signer.public_key)["image"] == IMAGE
    with pytest.raises(SupplyChainDenied): verify_envelope(envelope, Ed25519EnvelopeSigner().public_key)
    tampered = SignedEnvelope({"image": IMAGE + "x"}, envelope.signature)
    with pytest.raises(SupplyChainDenied): verify_envelope(tampered, signer.public_key)

def test_provenance_binds_every_security_subject() -> None:
    signer = Ed25519EnvelopeSigner(); payload = {"source_commit": "c"*40, "image_digest": IMAGE, "sbom_sha256": "b"*64, "scanner_report_sha256": "c"*64, "policy_version": "p11e-supply-chain-policy.v1", "build_parameters": {"network": "default"}}
    env = signer.sign(payload)
    assert verify_provenance(env, signer.public_key, source_commit="c"*40, image_digest=IMAGE, sbom_sha256="b"*64, scanner_sha256="c"*64)
    with pytest.raises(SupplyChainDenied): verify_provenance(env, signer.public_key, source_commit="d"*40, image_digest=IMAGE, sbom_sha256="b"*64, scanner_sha256="c"*64)

def test_receipt_expiry_tamper_image_and_fail_closed() -> None:
    signer = Ed25519EnvelopeSigner(); payload = {"image": IMAGE, "issued_at": 100, "expires_at": 200, "policy_version": "p11e-supply-chain-policy.v1", "sbom_sha256": "a"*64, "scanner_report_sha256": "b"*64, "provenance_sha256": "c"*64, "signer_fingerprint": signer.fingerprint}
    env = signer.sign(payload)
    assert verify_receipt(env, signer.public_key, image=IMAGE, now=150)
    with pytest.raises(SupplyChainDenied): verify_receipt(env, signer.public_key, image=IMAGE, now=201)
    with pytest.raises(SupplyChainDenied): verify_receipt(env, signer.public_key, image=IMAGE.replace("a", "d"), now=150)
    with pytest.raises(SupplyChainDenied): verify_receipt(env, Ed25519EnvelopeSigner().public_key, image=IMAGE, now=150)

def test_live_content_scan_blocks_signed_poison_and_never_executes_weights() -> None:
    scanner = LiveArtifactSafetyScanner()
    clean = b'{"architectures":["SyntheticModel"]}'
    assert scanner.scan_json(clean, expected_sha256=sha256(clean))["executed"] is False
    poison = b'{"tokenizer":{"backdoor_trigger":"cf_trigger"}}'
    with pytest.raises(SupplyChainDenied, match="POISON_MARKER"): scanner.scan_json(poison, expected_sha256=sha256(poison))
    with pytest.raises(SupplyChainDenied, match="UNSAFE_SERIALIZATION"): scanner.inspect_opaque(b"pickle-like", artifact_format="pkl", expected_sha256=sha256(b"pickle-like"))

def test_quarantine_and_cache_are_digest_bound() -> None:
    registry = QuarantineRegistry(); digest = sha256(b"poison")
    registry.quarantine(digest, reason="POISON_MARKER", incident_id="inc-1", order=4)
    with pytest.raises(SupplyChainDenied): registry.require_allowed(digest)
    assert cache_read({digest: b"clean"}, digest, sha256(b"clean")) == b"clean"
    with pytest.raises(SupplyChainDenied): cache_read({digest: b"changed"}, digest, sha256(b"clean"))

@pytest.mark.parametrize("secret", ["-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "Authorization: Bearer aaa.bbb.ccc"])
def test_sensitive_material_rejected(secret: str) -> None:
    assert evidence_is_clean({"log": secret}) is False

def test_live_flag_requires_every_gate_and_real_execution_mode() -> None:
    raw = fixture(); raw["execution_mode"] = "live"; raw["environment_classification"] = "LIVE_LOCAL_CODESPACE"
    for key in LIVE_GATE_NAMES: raw["observations"]["live_gates"][key] = True
    for key in LIVE_DATA_NAMES: raw["observations"]["live_gates"][key] = "a"*64
    assert assess(raw)["live_local_supply_chain_security_validated"] is True
    raw["observations"]["live_gates"]["fail_closed_verified"] = False
    assert assess(raw)["live_local_supply_chain_security_validated"] is False
    assert assess(fixture())["live_local_supply_chain_security_validated"] is False

def test_default_debt_is_latest_and_retains_prior_items() -> None:
    from scripts.verify_phase11 import default_summary
    assert default_summary()["deferred_mastery_items"] == list(DEFERRED_MASTERY_ITEMS)
    assert "p11d-production-ingress-load-balancer" in DEFERRED_MASTERY_ITEMS

def test_blocked_serving_candidate_cannot_receive_receipt_but_clean_fixture_can() -> None:
    with pytest.raises(SupplyChainDenied, match="PURPOSE"):
        require_receipt_candidate(purpose="REAL_P11D_DERIVED_NEGATIVE_SECURITY_CASE", scanner_policy_passed=False)
    with pytest.raises(SupplyChainDenied, match="VULNERABILITY"):
        require_receipt_candidate(purpose="P11E_POSITIVE_MECHANISM_VALIDATION", scanner_policy_passed=False)
    require_receipt_candidate(purpose="P11E_POSITIVE_MECHANISM_VALIDATION", scanner_policy_passed=True)

def test_two_candidate_evidence_preserves_negative_and_positive_paths() -> None:
    candidates = {
        "serving_candidate": {"purpose": "REAL_P11D_DERIVED_NEGATIVE_SECURITY_CASE", "scanner_policy_passed": False,
                              "admitted": False, "receipt_issued": False, "cluster_image": "registry/serving@sha256:" + "a"*64},
        "benign_supply_chain_fixture": {"purpose": "P11E_POSITIVE_MECHANISM_VALIDATION", "scanner_policy_passed": True,
                                         "kubernetes_admitted": True, "cluster_image": "registry/fixture@sha256:" + "b"*64},
    }
    validate_two_candidate_evidence(candidates)
    confused = copy.deepcopy(candidates); confused["benign_supply_chain_fixture"]["cluster_image"] = confused["serving_candidate"]["cluster_image"]
    with pytest.raises(SupplyChainDenied, match="CONFUSED"): validate_two_candidate_evidence(confused)

def test_live_pass_requires_blocked_serving_and_complete_clean_chain() -> None:
    raw = fixture(); raw["execution_mode"] = "live"; raw["environment_classification"] = "LIVE_LOCAL_CODESPACE_K3D"
    for key in LIVE_GATE_NAMES: raw["observations"]["live_gates"][key] = True
    for key in ("serving_image_digest", "clean_image_digest", "sbom_sha256", "scanner_report_sha256", "provenance_sha256", "audit_chain_sha256"):
        raw["observations"]["live_gates"][key] = "a"*64
    assert assess(raw)["live_local_supply_chain_security_validated"] is True
    for gate in ("real_serving_candidate_policy_blocked", "real_serving_candidate_receipt_not_issued", "clean_fixture_policy_passed", "clean_fixture_admitted"):
        changed = copy.deepcopy(raw); changed["observations"]["live_gates"][gate] = False
        assert assess(changed)["live_local_supply_chain_security_validated"] is False

def test_integrated_model_incident_uses_existing_successor_key_generation() -> None:
    from scripts.run_p11e_supply_chain_lab import model_scenario
    result = model_scenario()
    assert result["compromised_key_generation_revoked"] is True
    assert result["clean_key_generation_established"] is True
    assert result["clean_replacement_verified"] is True
    assert result["model_bytes_executed"] is False
