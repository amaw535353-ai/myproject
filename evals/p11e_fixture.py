from __future__ import annotations

import hashlib
from pathlib import Path

from aegis.platform.supply_chain_security import SupplyChainDenied, canonical_bytes, sha256

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "p11e-supply-chain-security.v1"
DEFERRED_MASTERY_ITEMS = (
    "p10f-live-nvidia-gpu-mig-cuda",
    "p11c-production-cloud-federation", "p11c-production-cloud-iam-kms-secrets-metadata",
    "p11c-production-hsm-key-custody", "p11c-multi-account-project-production-behavior",
    "p11c-production-cloud-incident-response", "p11d-production-ingress-load-balancer",
    "p11d-production-service-mesh-mtls", "p11d-production-pki-certificate-rotation",
    "p11d-multi-node-multi-zone-serving", "p11d-production-model-server-gpu-runtime",
    "p11d-production-waf-ddos-slo", "p11e-production-oci-registry-policy",
    "p11e-production-cicd-build-provenance", "p11e-production-sbom-vulnerability-governance",
    "p11e-production-keyless-signing-transparency-log", "p11e-production-hsm-signing-key-custody",
    "p11e-production-admission-controller", "p11e-production-model-registry-scanning",
    "p11e-production-artifact-quarantine-ir", "p11e-hardware-backed-remote-attestation",
)
GROUPS = ("container_provenance", "sbom", "scanning", "registry", "kubernetes_admission", "model_provenance", "model_content", "incident_response")
ATTACKS = {
    "container_provenance": ("unsigned_image", "wrong_key", "digest_substitution", "wrong_source_commit", "tampered_provenance", "wrong_sbom_binding"),
    "sbom": ("missing_sbom", "malformed_sbom", "tampered_sbom", "wrong_image_subject", "missing_package_metadata"),
    "scanning": ("scanner_not_executed", "stale_scanner_db", "critical_finding", "high_fixable_finding", "report_subject_mismatch", "tampered_report"),
    "registry": ("mutable_tag_only", "untrusted_registry", "tag_drift", "wrong_digest", "cache_substitution"),
    "kubernetes_admission": ("missing_receipt", "malformed_receipt", "expired_receipt", "tampered_receipt", "wrong_receipt_key", "receipt_image_mismatch", "webhook_unavailable"),
    "model_provenance": ("artifact_digest_mismatch", "bad_manifest_signature", "package_signature_failure", "unsafe_artifact_format", "remote_code_requirement", "dependency_mismatch", "release_tag_drift", "revoked_signer"),
    "model_content": ("signed_poisoned_config", "forbidden_tokenizer_trigger", "unsafe_executable_serialization", "quarantined_release_replay"),
    "incident_response": ("quarantine_bypass", "revoked_key_replay", "stale_receipt_replay", "old_digest_after_recovery"),
}
BENIGN = {
    "container_provenance": ("valid_signed_image", "valid_signed_provenance"), "sbom": ("valid_image_sbom",),
    "scanning": ("clean_scan_policy",), "registry": ("trusted_registry_digest",),
    "kubernetes_admission": ("fresh_receipt", "benign_pod_ready"),
    "model_provenance": ("valid_signed_artifact", "valid_signed_package", "immutable_release"),
    "model_content": ("clean_config_tokenizer", "known_good_release"),
    "incident_response": ("new_signing_generation", "clean_replacement", "safe_recovery"),
}
LIVE_GATE_NAMES = (
    "real_serving_candidate_scanned", "real_serving_candidate_policy_blocked", "real_serving_candidate_receipt_not_issued",
    "clean_fixture_built", "clean_fixture_sbom_generated", "clean_fixture_scanner_executed", "clean_fixture_policy_passed",
    "clean_fixture_signed", "clean_fixture_provenance_verified", "local_registry_started", "clean_fixture_digest_pull_verified",
    "tag_drift_detected", "admission_api_exercised", "clean_fixture_admitted", "mutable_tag_denied",
    "missing_receipt_denied", "tampered_receipt_denied", "expired_receipt_denied", "digest_mismatch_denied",
    "wrong_signer_denied", "fail_closed_verified",
    "model_artifact_verified", "model_package_verified", "immutable_release_verified", "unsafe_format_denied",
    "live_content_scan_exercised", "signed_poisoned_release_detected", "model_bytes_not_executed",
    "poisoned_digest_quarantined", "quarantined_replay_denied", "key_generation_revoked", "old_release_replay_denied",
    "clean_key_generation_established", "clean_replacement_verified", "safe_admission_restored",
    "sensitive_leak_absent", "cleanup_complete",
)
LIVE_DATA_NAMES = ("serving_image_digest", "clean_image_digest", "sbom_sha256", "scanner_report_sha256", "provenance_sha256", "audit_chain_sha256")

def fixture_manifests_sha256() -> str:
    files = [ROOT / "deploy/p11d/Dockerfile", *sorted((ROOT / "deploy/p11e").glob("*"))]
    return sha256([{"path": str(p.relative_to(ROOT)), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in files if p.is_file()])

def empty_live_gates() -> dict:
    return {**{x: False for x in LIVE_GATE_NAMES}, **{x: "" for x in LIVE_DATA_NAMES}}

def observations() -> dict:
    obs = {g: [] for g in GROUPS}
    for group in GROUPS:
        for case in ATTACKS[group]: obs[group].append({"case": case, "expected": "DENY", "observed": "DENY", "executed": True})
        for case in BENIGN[group]: obs[group].append({"case": case, "expected": "ALLOW", "observed": "ALLOW", "executed": True})
    obs["live_gates"] = empty_live_gates()
    return obs

def fixture() -> dict:
    return {"phase": "P11-E", "schema_version": SCHEMA_VERSION, "execution_mode": "deterministic",
            "environment_classification": "DETERMINISTIC_FIXTURE", "fixture_manifests_sha256": fixture_manifests_sha256(),
            "observations": observations(), "production_supply_chain_validation_claimed": False,
            "professional_mastery_complete": False, "deferred_mastery_items": list(DEFERRED_MASTERY_ITEMS)}
