from __future__ import annotations

import hashlib
from pathlib import Path

from aegis.detection.security_analytics import digest
from evals.p11e_fixture import DEFERRED_MASTERY_ITEMS as P11E_DEBT

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "p11f-detection-engineering.v1"
DEFERRED_MASTERY_ITEMS = P11E_DEBT + (
    "p11f-production-siem-platform",
    "p11f-production-log-pipeline-scale",
    "p11f-production-cloud-native-security-telemetry",
    "p11f-production-kubernetes-audit-ingestion",
    "p11f-production-detection-tuning-baselines",
    "p11f-production-soc-case-management",
    "p11f-production-threat-intelligence-enrichment",
    "p11f-production-retention-compliance-governance",
)

DOMAINS = (
    "application_agent", "identity_iam", "serving_network",
    "kubernetes_platform", "supply_chain", "cross_source_correlation",
)

MALICIOUS = {
    "application_agent": (
        "prompt_injection", "cross_tenant_rag", "approval_bypass",
        "unauthorized_high_impact_tool", "tool_poisoning", "memory_poisoning",
    ),
    "identity_iam": (
        "wrong_audience", "cross_workload_exchange", "revoked_credential_replay",
        "privilege_escalation", "cross_tenant_secret_key",
    ),
    "serving_network": (
        "trusted_header_spoof", "mtls_identity_failure", "request_rate_abuse",
        "concurrency_exhaustion", "oversized_body", "direct_backend_probe",
    ),
    "kubernetes_platform": (
        "privileged_pod", "forbidden_capability", "rbac_escalation",
        "forbidden_secret_access", "cross_namespace", "protected_backend_probe",
    ),
    "supply_chain": (
        "vulnerable_candidate", "tag_drift", "invalid_receipt",
        "poisoned_signed_release", "quarantined_digest_replay", "revoked_signer_replay",
    ),
    "cross_source_correlation": (
        "complete_chain", "out_of_order_within_skew", "benign_flood_between_stages",
    ),
}

BENIGN = (
    "normal_rag", "approved_tool", "isolated_authorization_denial",
    "normal_broker_operation", "valid_serving_request", "safe_request_rate",
    "valid_mtls", "ordinary_kubernetes_read", "expected_admission",
    "clean_image_release", "clean_model_replacement", "legitimate_out_of_order",
    "duplicate_http_retry",
)

LIVE_GATE_NAMES = (
    "collector_started", "collector_http_reached", "sqlite_store_created",
    "signed_producer_accepted", "invalid_signature_denied", "unknown_source_denied",
    "source_authorization_enforced", "duplicate_replay_deduped",
    "body_size_limit_enforced", "timestamp_policy_enforced",
    "secret_minimization_enforced", "rule_bundle_loaded",
    "rule_bundle_hash_verified", "malicious_case_alerted",
    "benign_case_not_alerted", "cross_event_correlation_alerted",
    "correlation_evasion_cases_exercised", "alert_dedup_exercised",
    "alert_store_persisted", "event_chain_valid", "alert_evidence_valid",
    "actual_http_security_denial_observed",
    "actual_kubernetes_security_denial_observed", "actual_source_adapters_ingested",
    "incident_snapshot_generated", "sensitive_leak_absent", "cleanup_complete",
)

LIVE_DATA_NAMES = (
    "rule_bundle_sha256", "event_store_snapshot_sha256", "event_chain_sha256",
    "alert_assessment_sha256", "incident_snapshot_sha256",
)


def fixture_rule_bundle_sha256() -> str:
    items = []
    for path in sorted((ROOT / "detections/p11f").glob("*.json")):
        items.append({"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return digest(items)


def cases() -> list[dict]:
    values = []
    for domain, names in MALICIOUS.items():
        values.extend({"case": name, "domain": domain, "expected": "ALERT", "observed": "ALERT", "executed": True} for name in names)
    values.extend({"case": name, "domain": "benign", "expected": "NO_HIGH_ALERT", "observed": "NO_HIGH_ALERT", "executed": True} for name in BENIGN)
    return values


def empty_live_gates() -> dict:
    return {**{name: False for name in LIVE_GATE_NAMES}, **{name: "" for name in LIVE_DATA_NAMES}}


def fixture() -> dict:
    return {
        "phase": "P11-F", "schema_version": SCHEMA_VERSION,
        "execution_mode": "deterministic", "environment_classification": "DETERMINISTIC_FIXTURE",
        "fixture_rule_bundle_sha256": fixture_rule_bundle_sha256(),
        "raw_cases": cases(), "live_gates": empty_live_gates(),
        "production_siem_validation_claimed": False,
        "professional_mastery_complete": False,
        "deferred_mastery_items": list(DEFERRED_MASTERY_ITEMS),
    }
