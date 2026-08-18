from __future__ import annotations

from pathlib import Path

from aegis.detection.security_analytics import load_rules
from evals.p11e_fixture import DEFERRED_MASTERY_ITEMS as P11E_DEBT

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "p11f-detection-engineering.v2"
DEFERRED_MASTERY_ITEMS = P11E_DEBT + (
    "p11f-production-siem-platform", "p11f-production-log-pipeline-scale",
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

# These are detector inputs. Observed outcomes and executed flags are deliberately
# absent and are added only by execute_fixture() after persisted alerts are read.
MALICIOUS_CASES = (
    {"case":"prompt_injection","domain":"application_agent","expected":"ALERT","events":("PROMPT_INJECTION_BLOCKED",),"expected_rules":("p11f.application.prompt-injection",)},
    {"case":"privilege_escalation","domain":"identity_iam","expected":"ALERT","events":("PRIVILEGE_ESCALATION_DENIED",),"expected_rules":("p11f.identity.privilege-escalation",)},
    {"case":"request_rate_abuse","domain":"serving_network","expected":"ALERT","events":("RATE_ABUSE_DENIED","RATE_ABUSE_DENIED","RATE_ABUSE_DENIED"),"expected_rules":("p11f.serving.rate-abuse",)},
    {"case":"privileged_pod","domain":"kubernetes_platform","expected":"ALERT","events":("PRIVILEGED_POD_DENIED",),"expected_rules":("p11f.kubernetes.privileged-pod",)},
    {"case":"vulnerable_candidate","domain":"supply_chain","expected":"ALERT","events":("VULNERABILITY_POLICY_BLOCKED",),"expected_rules":("p11f.supply-chain.vulnerability-block",)},
    {"case":"complete_chain","domain":"cross_source_correlation","expected":"ALERT","events":("PROMPT_INJECTION_BLOCKED","HIGH_IMPACT_TOOL_DENIED","REVOKED_CREDENTIAL_REPLAY","PRIVILEGED_POD_DENIED","POISONED_RELEASE_BLOCKED"),"transport_order":(0,1,2,3,4),"expected_rules":("p11f.correlation.multi-stage-ai-attack",)},
    {"case":"out_of_order_within_skew","domain":"cross_source_correlation","expected":"ALERT","events":("PROMPT_INJECTION_BLOCKED","HIGH_IMPACT_TOOL_DENIED","REVOKED_CREDENTIAL_REPLAY","PRIVILEGED_POD_DENIED","POISONED_RELEASE_BLOCKED"),"transport_order":(0,2,1,3,4),"expected_rules":("p11f.correlation.multi-stage-ai-attack",)},
    {"case":"benign_flood_between_stages","domain":"cross_source_correlation","expected":"ALERT","events":("PROMPT_INJECTION_BLOCKED","NORMAL_RAG_REQUEST","HIGH_IMPACT_TOOL_DENIED","NORMAL_RAG_REQUEST","REVOKED_CREDENTIAL_REPLAY","PRIVILEGED_POD_DENIED","POISONED_RELEASE_BLOCKED"),"transport_order":(0,1,2,3,4,5,6),"expected_rules":("p11f.correlation.multi-stage-ai-attack",)},
)

BENIGN_CASES = (
    ("normal_rag","NORMAL_RAG_REQUEST"), ("approved_tool","APPROVED_TOOL_CALL"),
    ("isolated_authorization_denial","HIGH_IMPACT_TOOL_DENIED"),
    ("normal_broker_operation","BROKER_CREDENTIAL_ISSUED"),
    ("valid_serving_request","SERVING_REQUEST_ALLOWED"),
    ("safe_request_rate","RATE_ABUSE_DENIED"), ("valid_mtls","MTLS_IDENTITY_VALID"),
    ("ordinary_kubernetes_read","KUBERNETES_READ_ALLOWED"),
    ("expected_admission","ADMISSION_ALLOWED"), ("clean_image_release","IMAGE_ADMITTED"),
    ("clean_model_replacement","MODEL_REPLACEMENT_ALLOWED"),
    ("legitimate_out_of_order","NORMAL_RAG_REQUEST"),
    ("duplicate_http_retry","NORMAL_RAG_REQUEST"),
)

LIVE_GATE_NAMES = (
    "collector_started", "collector_http_reached", "sqlite_store_created",
    "signed_producer_accepted", "invalid_signature_denied", "unknown_source_denied",
    "source_authorization_enforced", "provenance_binding_enforced",
    "duplicate_replay_deduped", "body_size_limit_enforced", "timestamp_policy_enforced",
    "trusted_server_clock_enforced", "secret_minimization_enforced", "rule_bundle_loaded",
    "rule_bundle_hash_verified", "detector_derived_metrics", "malicious_case_alerted",
    "benign_case_not_alerted", "cross_event_correlation_alerted",
    "correlation_evasion_cases_exercised", "alert_dedup_exercised",
    "alert_store_persisted", "event_chain_valid", "alert_evidence_valid",
    "actual_http_security_denial_observed", "actual_kubernetes_security_denial_observed",
    "actual_source_adapters_ingested", "incident_snapshot_generated",
    "sensitive_leak_absent", "cleanup_complete",
)
LIVE_DATA_NAMES = (
    "rule_bundle_sha256", "event_store_snapshot_sha256", "event_chain_sha256",
    "alert_assessment_sha256", "incident_snapshot_sha256",
)

def fixture_rule_bundle_sha256() -> str:
    return load_rules(ROOT / "detections/p11f")[1]

def cases() -> list[dict]:
    values = [dict(item) for item in MALICIOUS_CASES]
    values.extend({"case":name,"domain":"benign","expected":"NO_HIGH_ALERT","events":(event_type,),"expected_rules":()} for name,event_type in BENIGN_CASES)
    return values

def empty_live_gates() -> dict:
    return {**{name:False for name in LIVE_GATE_NAMES}, **{name:"" for name in LIVE_DATA_NAMES}}

def fixture() -> dict:
    return {
        "phase":"P11-F", "schema_version":SCHEMA_VERSION,
        "execution_mode":"deterministic", "environment_classification":"DETERMINISTIC_FIXTURE",
        "fixture_rule_bundle_sha256":fixture_rule_bundle_sha256(),
        "case_definitions":cases(), "live_gates":empty_live_gates(),
        "production_siem_validation_claimed":False, "professional_mastery_complete":False,
        "deferred_mastery_items":list(DEFERRED_MASTERY_ITEMS),
    }
