from __future__ import annotations

import json

from aegis.platform.kubernetes_enforcement import (
    KubernetesEnforcementAnalyzer,
    VulnerableKubernetesEnforcementAnalyzer,
    clean_evidence,
    evidence_digest,
    with_change,
)


def adversarial_cases():
    base = clean_evidence()
    mutations = [
        {"cluster_uid": ""},
        {"admission_rejected_privileged": False},
        {"admission_rejected_host_namespaces": False},
        {"admission_rejected_host_path": False},
        {"admission_rejected_added_capabilities": False},
        {"admission_rejected_privilege_escalation": False},
        {"secret_list_denied": False},
        {"pod_create_denied": False},
        {"rolebinding_create_denied": False},
        {"clusterrolebinding_create_denied": False},
        {"cross_namespace_secret_get_denied": False},
        {"projected_token_used": False},
        {"token_audience": "kubernetes.default.svc"},
        {"token_ttl_seconds": 3600},
        {"stolen_token_wrong_audience_denied": False},
        {"stolen_token_post_containment_denied": False},
        {"network_policy_enforced_by_cni": False},
        {"cross_namespace_connection_denied": False},
        {"arbitrary_egress_denied": False},
        {"kubernetes_api_direct_egress_denied": False},
        {"metadata_service_egress_denied": False},
        {"compromised_pod_terminated": False},
        {"compromised_identity_fenced": False},
        {"clean_replacement_ready": False},
        {"clean_replacement_uses_new_pod_uid": False},
        {"audit_detected_compromise": False},
        {"audit_records_admission_denials": False},
        {"audit_records_rbac_denials": False},
        {"audit_records_containment": False},
    ]
    return [with_change(base, **mutation) for mutation in mutations]


def main() -> int:
    hardened = KubernetesEnforcementAnalyzer()
    vulnerable = VulnerableKubernetesEnforcementAnalyzer()
    clean = clean_evidence()
    cases = adversarial_cases()
    vulnerable_asr = sum(vulnerable.evaluate(case).decision == "allow" for case in cases)
    hardened_asr = sum(hardened.evaluate(case).decision == "allow" for case in cases)
    safe_cases = [clean, with_change(clean, evidence_id="safe-2"), with_change(clean, evidence_id="safe-3"), with_change(clean, evidence_id="safe-4")]
    safe_task_rate = sum(hardened.evaluate(case).decision == "allow" for case in safe_cases)
    report = {
        "phase": "P11-B",
        "adversarial_cases": len(cases),
        "vulnerable_asr": f"{vulnerable_asr}/{len(cases)}",
        "hardened_asr": f"{hardened_asr}/{len(cases)}",
        "hardened_fpr": f"{len(safe_cases) - safe_task_rate}/{len(safe_cases)}",
        "safe_task_rate": f"{safe_task_rate}/{len(safe_cases)}",
        "clean_evidence_sha256": evidence_digest(clean),
        "clean_decision": hardened.evaluate(clean).decision,
        "live_cluster_claim_boundary": "synthetic evaluation only; live mastery requires run_p11b_kubernetes_lab.py evidence",
    }
    print(json.dumps(report, sort_keys=True))
    if vulnerable_asr != len(cases) or hardened_asr != 0 or safe_task_rate != len(safe_cases):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
