from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import Enum
import hashlib
import json


class KubernetesRisk(str, Enum):
    LIVE_CLUSTER_UNVERIFIED = "live_cluster_unverified"
    POD_SECURITY_ADMISSION_BYPASS = "pod_security_admission_bypass"
    RBAC_OVERPRIVILEGE = "rbac_overprivilege"
    CROSS_NAMESPACE_ACCESS = "cross_namespace_access"
    SERVICE_ACCOUNT_TOKEN_UNSAFE = "service_account_token_unsafe"
    TOKEN_REPLAY_ACCEPTED = "token_replay_accepted"
    NETWORK_POLICY_UNVERIFIED = "network_policy_unverified"
    NETWORK_ISOLATION_BYPASS = "network_isolation_bypass"
    API_OR_METADATA_EGRESS = "api_or_metadata_egress"
    CONTAINMENT_FAILED = "containment_failed"
    RECOVERY_UNVERIFIED = "recovery_unverified"
    AUDIT_TRAIL_INCOMPLETE = "audit_trail_incomplete"


@dataclass(frozen=True)
class KubernetesEnforcementPolicy:
    expected_namespace: str = "tenant-acme-inference"
    expected_service_account: str = "aegisdesk-inference"
    required_psa_level: str = "restricted"
    expected_token_audience: str = "aegisdesk-inference-runtime"
    max_token_ttl_seconds: int = 600


@dataclass(frozen=True)
class KubernetesEnforcementEvidence:
    evidence_id: str
    collected_at_epoch: int
    cluster_uid: str
    kubernetes_version: str
    cni_name: str
    namespace: str
    service_account: str
    psa_enforce_level: str
    admission_rejected_privileged: bool
    admission_rejected_host_namespaces: bool
    admission_rejected_host_path: bool
    admission_rejected_added_capabilities: bool
    admission_rejected_privilege_escalation: bool
    intended_configmap_get_allowed: bool
    secret_list_denied: bool
    pod_create_denied: bool
    rolebinding_create_denied: bool
    clusterrolebinding_create_denied: bool
    cross_namespace_secret_get_denied: bool
    automount_service_account_token_disabled: bool
    projected_token_used: bool
    token_audience: str
    token_ttl_seconds: int
    stolen_token_wrong_audience_denied: bool
    stolen_token_post_containment_denied: bool
    network_policy_present: bool
    network_policy_enforced_by_cni: bool
    intended_dependency_reachable: bool
    cross_namespace_connection_denied: bool
    arbitrary_egress_denied: bool
    kubernetes_api_direct_egress_denied: bool
    metadata_service_egress_denied: bool
    compromised_pod_terminated: bool
    compromised_identity_fenced: bool
    clean_replacement_ready: bool
    clean_replacement_uses_new_pod_uid: bool
    audit_detected_compromise: bool
    audit_records_admission_denials: bool
    audit_records_rbac_denials: bool
    audit_records_containment: bool
    declared_kubernetes_safe: bool = True


def evidence_digest(e: KubernetesEnforcementEvidence) -> str:
    raw = json.dumps(asdict(e), sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class KubernetesEnforcementAssessment:
    decision: str
    evidence_sha256: str
    risks: tuple[KubernetesRisk, ...]
    live_kubernetes_cluster_validated: bool
    professional_mastery_complete: bool = False


class KubernetesEnforcementAnalyzer:
    def __init__(self, policy: KubernetesEnforcementPolicy | None = None):
        self.policy = policy or KubernetesEnforcementPolicy()

    def evaluate(self, e: KubernetesEnforcementEvidence) -> KubernetesEnforcementAssessment:
        p = self.policy
        risks: list[KubernetesRisk] = []

        def add(risk: KubernetesRisk, bad: bool) -> None:
            if bad and risk not in risks:
                risks.append(risk)

        live_identity = bool(e.cluster_uid and e.kubernetes_version and e.cni_name)
        add(KubernetesRisk.LIVE_CLUSTER_UNVERIFIED, not live_identity)

        admission_ok = (
            e.namespace == p.expected_namespace
            and e.psa_enforce_level == p.required_psa_level
            and e.admission_rejected_privileged
            and e.admission_rejected_host_namespaces
            and e.admission_rejected_host_path
            and e.admission_rejected_added_capabilities
            and e.admission_rejected_privilege_escalation
        )
        add(KubernetesRisk.POD_SECURITY_ADMISSION_BYPASS, not admission_ok)

        rbac_ok = (
            e.service_account == p.expected_service_account
            and e.intended_configmap_get_allowed
            and e.secret_list_denied
            and e.pod_create_denied
            and e.rolebinding_create_denied
            and e.clusterrolebinding_create_denied
        )
        add(KubernetesRisk.RBAC_OVERPRIVILEGE, not rbac_ok)
        add(KubernetesRisk.CROSS_NAMESPACE_ACCESS, not e.cross_namespace_secret_get_denied)

        token_ok = (
            e.automount_service_account_token_disabled
            and e.projected_token_used
            and e.token_audience == p.expected_token_audience
            and 0 < e.token_ttl_seconds <= p.max_token_ttl_seconds
            and e.stolen_token_wrong_audience_denied
        )
        add(KubernetesRisk.SERVICE_ACCOUNT_TOKEN_UNSAFE, not token_ok)
        add(KubernetesRisk.TOKEN_REPLAY_ACCEPTED, not e.stolen_token_post_containment_denied)

        network_verified = e.network_policy_present and e.network_policy_enforced_by_cni
        add(KubernetesRisk.NETWORK_POLICY_UNVERIFIED, not network_verified)
        network_ok = (
            e.intended_dependency_reachable
            and e.cross_namespace_connection_denied
            and e.arbitrary_egress_denied
        )
        add(KubernetesRisk.NETWORK_ISOLATION_BYPASS, not network_ok)
        add(
            KubernetesRisk.API_OR_METADATA_EGRESS,
            not e.kubernetes_api_direct_egress_denied or not e.metadata_service_egress_denied,
        )

        containment_ok = (
            e.compromised_pod_terminated
            and e.compromised_identity_fenced
            and e.stolen_token_post_containment_denied
        )
        add(KubernetesRisk.CONTAINMENT_FAILED, not containment_ok)
        recovery_ok = e.clean_replacement_ready and e.clean_replacement_uses_new_pod_uid
        add(KubernetesRisk.RECOVERY_UNVERIFIED, not recovery_ok)
        audit_ok = (
            e.audit_detected_compromise
            and e.audit_records_admission_denials
            and e.audit_records_rbac_denials
            and e.audit_records_containment
        )
        add(KubernetesRisk.AUDIT_TRAIL_INCOMPLETE, not audit_ok)

        decision = "allow" if not risks else "deny"
        return KubernetesEnforcementAssessment(
            decision=decision,
            evidence_sha256=evidence_digest(e),
            risks=tuple(risks),
            live_kubernetes_cluster_validated=decision == "allow" and live_identity and network_verified,
        )


class VulnerableKubernetesEnforcementAnalyzer:
    def evaluate(self, e: KubernetesEnforcementEvidence) -> KubernetesEnforcementAssessment:
        return KubernetesEnforcementAssessment(
            decision="allow" if e.declared_kubernetes_safe else "deny",
            evidence_sha256=evidence_digest(e),
            risks=(),
            live_kubernetes_cluster_validated=False,
        )


def clean_evidence() -> KubernetesEnforcementEvidence:
    return KubernetesEnforcementEvidence(
        evidence_id="p11b-live-k8s-acme-001",
        collected_at_epoch=1_786_872_000,
        cluster_uid="cluster-live-001",
        kubernetes_version="v1.live",
        cni_name="live-cni",
        namespace="tenant-acme-inference",
        service_account="aegisdesk-inference",
        psa_enforce_level="restricted",
        admission_rejected_privileged=True,
        admission_rejected_host_namespaces=True,
        admission_rejected_host_path=True,
        admission_rejected_added_capabilities=True,
        admission_rejected_privilege_escalation=True,
        intended_configmap_get_allowed=True,
        secret_list_denied=True,
        pod_create_denied=True,
        rolebinding_create_denied=True,
        clusterrolebinding_create_denied=True,
        cross_namespace_secret_get_denied=True,
        automount_service_account_token_disabled=True,
        projected_token_used=True,
        token_audience="aegisdesk-inference-runtime",
        token_ttl_seconds=300,
        stolen_token_wrong_audience_denied=True,
        stolen_token_post_containment_denied=True,
        network_policy_present=True,
        network_policy_enforced_by_cni=True,
        intended_dependency_reachable=True,
        cross_namespace_connection_denied=True,
        arbitrary_egress_denied=True,
        kubernetes_api_direct_egress_denied=True,
        metadata_service_egress_denied=True,
        compromised_pod_terminated=True,
        compromised_identity_fenced=True,
        clean_replacement_ready=True,
        clean_replacement_uses_new_pod_uid=True,
        audit_detected_compromise=True,
        audit_records_admission_denials=True,
        audit_records_rbac_denials=True,
        audit_records_containment=True,
    )


def with_change(e: KubernetesEnforcementEvidence, **changes: object) -> KubernetesEnforcementEvidence:
    return replace(e, **changes)
