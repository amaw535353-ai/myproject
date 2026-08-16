from aegis.platform.kubernetes_enforcement import (
    KubernetesEnforcementAnalyzer,
    KubernetesRisk,
    VulnerableKubernetesEnforcementAnalyzer,
    clean_evidence,
    with_change,
)


def test_clean_live_evidence_allows() -> None:
    result = KubernetesEnforcementAnalyzer().evaluate(clean_evidence())
    assert result.decision == "allow"
    assert result.risks == ()
    assert result.live_kubernetes_cluster_validated is True


def test_vulnerable_baseline_trusts_declaration() -> None:
    evidence = with_change(clean_evidence(), admission_rejected_privileged=False)
    assert VulnerableKubernetesEnforcementAnalyzer().evaluate(evidence).decision == "allow"
    hardened = KubernetesEnforcementAnalyzer().evaluate(evidence)
    assert hardened.decision == "deny"
    assert KubernetesRisk.POD_SECURITY_ADMISSION_BYPASS in hardened.risks


def test_rbac_overprivilege_denied() -> None:
    result = KubernetesEnforcementAnalyzer().evaluate(with_change(clean_evidence(), secret_list_denied=False))
    assert KubernetesRisk.RBAC_OVERPRIVILEGE in result.risks


def test_cross_namespace_access_denied() -> None:
    result = KubernetesEnforcementAnalyzer().evaluate(with_change(clean_evidence(), cross_namespace_secret_get_denied=False))
    assert KubernetesRisk.CROSS_NAMESPACE_ACCESS in result.risks


def test_token_audience_and_ttl_enforced() -> None:
    result = KubernetesEnforcementAnalyzer().evaluate(
        with_change(clean_evidence(), token_audience="kubernetes.default.svc", token_ttl_seconds=3600)
    )
    assert KubernetesRisk.SERVICE_ACCOUNT_TOKEN_UNSAFE in result.risks


def test_stolen_token_replay_after_containment_denied() -> None:
    result = KubernetesEnforcementAnalyzer().evaluate(with_change(clean_evidence(), stolen_token_post_containment_denied=False))
    assert KubernetesRisk.TOKEN_REPLAY_ACCEPTED in result.risks
    assert KubernetesRisk.CONTAINMENT_FAILED in result.risks


def test_cni_enforcement_must_be_live() -> None:
    result = KubernetesEnforcementAnalyzer().evaluate(with_change(clean_evidence(), network_policy_enforced_by_cni=False))
    assert KubernetesRisk.NETWORK_POLICY_UNVERIFIED in result.risks
    assert result.live_kubernetes_cluster_validated is False


def test_cross_namespace_network_bypass_denied() -> None:
    result = KubernetesEnforcementAnalyzer().evaluate(with_change(clean_evidence(), cross_namespace_connection_denied=False))
    assert KubernetesRisk.NETWORK_ISOLATION_BYPASS in result.risks


def test_api_and_metadata_egress_denied() -> None:
    result = KubernetesEnforcementAnalyzer().evaluate(
        with_change(clean_evidence(), kubernetes_api_direct_egress_denied=False, metadata_service_egress_denied=False)
    )
    assert KubernetesRisk.API_OR_METADATA_EGRESS in result.risks


def test_recovery_requires_new_pod_identity() -> None:
    result = KubernetesEnforcementAnalyzer().evaluate(with_change(clean_evidence(), clean_replacement_uses_new_pod_uid=False))
    assert KubernetesRisk.RECOVERY_UNVERIFIED in result.risks


def test_audit_chain_is_required() -> None:
    result = KubernetesEnforcementAnalyzer().evaluate(with_change(clean_evidence(), audit_records_containment=False))
    assert KubernetesRisk.AUDIT_TRAIL_INCOMPLETE in result.risks


def test_empty_live_cluster_identity_is_not_mastery() -> None:
    result = KubernetesEnforcementAnalyzer().evaluate(with_change(clean_evidence(), cluster_uid="", cni_name=""))
    assert KubernetesRisk.LIVE_CLUSTER_UNVERIFIED in result.risks
    assert result.live_kubernetes_cluster_validated is False
