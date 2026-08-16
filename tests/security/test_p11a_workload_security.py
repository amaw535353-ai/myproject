from dataclasses import replace

import pytest

from aegis.platform.workload_security import PlatformWorkloadSecurityAnalyzer
from aegis.platform.workload_security_types import *
from aegis.vulnerable.workload_security import VulnerableCallerDeclaredWorkloadSecurity
from evals.p11a_fixture import *
from evals.p11a_workload_security import attack_cases, safe_cases


def evaluate(f):
    return PlatformWorkloadSecurityAnalyzer(f["policy"]).evaluate(f["manifest"], f["request"], f["p10i"])


def attack_rebind(f, m):
    p = replace(f["policy"], expected_manifest_sha256=platform_workload_security_manifest_digest(m))
    q = replace(
        f["request"],
        manifest_id=m.manifest_id,
        manifest_sha256=platform_workload_security_manifest_digest(m),
        evaluated_at_epoch=max(f["request"].evaluated_at_epoch, m.created_at_epoch),
        declared_tenant_id=m.tenant_id,
        declared_namespace=m.identity.namespace,
        declared_workload_id=m.identity.workload_id,
        declared_service_account=m.identity.service_account,
    )
    return {"manifest": m, "policy": p, "request": q, "p10i": f["p10i"]}


def test_clean_assessment_allows_with_bounded_nonclaims():
    result = evaluate(build_fixture())
    assert result.decision == PlatformDecision.ALLOW
    assert result.risks == ()
    assert result.upstream_p10i_bound
    assert result.workload_identity_verified
    assert result.privilege_boundary_verified
    assert result.filesystem_boundary_verified
    assert result.secret_projection_verified
    assert result.network_policy_verified
    assert result.rbac_verified
    assert result.image_supply_chain_verified
    assert result.runtime_boundary_verified
    assert result.deferred_mastery_debt_carried
    assert not result.caller_declared_safety_trusted
    assert not result.live_kubernetes_cluster_validated
    assert not result.production_admission_controller_validated
    assert not result.production_cni_enforcement_validated
    assert not result.cloud_workload_identity_validated
    assert not result.container_escape_resistance_validated
    assert not result.kernel_hardening_validated
    assert not result.production_container_runtime_integrated
    assert result.assessment_schema_version == P11A_ASSESSMENT_SCHEMA_VERSION
    assert result.assessment_mode == P11A_ASSESSMENT_MODE


@pytest.mark.parametrize("name,fixture", safe_cases(), ids=lambda value: value if isinstance(value, str) else None)
def test_safe_corpus(name, fixture):
    assert evaluate(fixture).decision == PlatformDecision.ALLOW


@pytest.mark.parametrize("name,fixture", attack_cases(), ids=lambda value: value if isinstance(value, str) else None)
def test_adversarial_corpus_blocked(name, fixture):
    vulnerable = VulnerableCallerDeclaredWorkloadSecurity()
    assert vulnerable.accepts(fixture["request"]), name
    try:
        result = evaluate(fixture)
    except PlatformWorkloadSecurityRejected:
        return
    assert result.decision == PlatformDecision.DENY, name


def test_privileged_container_produces_specific_risk_when_summary_matches():
    f = build_fixture()
    containers = list(f["manifest"].containers)
    containers[0] = replace(containers[0], privileged=True)
    out = attack_rebind(f, replace(f["manifest"], containers=tuple(containers)))
    out["request"] = replace(out["request"], declared_privilege_boundary_verified=False, declared_workload_security_safe=False)
    result = evaluate(out)
    assert WorkloadRisk.PRIVILEGED_CONTAINER in result.risks
    assert result.decision == PlatformDecision.DENY


def test_readwrite_rootfs_produces_specific_risk():
    f = build_fixture()
    containers = list(f["manifest"].containers)
    containers[0] = replace(containers[0], read_only_root_filesystem=False)
    out = attack_rebind(f, replace(f["manifest"], containers=tuple(containers)))
    out["request"] = replace(out["request"], declared_filesystem_boundary_verified=False, declared_workload_security_safe=False)
    result = evaluate(out)
    assert WorkloadRisk.ROOT_FILESYSTEM_WRITABLE in result.risks


def test_secret_permissions_produce_specific_risk():
    f = build_fixture()
    secrets = list(f["manifest"].secrets)
    secrets[0] = replace(secrets[0], file_mode=0o644)
    out = attack_rebind(f, replace(f["manifest"], secrets=tuple(secrets)))
    out["request"] = replace(out["request"], declared_secret_projection_verified=False, declared_workload_security_safe=False)
    result = evaluate(out)
    assert WorkloadRisk.SECRET_PERMISSION_UNSAFE in result.risks


def test_metadata_access_produces_specific_risk():
    f = build_fixture()
    n = replace(f["manifest"].network_policies[0], cloud_metadata_blocked=False)
    out = attack_rebind(f, replace(f["manifest"], network_policies=(n,)))
    out["request"] = replace(out["request"], declared_network_policy_verified=False, declared_workload_security_safe=False)
    result = evaluate(out)
    assert WorkloadRisk.CLOUD_METADATA_EXPOSED in result.risks


def test_cluster_scope_rbac_produces_specific_risk():
    f = build_fixture()
    r = replace(f["manifest"].rbac_bindings[0], cluster_scope=True)
    out = attack_rebind(f, replace(f["manifest"], rbac_bindings=(r,)))
    out["request"] = replace(out["request"], declared_rbac_verified=False, declared_workload_security_safe=False)
    result = evaluate(out)
    assert WorkloadRisk.RBAC_CLUSTER_SCOPE in result.risks


def test_critical_image_vulnerability_produces_specific_risk():
    f = build_fixture()
    images = list(f["manifest"].image_trust)
    images[0] = replace(images[0], critical_vulnerability_count=1)
    out = attack_rebind(f, replace(f["manifest"], image_trust=tuple(images)))
    out["request"] = replace(out["request"], declared_image_supply_chain_verified=False, declared_workload_security_safe=False)
    result = evaluate(out)
    assert WorkloadRisk.CRITICAL_VULNERABILITY_PRESENT in result.risks


def test_runtime_cgroup_downgrade_produces_specific_risk():
    f = build_fixture()
    runtime = replace(f["manifest"].runtime_boundary, cgroup_mode="cgroup-v1")
    out = attack_rebind(f, replace(f["manifest"], runtime_boundary=runtime))
    out["request"] = replace(out["request"], declared_runtime_boundary_verified=False, declared_workload_security_safe=False)
    result = evaluate(out)
    assert WorkloadRisk.CGROUP_POLICY_MISMATCH in result.risks


def test_deferred_mastery_debt_cannot_be_dropped():
    f = build_fixture()
    m = replace(f["manifest"], deferred_mastery_items=("p10f-live-nvidia-gpu-mig-cuda",))
    out = attack_rebind(f, m)
    out["request"] = replace(out["request"], declared_gpu_debt_carried=False, declared_workload_security_safe=False)
    result = evaluate(out)
    assert WorkloadRisk.DEFERRED_MASTERY_DEBT_DROPPED in result.risks


def test_upstream_production_claim_is_rejected_as_invalid_upstream():
    f = build_fixture()
    f["p10i"] = replace(f["p10i"], production_validation_claimed=True)
    f["request"] = replace(f["request"], declared_upstream_p10i_bound=False, declared_gpu_debt_carried=True, declared_workload_security_safe=False)
    result = evaluate(f)
    assert WorkloadRisk.UPSTREAM_P10I_INVALID in result.risks


def test_caller_cannot_flip_safe_boolean_on_clean_evidence():
    f = build_fixture()
    f["request"] = replace(f["request"], declared_workload_security_safe=False)
    with pytest.raises(PlatformWorkloadSecurityRejected) as exc:
        evaluate(f)
    assert exc.value.reason == WorkloadRejectReason.DECLARED_SUMMARY_MISMATCH


def test_manifest_digest_is_outer_binding():
    f = build_fixture()
    f["request"] = replace(f["request"], manifest_sha256=h("wrong"))
    with pytest.raises(PlatformWorkloadSecurityRejected) as exc:
        evaluate(f)
    assert exc.value.reason == WorkloadRejectReason.REQUEST_INVALID


def test_policy_cannot_require_root_execution():
    f = build_fixture()
    f["policy"] = replace(f["policy"], expected_run_as_user=0)
    with pytest.raises(PlatformWorkloadSecurityRejected) as exc:
        PlatformWorkloadSecurityAnalyzer(f["policy"])
    assert exc.value.reason == WorkloadRejectReason.POLICY_INVALID
