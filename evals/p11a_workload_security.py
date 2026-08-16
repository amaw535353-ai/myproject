from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

from aegis.platform.workload_security import PlatformWorkloadSecurityAnalyzer
from aegis.platform.workload_security_types import *
from aegis.vulnerable.workload_security import VulnerableCallerDeclaredWorkloadSecurity
from evals.p11a_fixture import *

ROOT = Path(__file__).resolve().parents[1]


def _attack_rebind(f, m):
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


def attack_cases():
    base = build_fixture()
    cases = []

    def add(name, fixture):
        cases.append((name, fixture))

    # Upstream P10-I integrity and nonclaim attacks.
    upstream_fields_false = (
        "upstream_p10h_bound",
        "detection_verified",
        "containment_verified",
        "recovery_verified",
        "forensic_chain_verified",
        "phase10_exit_gate_verified",
        "deferred_mastery_debt_carried",
    )
    for field in upstream_fields_false:
        add(f"upstream_{field}_false", {**base, "p10i": replace(base["p10i"], **{field: False})})
    upstream_fields_true = (
        "caller_declared_safety_trusted",
        "production_soc_integrated",
        "production_siem_integrated",
        "production_orchestrator_remediation_validated",
        "cross_zone_recovery_validated",
        "hosted_ci_execution_verified",
        "production_validation_claimed",
        "professional_mastery_complete",
    )
    for field in upstream_fields_true:
        add(f"upstream_{field}_true", {**base, "p10i": replace(base["p10i"], **{field: True})})
    add("upstream_decision_deny", {**base, "p10i": replace(base["p10i"], decision=IncidentDecision.DENY)})
    add("upstream_risk_present", {**base, "p10i": replace(base["p10i"], risks=("synthetic",))})
    add("upstream_exit_gate_pass", {**base, "p10i": replace(base["p10i"], exit_gate_status=ExitGateStatus.PASS)})
    add("upstream_schema_mismatch", {**base, "p10i": replace(base["p10i"], assessment_schema_version="bad")})
    add("upstream_mode_mismatch", {**base, "p10i": replace(base["p10i"], assessment_mode="bad")})
    add("upstream_digest_mismatch", {**base, "p10i": replace(base["p10i"], assessment_evidence_sha256=h("wrong-upstream"))})
    for field, value in (
        ("request_id", "request-other"),
        ("tenant_id", "other"),
        ("session_id", "tenant/other/session/s-1"),
        ("target_model_id", "other-model"),
        ("target_model_revision", "other-rev"),
        ("adapter_ids", ("adapter-security-policy",)),
        ("adapter_generation", 99),
        ("router_id", "router-other"),
        ("router_generation", 41),
        ("manifest_sha256", h("wrong-p10i-manifest")),
    ):
        add(f"upstream_route_{field}", {**base, "p10i": replace(base["p10i"], **{field: value})})

    # Outer and route bindings.
    for field, value in (
        ("p10i_assessment_sha256", h("wrong-p10i-assessment")),
        ("p10i_manifest_sha256", h("wrong-p10i-manifest")),
        ("request_id", "request-other"),
        ("tenant_id", "other"),
        ("session_id", "tenant/other/session/s-1"),
        ("target_model_id", "other-model"),
        ("target_model_revision", "other-rev"),
        ("adapter_ids", ("adapter-security-policy",)),
        ("adapter_generation", 99),
        ("router_id", "router-other"),
        ("router_generation", 41),
        ("network_operations", 1),
    ):
        m = replace(base["manifest"], **{field: value})
        add(f"manifest_route_{field}", _attack_rebind(base, m))

    # Workload identity attacks.
    identity_mutations = (
        ("workload_id", "workload-other"),
        ("namespace", "tenant-other-inference"),
        ("tenant_id", "other"),
        ("service_account", "default"),
        ("pod_uid", "pod-other"),
        ("node_id", "worker-other"),
        ("runtime_class", "privileged"),
        ("run_as_user", 0),
        ("run_as_group", 0),
        ("supplemental_groups", (0,)),
        ("workload_identity_subject", "system:serviceaccount:default:default"),
        ("workload_identity_audience", "kubernetes.default.svc"),
        ("token_expiry_epoch", NOW - 1),
        ("token_expiry_epoch", NOW + 3600),
        ("token_sha256", h("wrong-token")),
        ("automount_service_account_token", True),
    )
    for index, (field, value) in enumerate(identity_mutations):
        ident = replace(base["manifest"].identity, **{field: value})
        m = replace(base["manifest"], identity=ident)
        add(f"identity_{index}_{field}", _attack_rebind(base, m))

    # Per-container privilege and filesystem attacks.
    container_mutations = (
        ("run_as_non_root", False),
        ("run_as_user", 0),
        ("run_as_group", 0),
        ("privileged", True),
        ("allow_privilege_escalation", True),
        ("read_only_root_filesystem", False),
        ("host_network", True),
        ("host_pid", True),
        ("host_ipc", True),
        ("host_path_mounts", ("/var/run/docker.sock",)),
        ("added_capabilities", ("SYS_ADMIN",)),
        ("dropped_capabilities", ("NET_RAW",)),
        ("seccomp_profile", "Unconfined"),
        ("apparmor_profile", "unconfined"),
        ("proc_mount", "Unmasked"),
        ("writable_paths", ("/",)),
        ("image_ref", "registry.example/aegisdesk/inference:latest"),
        ("image_digest", h("wrong-image")),
    )
    for ci in range(len(base["manifest"].containers)):
        for mi, (field, value) in enumerate(container_mutations):
            containers = list(base["manifest"].containers)
            containers[ci] = replace(containers[ci], **{field: value})
            m = replace(base["manifest"], containers=tuple(containers))
            add(f"container_{ci}_{mi}_{field}", _attack_rebind(base, m))
    m = replace(base["manifest"], containers=base["manifest"].containers[:1])
    add("container_dropped", _attack_rebind(base, m))
    m = replace(base["manifest"], containers=tuple(reversed(base["manifest"].containers)))
    add("container_reordered", _attack_rebind(base, m))

    # Secret projection attacks.
    secret_mutations = (
        ("workload_id", "workload-other"),
        ("namespace", "tenant-other-inference"),
        ("tenant_id", "other"),
        ("mount_path", "/etc/token"),
        ("source_kind", "environment_variable"),
        ("source_ref", "wrong-secret"),
        ("read_only", False),
        ("file_mode", 0o644),
        ("owner_uid", 12345),
        ("owner_gid", 0),
        ("content_sha256", h("wrong-secret")),
        ("rotation_epoch", NOW + 1),
        ("expires_at_epoch", NOW - 1),
    )
    for si in range(len(base["manifest"].secrets)):
        for mi, (field, value) in enumerate(secret_mutations):
            secrets = list(base["manifest"].secrets)
            secrets[si] = replace(secrets[si], **{field: value})
            m = replace(base["manifest"], secrets=tuple(secrets))
            add(f"secret_{si}_{mi}_{field}", _attack_rebind(base, m))
    add("secret_dropped", _attack_rebind(base, replace(base["manifest"], secrets=base["manifest"].secrets[:1])))

    # Network policy attacks.
    network_mutations = (
        ("namespace", "tenant-other-inference"),
        ("selector_workload_id", "workload-other"),
        ("default_deny_ingress", False),
        ("default_deny_egress", False),
        ("allowed_ingress_peers", ("any",)),
        ("allowed_egress_peers", EGRESS_PEERS + ("internet:any",)),
        ("allowed_egress_ports", EGRESS_PORTS + (22,)),
        ("cloud_metadata_blocked", False),
        ("kube_api_access_allowed", True),
    )
    for mi, (field, value) in enumerate(network_mutations):
        n = replace(base["manifest"].network_policies[0], **{field: value})
        m = replace(base["manifest"], network_policies=(n,))
        add(f"network_{mi}_{field}", _attack_rebind(base, m))
    add("network_policy_dropped", _attack_rebind(base, replace(base["manifest"], network_policies=())))

    # RBAC attacks.
    rbac_mutations = (
        ("namespace", "tenant-other-inference"),
        ("subject_service_account", "default"),
        ("role_name", "cluster-admin"),
        ("verbs", ("*",)),
        ("verbs", ("get", "list")),
        ("resources", ("*",)),
        ("resources", ("secrets",)),
        ("resource_names", ("*",)),
        ("cluster_scope", True),
    )
    for mi, (field, value) in enumerate(rbac_mutations):
        r = replace(base["manifest"].rbac_bindings[0], **{field: value})
        m = replace(base["manifest"], rbac_bindings=(r,))
        add(f"rbac_{mi}_{field}", _attack_rebind(base, m))
    add("rbac_dropped", _attack_rebind(base, replace(base["manifest"], rbac_bindings=())))

    # Image supply-chain attacks.
    image_mutations = (
        ("image_digest", h("wrong-image-trust")),
        ("registry", "untrusted.example"),
        ("mutable_tag_used", True),
        ("signature_bundle_sha256", "not-a-sha"),
        ("sbom_sha256", "not-a-sha"),
        ("provenance_sha256", "not-a-sha"),
        ("critical_vulnerability_count", 1),
        ("admission_verified", False),
    )
    for ii in range(len(base["manifest"].image_trust)):
        for mi, (field, value) in enumerate(image_mutations):
            images = list(base["manifest"].image_trust)
            images[ii] = replace(images[ii], **{field: value})
            m = replace(base["manifest"], image_trust=tuple(images))
            add(f"image_{ii}_{mi}_{field}", _attack_rebind(base, m))
    add("image_trust_dropped", _attack_rebind(base, replace(base["manifest"], image_trust=base["manifest"].image_trust[:1])))

    # Runtime boundary and debt attacks.
    runtime_mutations = (
        ("runtime_class", "privileged"),
        ("cgroup_mode", "cgroup-v1"),
        ("user_namespace_mode", "host-userns"),
        ("seccomp_default", False),
        ("lsm_mode", "none"),
        ("rootless_or_userns_remap", False),
        ("device_access_mode", "all"),
        ("host_socket_mounts", ("/var/run/docker.sock",)),
        ("ptrace_restricted", False),
        ("privileged_workloads_on_node", 1),
    )
    for mi, (field, value) in enumerate(runtime_mutations):
        runtime = replace(base["manifest"].runtime_boundary, **{field: value})
        m = replace(base["manifest"], runtime_boundary=runtime)
        add(f"runtime_{mi}_{field}", _attack_rebind(base, m))
    add("gpu_debt_dropped", _attack_rebind(base, replace(base["manifest"], deferred_mastery_items=("p11a-live-kubernetes-cluster",))))
    add("kubernetes_debt_dropped", _attack_rebind(base, replace(base["manifest"], deferred_mastery_items=("p10f-live-nvidia-gpu-mig-cuda",))))

    # Caller, time, and policy integrity attacks.
    add("caller_outer_manifest_id", {**base, "request": replace(base["request"], manifest_id="other")})
    add("caller_outer_manifest_sha", {**base, "request": replace(base["request"], manifest_sha256=h("other"))})
    add("caller_tenant_lie", {**base, "request": replace(base["request"], declared_tenant_id="other")})
    add("caller_namespace_lie", {**base, "request": replace(base["request"], declared_namespace="other")})
    add("caller_workload_lie", {**base, "request": replace(base["request"], declared_workload_id="other")})
    add("caller_service_account_lie", {**base, "request": replace(base["request"], declared_service_account="default")})
    add("manifest_stale", {**base, "request": replace(base["request"], evaluated_at_epoch=NOW + 301)})
    add("manifest_future", {**base, "request": replace(base["request"], evaluated_at_epoch=NOW - 6)})
    add("policy_version", {**base, "policy": replace(base["policy"], policy_version="bad")})
    add("policy_manifest_digest", {**base, "policy": replace(base["policy"], expected_manifest_sha256=h("wrong"))})
    add("policy_container_coverage", {**base, "policy": replace(base["policy"], expected_container_ids=(CONTAINER_IDS[0],))})
    add("policy_secret_coverage", {**base, "policy": replace(base["policy"], expected_secret_ids=(SECRET_IDS[0],))})
    add("policy_run_as_root", {**base, "policy": replace(base["policy"], expected_run_as_user=0)})

    return tuple(cases)


def safe_cases():
    return (
        ("canonical", build_fixture()),
        ("delayed_evaluation", safe_delayed_evaluation_fixture()),
        ("shorter_token", safe_shorter_token_fixture()),
        ("reduced_writable_path", safe_reduced_writable_path_fixture()),
    )


def hardened_accepts(f) -> bool:
    try:
        result = PlatformWorkloadSecurityAnalyzer(f["policy"]).evaluate(f["manifest"], f["request"], f["p10i"])
        return result.decision == PlatformDecision.ALLOW
    except (PlatformWorkloadSecurityRejected, ValueError, TypeError):
        return False


def main() -> int:
    attacks = attack_cases()
    safe = safe_cases()
    vulnerable = VulnerableCallerDeclaredWorkloadSecurity()
    vulnerable_hits = sum(vulnerable.accepts(f["request"]) for _, f in attacks)
    hardened_hits = sum(hardened_accepts(f) for _, f in attacks)
    false_positives = sum(not hardened_accepts(f) for _, f in safe)
    safe_hits = len(safe) - false_positives
    clean = PlatformWorkloadSecurityAnalyzer(build_fixture()["policy"]).evaluate(
        build_fixture()["manifest"], build_fixture()["request"], build_fixture()["p10i"]
    )
    dataset_sha = hashlib.sha256(
        json.dumps([name for name, _ in attacks], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    fixture_eval_sha = hashlib.sha256(
        (ROOT / "evals/p11a_fixture.py").read_bytes() + (ROOT / "evals/p11a_workload_security.py").read_bytes()
    ).hexdigest()
    print(json.dumps({
        "phase": "P11-A",
        "adversarial_cases": len(attacks),
        "vulnerable_asr": f"{vulnerable_hits}/{len(attacks)}",
        "hardened_asr": f"{hardened_hits}/{len(attacks)}",
        "hardened_fpr": f"{false_positives}/{len(safe)}",
        "safe_task_rate": f"{safe_hits}/{len(safe)}",
        "manifest_sha256": clean.manifest_sha256,
        "adversarial_dataset_sha256": dataset_sha,
        "fixture_evaluator_sha256": fixture_eval_sha,
        "clean_assessment_sha256": clean.assessment_evidence_sha256,
        "clean_decision": clean.decision.value,
        "live_kubernetes_cluster_validated": clean.live_kubernetes_cluster_validated,
        "production_validation_claimed": False,
    }, sort_keys=True))
    if vulnerable_hits != len(attacks) or hardened_hits != 0 or false_positives != 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
