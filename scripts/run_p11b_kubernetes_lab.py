from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from aegis.platform.kubernetes_enforcement import (
    KubernetesEnforcementAnalyzer,
    KubernetesEnforcementEvidence,
    evidence_digest,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_NAMESPACE = "tenant-acme-inference"
DEFAULT_SA = "aegisdesk-inference"


def kubectl(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["kubectl", *args], cwd=ROOT, check=check, text=True, capture_output=True)


def auth_can_i(
    verb: str,
    resource: str,
    subject_namespace: str,
    sa: str,
    target_namespace: str | None = None,
    resource_name: str | None = None,
) -> bool:
    args = [
        "auth",
        "can-i",
        verb,
        resource,
        "--as",
        f"system:serviceaccount:{subject_namespace}:{sa}",
    ]
    if resource_name:
        args.extend(["--resource-name", resource_name])
    if target_namespace:
        args.extend(["-n", target_namespace])
    return kubectl(*args).stdout.strip().lower() == "yes"


def server_dry_run_rejected(
    namespace: str,
    name: str,
    *,
    container_overrides: dict | None = None,
    pod_overrides: dict | None = None,
) -> bool:
    container = {
        "name": "probe",
        "image": "registry.k8s.io/pause:3.10",
    }
    container.update(container_overrides or {})
    pod_spec = {
        "restartPolicy": "Never",
        "containers": [container],
    }
    pod_spec.update(pod_overrides or {})
    doc = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace},
        "spec": pod_spec,
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(doc, f)
        path = f.name
    try:
        proc = kubectl("apply", "--dry-run=server", "-f", path, check=False)
        return proc.returncode != 0
    finally:
        Path(path).unlink(missing_ok=True)


def load_runtime(path: Path) -> dict:
    data = json.loads(path.read_text())
    required = {
        "cni_name",
        "automount_service_account_token_disabled",
        "projected_token_used",
        "token_audience",
        "token_ttl_seconds",
        "stolen_token_wrong_audience_denied",
        "stolen_token_post_containment_denied",
        "network_policy_enforced_by_cni",
        "intended_dependency_reachable",
        "cross_namespace_connection_denied",
        "arbitrary_egress_denied",
        "kubernetes_api_direct_egress_denied",
        "metadata_service_egress_denied",
        "compromised_pod_terminated",
        "compromised_identity_fenced",
        "clean_replacement_ready",
        "clean_replacement_uses_new_pod_uid",
        "audit_detected_compromise",
        "audit_records_admission_denials",
        "audit_records_rbac_denials",
        "audit_records_containment",
    }
    missing = sorted(required - set(data))
    if missing:
        raise ValueError(f"runtime evidence missing fields: {', '.join(missing)}")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="P11-B live Kubernetes enforcement mastery gate")
    parser.add_argument(
        "--runtime-evidence",
        type=Path,
        required=True,
        help="JSON produced by the live network/token/containment exercise",
    )
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    parser.add_argument("--service-account", default=DEFAULT_SA)
    args = parser.parse_args()

    if shutil.which("kubectl") is None:
        print(
            json.dumps(
                {
                    "phase": "P11-B",
                    "status": "LIVE_KUBERNETES_UNAVAILABLE",
                    "live_kubernetes_cluster_validated": False,
                },
                sort_keys=True,
            )
        )
        return 2

    runtime = load_runtime(args.runtime_evidence)
    version = json.loads(kubectl("version", "-o", "json").stdout)
    ns = json.loads(kubectl("get", "namespace", args.namespace, "-o", "json").stdout)
    psa = ns.get("metadata", {}).get("labels", {}).get("pod-security.kubernetes.io/enforce", "")
    network_policies = json.loads(kubectl("get", "networkpolicy", "-n", args.namespace, "-o", "json").stdout)

    evidence = KubernetesEnforcementEvidence(
        evidence_id=f"p11b-live-{int(time.time())}",
        collected_at_epoch=int(time.time()),
        cluster_uid=ns.get("metadata", {}).get("uid", ""),
        kubernetes_version=version.get("serverVersion", {}).get("gitVersion", ""),
        cni_name=str(runtime["cni_name"]),
        namespace=args.namespace,
        service_account=args.service_account,
        psa_enforce_level=psa,
        admission_rejected_privileged=server_dry_run_rejected(
            args.namespace,
            "p11b-privileged",
            container_overrides={"securityContext": {"privileged": True}},
        ),
        admission_rejected_host_namespaces=server_dry_run_rejected(
            args.namespace,
            "p11b-hostns",
            pod_overrides={"hostNetwork": True, "hostPID": True},
        ),
        admission_rejected_host_path=server_dry_run_rejected(
            args.namespace,
            "p11b-hostpath",
            container_overrides={"volumeMounts": [{"name": "host", "mountPath": "/host"}]},
            pod_overrides={"volumes": [{"name": "host", "hostPath": {"path": "/"}}]},
        ),
        admission_rejected_added_capabilities=server_dry_run_rejected(
            args.namespace,
            "p11b-cap",
            container_overrides={"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}}},
        ),
        admission_rejected_privilege_escalation=server_dry_run_rejected(
            args.namespace,
            "p11b-pe",
            container_overrides={"securityContext": {"allowPrivilegeEscalation": True}},
        ),
        intended_configmap_get_allowed=auth_can_i(
            "get",
            "configmaps",
            args.namespace,
            args.service_account,
            target_namespace=args.namespace,
            resource_name="aegisdesk-runtime-config",
        ),
        secret_list_denied=not auth_can_i(
            "list", "secrets", args.namespace, args.service_account, target_namespace=args.namespace
        ),
        pod_create_denied=not auth_can_i(
            "create", "pods", args.namespace, args.service_account, target_namespace=args.namespace
        ),
        rolebinding_create_denied=not auth_can_i(
            "create",
            "rolebindings.rbac.authorization.k8s.io",
            args.namespace,
            args.service_account,
            target_namespace=args.namespace,
        ),
        clusterrolebinding_create_denied=not auth_can_i(
            "create",
            "clusterrolebindings.rbac.authorization.k8s.io",
            args.namespace,
            args.service_account,
        ),
        cross_namespace_secret_get_denied=not auth_can_i(
            "get",
            "secrets",
            args.namespace,
            args.service_account,
            target_namespace="default",
        ),
        automount_service_account_token_disabled=bool(runtime["automount_service_account_token_disabled"]),
        projected_token_used=bool(runtime["projected_token_used"]),
        token_audience=str(runtime["token_audience"]),
        token_ttl_seconds=int(runtime["token_ttl_seconds"]),
        stolen_token_wrong_audience_denied=bool(runtime["stolen_token_wrong_audience_denied"]),
        stolen_token_post_containment_denied=bool(runtime["stolen_token_post_containment_denied"]),
        network_policy_present=bool(network_policies.get("items")),
        network_policy_enforced_by_cni=bool(runtime["network_policy_enforced_by_cni"]),
        intended_dependency_reachable=bool(runtime["intended_dependency_reachable"]),
        cross_namespace_connection_denied=bool(runtime["cross_namespace_connection_denied"]),
        arbitrary_egress_denied=bool(runtime["arbitrary_egress_denied"]),
        kubernetes_api_direct_egress_denied=bool(runtime["kubernetes_api_direct_egress_denied"]),
        metadata_service_egress_denied=bool(runtime["metadata_service_egress_denied"]),
        compromised_pod_terminated=bool(runtime["compromised_pod_terminated"]),
        compromised_identity_fenced=bool(runtime["compromised_identity_fenced"]),
        clean_replacement_ready=bool(runtime["clean_replacement_ready"]),
        clean_replacement_uses_new_pod_uid=bool(runtime["clean_replacement_uses_new_pod_uid"]),
        audit_detected_compromise=bool(runtime["audit_detected_compromise"]),
        audit_records_admission_denials=bool(runtime["audit_records_admission_denials"]),
        audit_records_rbac_denials=bool(runtime["audit_records_rbac_denials"]),
        audit_records_containment=bool(runtime["audit_records_containment"]),
    )
    assessment = KubernetesEnforcementAnalyzer().evaluate(evidence)
    report = {
        "phase": "P11-B",
        "status": "LIVE_MASTERY_PASS" if assessment.live_kubernetes_cluster_validated else "LIVE_MASTERY_FAIL",
        "decision": assessment.decision,
        "risks": [r.value for r in assessment.risks],
        "evidence_sha256": evidence_digest(evidence),
        "cluster_uid": evidence.cluster_uid,
        "kubernetes_version": evidence.kubernetes_version,
        "cni_name": evidence.cni_name,
        "live_kubernetes_cluster_validated": assessment.live_kubernetes_cluster_validated,
        "production_validation_claimed": False,
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if assessment.live_kubernetes_cluster_validated else 1


if __name__ == "__main__":
    raise SystemExit(main())
