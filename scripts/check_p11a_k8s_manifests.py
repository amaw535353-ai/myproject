from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
DIGEST_REF = re.compile(r"@sha256:[0-9a-fA-F]{64}$")
DANGEROUS_HOST_SOCKETS = ("docker.sock", "containerd.sock", "crio.sock", "podman.sock")


def _find(items: list[dict], kind: str) -> list[dict]:
    return [item for item in items if item.get("kind") == kind]


def _containers_from_deployment(deployment: dict) -> list[dict]:
    return deployment.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])


def validate(document: dict) -> dict:
    checks: dict[str, bool] = {}
    items = document.get("items", []) if document.get("kind") == "List" else [document]
    namespaces = _find(items, "Namespace")
    service_accounts = _find(items, "ServiceAccount")
    roles = _find(items, "Role")
    bindings = _find(items, "RoleBinding")
    network_policies = _find(items, "NetworkPolicy")
    deployments = _find(items, "Deployment")

    checks["has_namespace"] = len(namespaces) == 1
    if namespaces:
        labels = namespaces[0].get("metadata", {}).get("labels", {})
        checks["pod_security_admission_restricted"] = all(
            labels.get(f"pod-security.kubernetes.io/{mode}") == "restricted"
            for mode in ("enforce", "audit", "warn")
        )
    else:
        checks["pod_security_admission_restricted"] = False

    checks["no_cluster_scope_rbac_objects"] = not _find(items, "ClusterRole") and not _find(items, "ClusterRoleBinding")
    checks["service_account_token_automount_disabled"] = bool(service_accounts) and all(
        item.get("automountServiceAccountToken") is False for item in service_accounts
    )

    role_ok = bool(roles)
    for role in roles:
        if not role.get("metadata", {}).get("namespace"):
            role_ok = False
        for rule in role.get("rules", []):
            verbs = set(rule.get("verbs", []))
            resources = set(rule.get("resources", []))
            names = set(rule.get("resourceNames", []))
            if not verbs or "*" in verbs or not verbs.issubset({"get"}):
                role_ok = False
            if not resources or "*" in resources or not resources.issubset({"configmaps"}):
                role_ok = False
            if not names or "*" in names:
                role_ok = False
    checks["namespaced_least_privilege_rbac"] = role_ok

    binding_ok = bool(bindings)
    for binding in bindings:
        namespace = binding.get("metadata", {}).get("namespace")
        role_ref = binding.get("roleRef", {})
        subjects = binding.get("subjects", [])
        if role_ref.get("kind") != "Role" or not subjects:
            binding_ok = False
        for subject in subjects:
            if subject.get("kind") != "ServiceAccount" or subject.get("namespace") != namespace or subject.get("name") == "default":
                binding_ok = False
    checks["role_bindings_scoped_to_service_accounts"] = binding_ok

    deployment_ok = bool(deployments)
    image_pins = True
    privilege = True
    readonly = True
    resources_bounded = True
    secret_mounts = True
    projected_identity = False
    no_host_surface = True
    for deployment in deployments:
        pod = deployment.get("spec", {}).get("template", {}).get("spec", {})
        pod_sc = pod.get("securityContext", {})
        if (
            pod.get("automountServiceAccountToken") is not False
            or pod.get("serviceAccountName") in (None, "", "default")
            or pod.get("hostNetwork", False)
            or pod.get("hostPID", False)
            or pod.get("hostIPC", False)
            or pod.get("shareProcessNamespace", False)
            or pod_sc.get("runAsNonRoot") is not True
            or int(pod_sc.get("runAsUser", 0)) <= 0
            or int(pod_sc.get("runAsGroup", 0)) <= 0
            or int(pod_sc.get("fsGroup", 0)) <= 0
            or pod_sc.get("seccompProfile", {}).get("type") != "RuntimeDefault"
        ):
            deployment_ok = False
        volumes = {volume.get("name"): volume for volume in pod.get("volumes", [])}
        for volume in volumes.values():
            if "hostPath" in volume:
                no_host_surface = False
            secret = volume.get("secret")
            if secret:
                mode = int(secret.get("defaultMode", 0o644))
                if mode > 0o440 or mode & 0o007 or mode & 0o020:
                    secret_mounts = False
            projected = volume.get("projected")
            if projected:
                mode = int(projected.get("defaultMode", 0o644))
                if mode > 0o440 or mode & 0o007 or mode & 0o020:
                    secret_mounts = False
                for source in projected.get("sources", []):
                    token = source.get("serviceAccountToken")
                    if token:
                        audience = token.get("audience", "")
                        expiry = int(token.get("expirationSeconds", 0))
                        projected_identity = bool(audience and audience != "kubernetes.default.svc" and 0 < expiry <= 600)
        for container in _containers_from_deployment(deployment):
            image = container.get("image", "")
            image_pins = image_pins and bool(DIGEST_REF.search(image))
            sc = container.get("securityContext", {})
            privilege = privilege and (
                sc.get("runAsNonRoot") is True
                and int(sc.get("runAsUser", 0)) > 0
                and int(sc.get("runAsGroup", 0)) > 0
                and sc.get("privileged") is False
                and sc.get("allowPrivilegeEscalation") is False
                and sc.get("capabilities", {}).get("drop") == ["ALL"]
                and not sc.get("capabilities", {}).get("add", [])
                and sc.get("seccompProfile", {}).get("type") == "RuntimeDefault"
                and sc.get("appArmorProfile", {}).get("type") == "RuntimeDefault"
            )
            readonly = readonly and sc.get("readOnlyRootFilesystem") is True
            resources = container.get("resources", {})
            resources_bounded = resources_bounded and bool(resources.get("requests")) and bool(resources.get("limits"))
            for mount in container.get("volumeMounts", []):
                path = mount.get("mountPath", "")
                if any(marker in path for marker in DANGEROUS_HOST_SOCKETS):
                    no_host_surface = False
                if "secret" in mount.get("name", "") or "token" in mount.get("name", ""):
                    secret_mounts = secret_mounts and mount.get("readOnly") is True

    checks["deployment_pod_security_context_hardened"] = deployment_ok
    checks["images_pinned_by_digest"] = image_pins
    checks["container_privilege_escalation_blocked"] = privilege
    checks["container_root_filesystems_readonly"] = readonly
    checks["container_resources_bounded"] = resources_bounded
    checks["secret_and_token_mounts_restricted"] = secret_mounts
    checks["projected_workload_identity_token_bounded"] = projected_identity
    checks["no_host_path_or_runtime_socket_surface"] = no_host_surface

    net_ok = bool(network_policies)
    serialized = json.dumps(network_policies, sort_keys=True)
    for policy in network_policies:
        spec = policy.get("spec", {})
        types = set(spec.get("policyTypes", []))
        selector = spec.get("podSelector", {}).get("matchLabels", {})
        if types != {"Ingress", "Egress"} or not selector or not spec.get("ingress") or not spec.get("egress"):
            net_ok = False
    checks["network_policy_ingress_and_egress_allowlists_present"] = net_ok
    checks["cloud_metadata_not_allowlisted"] = "169.254.169.254" not in serialized
    checks["direct_kubernetes_api_service_not_allowlisted"] = "kubernetes.default" not in serialized

    passed = all(checks.values())
    static = {
        "manifest": "deploy/p11a/kubernetes.json",
        "status": "pass" if passed else "fail",
        "checks": checks,
        "resource_counts": {
            "namespaces": len(namespaces),
            "service_accounts": len(service_accounts),
            "roles": len(roles),
            "role_bindings": len(bindings),
            "network_policies": len(network_policies),
            "deployments": len(deployments),
        },
    }
    payload = json.dumps(static, sort_keys=True, separators=(",", ":")).encode()
    static["static_report_sha256"] = hashlib.sha256(payload).hexdigest()
    static["kubectl_present"] = shutil.which("kubectl") is not None
    static["live_kubernetes_cluster_validated"] = False
    static["production_admission_controller_validated"] = False
    static["production_cni_enforcement_validated"] = False
    return static


def main() -> int:
    parser = argparse.ArgumentParser(description="Static P11-A Kubernetes hardening manifest check")
    parser.add_argument("--manifest", default=str(ROOT / "deploy/p11a/kubernetes.json"))
    parser.add_argument("--output")
    args = parser.parse_args()
    document = json.loads(Path(args.manifest).read_text())
    result = validate(document)
    text = json.dumps(result, sort_keys=True)
    print(text)
    if args.output:
        Path(args.output).write_text(text + "\n")
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
