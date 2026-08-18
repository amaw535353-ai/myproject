from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time

from evals.p11b_fixture import PSA_CASES, RBAC_CASES, fixture
from evals.p11b_kubernetes_security import assess

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "p11b-kubernetes-evidence.json"
CLUSTER = "aegisdesk-p11b"
K3D_VERSION = "v5.8.3"
K3S_IMAGE = "rancher/k3s:v1.33.5-k3s1"
TIMEOUT = 60


class InfrastructureUnavailable(RuntimeError):
    pass


class SecurityFailure(RuntimeError):
    pass


def run(args: list[str], *, check: bool = True, timeout: int = TIMEOUT, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, input=stdin, text=True, capture_output=True, check=check, timeout=timeout)


def kubectl(*args: str, check: bool = True, timeout: int = TIMEOUT, stdin: str | None = None):
    return run(["kubectl", *args], check=check, timeout=timeout, stdin=stdin)


def pod_doc(name: str, mutation: dict | None = None) -> dict:
    doc = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": "p11b-restricted"}, "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never", "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [{"name": "probe", "image": "registry.k8s.io/pause:3.10", "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}}]}}
    if mutation:
        mutation(doc)
    return doc


def apply_json(doc: dict, dry_run: bool = True) -> subprocess.CompletedProcess[str]:
    args = ["apply"] + (["--dry-run=server"] if dry_run else []) + ["-f", "-"]
    return kubectl(*args, check=False, stdin=json.dumps(doc))


def pod_security_api_denial(proc: subprocess.CompletedProcess[str]) -> bool:
    message = (proc.stderr + proc.stdout).lower()
    return proc.returncode != 0 and "forbidden" in message and any(
        marker in message for marker in ("podsecurity", "pod-security", "pod security")
    )


def authorization_answer(proc: subprocess.CompletedProcess[str]) -> tuple[str, bool]:
    lines = [line.strip().lower() for line in proc.stdout.splitlines() if line.strip()]
    answer = lines[-1] if lines else ""
    evaluated = answer in {"yes", "no"}
    return ("ALLOW" if answer == "yes" else "DENY", evaluated)


def psa_observations() -> list[dict]:
    mutations = {
        "privileged": lambda d: (
            d["spec"]["containers"][0]["securityContext"].pop("allowPrivilegeEscalation"),
            d["spec"]["containers"][0]["securityContext"].update(privileged=True),
        ),
        "allowPrivilegeEscalation": lambda d: d["spec"]["containers"][0]["securityContext"].update(allowPrivilegeEscalation=True),
        "SYS_ADMIN": lambda d: d["spec"]["containers"][0]["securityContext"]["capabilities"].update(add=["SYS_ADMIN"]),
        "hostPID": lambda d: d["spec"].update(hostPID=True),
        "hostNetwork": lambda d: d["spec"].update(hostNetwork=True),
        "hostPath": lambda d: (d["spec"].update(volumes=[{"name": "host", "hostPath": {"path": "/"}}]), d["spec"]["containers"][0].update(volumeMounts=[{"name": "host", "mountPath": "/host"}])),
        "UID_0": lambda d: d["spec"]["securityContext"].update(runAsNonRoot=False, runAsUser=0),
        "missing_seccomp": lambda d: d["spec"]["securityContext"].pop("seccompProfile"),
    }
    out = []
    for name in PSA_CASES:
        doc = pod_doc(f"attack-{name.lower().replace('_', '-')}")
        mutations[name](doc)
        proc = apply_json(doc)
        api = pod_security_api_denial(proc)
        out.append({"case": name, "attack": True, "expected": "DENY", "observed": "DENY" if proc.returncode else "ALLOW", "api_evaluated": api})
    benign = apply_json(pod_doc("restricted-benign"))
    out.append({"case": "restricted_benign", "attack": False, "expected": "ALLOW", "observed": "ALLOW" if benign.returncode == 0 else "DENY", "api_evaluated": benign.returncode == 0})
    return out


def auth(verb: str, resource: str, namespace: str | None = None, name: str | None = None) -> tuple[str, bool]:
    if name:
        resource = f"{resource}/{name}"
    args = ["auth", "can-i", verb, resource, "--as", "system:serviceaccount:p11b-restricted:p11b-client"]
    if namespace: args += ["-n", namespace]
    proc = kubectl(*args, check=False)
    return authorization_answer(proc)


def rbac_observations() -> list[dict]:
    queries = [
        ("get", "configmaps", "p11b-restricted", "allowed-config"), ("get", "secrets", "p11b-restricted", None),
        ("get", "configmaps", "p11b-other", None), ("get", "secrets", "p11b-other", None),
        ("create", "rolebindings.rbac.authorization.k8s.io", "p11b-restricted", None),
        ("create", "clusterrolebindings.rbac.authorization.k8s.io", None, None),
        ("impersonate", "users", None, None), ("create", "pods", "p11b-other", None),
        ("create", "pods/exec", "p11b-restricted", None), ("create", "serviceaccounts/token", "p11b-restricted", None),
    ]
    out = []
    for (name, expected), query in zip(RBAC_CASES, queries):
        observed, evaluated = auth(*query)
        out.append({"case": name, "principal": "system:serviceaccount:p11b-restricted:p11b-client", "namespace": query[2] or "cluster", "verb": query[0], "resource": query[1], "expected": expected, "observed": observed, "api_evaluated": evaluated, "pass": observed == expected})
    return out


def workload(name: str, labels: dict[str, str]) -> dict:
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": "p11b-restricted", "labels": labels}, "spec": {"automountServiceAccountToken": False, "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [{"name": "main", "image": "busybox:1.37.0", "command": ["sh", "-c", "sleep 600"], "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}}]}}


def probe(client: str) -> str:
    proc = kubectl("exec", "-n", "p11b-restricted", client, "--", "wget", "-q", "-T", "4", "-O", "-", "http://victim:8080", check=False, timeout=15)
    if proc.returncode == 0: return "SUCCESS"
    msg = (proc.stdout + proc.stderr).lower()
    if "bad address" in msg or "not known" in msg: return "DNS_FAILURE"
    if "refused" in msg: return "CONNECTION_REFUSED"
    if "timed out" in msg: return "TIMEOUT"
    return "INFRASTRUCTURE_FAILURE"


def positive_probe(client: str, attempts: int = 6) -> str:
    result = "INFRASTRUCTURE_FAILURE"
    for _ in range(attempts):
        result = probe(client)
        if result == "SUCCESS":
            return result
        time.sleep(1)
    return result


def network_observation() -> dict:
    victim = workload("victim", {"app": "victim"})
    victim["spec"]["containers"][0].update(image="python:3.13.7-alpine3.22", command=["python", "-m", "http.server", "8080"])
    docs = [victim, workload("authorized-client", {"access": "authorized"}), workload("attacker", {"access": "attacker"}), {"apiVersion": "v1", "kind": "Service", "metadata": {"name": "victim", "namespace": "p11b-restricted"}, "spec": {"selector": {"app": "victim"}, "ports": [{"port": 8080, "targetPort": 8080}]}}]
    for doc in docs:
        p = apply_json(doc, dry_run=False)
        if p.returncode: raise InfrastructureUnavailable(p.stderr)
    kubectl("wait", "--for=condition=Ready", "pod/victim", "pod/authorized-client", "pod/attacker", "-n", "p11b-restricted", "--timeout=90s", timeout=100)
    baseline = positive_probe("attacker")
    policy = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": {"name": "victim-ingress", "namespace": "p11b-restricted"}, "spec": {"podSelector": {"matchLabels": {"app": "victim"}}, "policyTypes": ["Ingress"], "ingress": [{"from": [{"podSelector": {"matchLabels": {"access": "authorized"}}}], "ports": [{"protocol": "TCP", "port": 8080}]}]}}
    if apply_json(policy, dry_run=False).returncode: raise InfrastructureUnavailable("policy apply failed")
    time.sleep(4)
    return {"baseline": baseline, "authorized_after_policy": positive_probe("authorized-client"), "attacker_after_policy": probe("attacker"), "api_evaluated": True}


def live_observations() -> dict:
    kubectl("apply", "-f", "deploy/p11b/lab.yaml")
    return {"infrastructure": {"cluster_created": True, "api_reached": True, "node_ready": True}, "psa": psa_observations(), "rbac": rbac_observations(), "network_policy": network_observation()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    tools = {name: shutil.which(name) for name in ("docker", "kubectl", "k3d")}
    preflight = {"architecture": platform.machine(), "cpu_count": os.cpu_count(), "memory_bytes": Path("/proc/meminfo").read_text().splitlines()[0], "disk_free_bytes": shutil.disk_usage(ROOT).free, "tools": tools, "k3d_version_pin": K3D_VERSION, "k3s_image_pin": K3S_IMAGE}
    classification = "TOOLING_UNAVAILABLE"
    created = False
    try:
        if not all(tools.values()): raise InfrastructureUnavailable("docker, kubectl, or k3d missing")
        if run(["docker", "version"], check=False).returncode: raise InfrastructureUnavailable("Docker unavailable")
        proc = run(["k3d", "cluster", "create", CLUSTER, "--image", K3S_IMAGE, "--servers", "1", "--agents", "0", "--k3s-arg", "--disable=traefik@server:0", "--k3s-arg", "--disable=servicelb@server:0", "--wait"], check=False, timeout=180)
        if proc.returncode: classification = "CLUSTER_CREATION_UNAVAILABLE"; raise InfrastructureUnavailable(proc.stderr)
        created = True
        kubectl("wait", "--for=condition=Ready", "node", "--all", "--timeout=90s", timeout=100)
        raw = fixture("live", live_observations())
        evidence = assess(raw)
        evidence["preflight"] = preflight
        ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        ARTIFACT.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        classification = "LIVE_LOCAL_PASS" if evidence["live_kubernetes_cluster_validated"] else "SECURITY_VALIDATION_FAILED"
        print(json.dumps({"classification": classification, "evidence_path": str(ARTIFACT)}, sort_keys=True))
        return 0 if classification == "LIVE_LOCAL_PASS" else 1
    except InfrastructureUnavailable as exc:
        print(json.dumps({"classification": classification, "reason": str(exc), "preflight": preflight}, sort_keys=True))
        return 2
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        print(json.dumps({"classification": "SECURITY_VALIDATION_FAILED", "reason": str(exc), "preflight": preflight}, sort_keys=True))
        return 1
    finally:
        if created and not args.keep:
            run(["k3d", "cluster", "delete", CLUSTER], check=False, timeout=120)


if __name__ == "__main__":
    raise SystemExit(main())
