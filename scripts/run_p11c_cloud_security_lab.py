from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess

from aegis.platform.cloud_security import AuditTrail, IdentityBroker, SecurityDenied
from evals.p11c_cloud_security import assess, validate_evidence
from evals.p11c_fixture import fixture

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "p11c-cloud-security-evidence.json"
CLUSTER = "aegisdesk-p11c"
K3S_IMAGE = "rancher/k3s:v1.33.5-k3s1"
TOKEN_DURATION = "10m"  # K3s TokenRequest enforces a ten-minute minimum.


class InfrastructureUnavailable(RuntimeError): pass


def run(args: list[str], *, check: bool = True, timeout: int = 90, stdin: str | None = None):
    return subprocess.run(args, cwd=ROOT, check=check, timeout=timeout, input=stdin, text=True, capture_output=True)


def kubectl(*args: str, check: bool = True, stdin: str | None = None):
    return run(["kubectl", *args], check=check, stdin=stdin)


def tokenreview(token: str, audience: str = "aegisdesk-cloud-broker") -> dict:
    request = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": {"token": token, "audiences": [audience]}}
    response = json.loads(kubectl("create", "--raw", "/apis/authentication.k8s.io/v1/tokenreviews", "-f", "-", stdin=json.dumps(request)).stdout)
    status = response.get("status", {})
    return {"authenticated": status.get("authenticated") is True, "username": status.get("user", {}).get("username", ""), "audiences": status.get("audiences", [])}


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--keep", action="store_true"); args = parser.parse_args()
    tools = {name: shutil.which(name) for name in ("docker", "kubectl", "k3d")}; created = False
    preflight = {"architecture": platform.machine(), "cpu_count": os.cpu_count(), "disk_free_bytes": shutil.disk_usage(ROOT).free,
                 "tools": tools, "k3s_image_pin": K3S_IMAGE}
    classification = "LIVE_LOCAL_CLOUD_SECURITY_DEFERRED"
    try:
        if not all(tools.values()) or run(["docker", "version"], check=False).returncode: raise InfrastructureUnavailable("required local tooling unavailable")
        proc = run(["k3d", "cluster", "create", CLUSTER, "--image", K3S_IMAGE, "--servers", "1", "--agents", "0",
                    "--k3s-arg", "--disable=traefik@server:0", "--k3s-arg", "--disable=servicelb@server:0", "--wait"], check=False, timeout=180)
        if proc.returncode: raise InfrastructureUnavailable("cluster creation unavailable")
        created = True; kubectl("wait", "--for=condition=Ready", "node", "--all", "--timeout=90s")
        kubectl("apply", "-f", "deploy/p11c/identity.yaml")
        intended = kubectl("create", "token", "inference", "-n", "tenant-acme", "--audience=aegisdesk-cloud-broker", f"--duration={TOKEN_DURATION}").stdout.strip()
        wrong_aud = kubectl("create", "token", "inference", "-n", "tenant-acme", "--audience=wrong-audience", f"--duration={TOKEN_DURATION}").stdout.strip()
        attacker = kubectl("create", "token", "attacker", "-n", "tenant-other", "--audience=aegisdesk-cloud-broker", f"--duration={TOKEN_DURATION}").stdout.strip()
        if not intended or not wrong_aud or not attacker: raise InfrastructureUnavailable("ServiceAccount token unavailable")

        def reviewer(token: str) -> dict:
            result = tokenreview(token)
            if not result["authenticated"]: raise SecurityDenied("TOKENREVIEW_DENIED")
            subject = result["username"]
            parts = subject.split(":")
            if len(parts) != 4: raise SecurityDenied("SUBJECT_MALFORMED")
            return {"cluster": "local-k3d", "namespace": parts[2], "service_account": parts[3],
                    "tenant": parts[2].removeprefix("tenant-"), "audience": "aegisdesk-cloud-broker",
                    "subject": subject, "expiry": 2**31}

        audit = AuditTrail(); broker = IdentityBroker(audit, reviewer)
        valid_credential = broker.exchange(intended)
        wrong_denied = not tokenreview(wrong_aud)["authenticated"]
        try: broker.exchange(attacker); cross_denied = False
        except SecurityDenied: cross_denied = True
        live_gates = {"cluster_created": True, "api_reached": True, "node_ready": True,
                      "serviceaccount_token_obtained": bool(intended), "tokenreview_api_exercised": True,
                      "valid_identity_accepted": valid_credential.principal_id == "system:serviceaccount:tenant-acme:inference",
                      "wrong_audience_denied": wrong_denied, "cross_workload_denied": cross_denied}
        raw = fixture("live", live_gates); evidence = assess(raw); validate_evidence({**raw, **evidence})
        evidence["preflight"] = preflight
        ARTIFACT.parent.mkdir(parents=True, exist_ok=True); ARTIFACT.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        classification = "P11C_LIVE_LOCAL_PASS" if evidence["live_local_cloud_security_validated"] else "P11C_SECURITY_VALIDATION_FAILED"
        print(json.dumps({"classification": classification, "evidence_path": str(ARTIFACT)}, sort_keys=True))
        return 0 if classification == "P11C_LIVE_LOCAL_PASS" else 1
    except InfrastructureUnavailable as exc:
        print(json.dumps({"classification": classification, "reason": str(exc), "preflight": preflight}, sort_keys=True)); return 2
    except (SecurityDenied, subprocess.SubprocessError, ValueError, OSError) as exc:
        print(json.dumps({"classification": "P11C_SECURITY_VALIDATION_FAILED", "reason": str(exc), "preflight": preflight}, sort_keys=True)); return 1
    finally:
        intended = wrong_aud = attacker = ""
        if created and not args.keep: run(["k3d", "cluster", "delete", CLUSTER], check=False, timeout=120)


if __name__ == "__main__": raise SystemExit(main())
