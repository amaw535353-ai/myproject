from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time

from aegis.platform.cloud_security import AuditTrail, IdentityBroker, SecurityDenied, digest
from evals.p11c_cloud_security import assess, validate_evidence
from evals.p11c_fixture import DEFERRED_MASTERY_ITEMS, SCHEMA_VERSION, fixture_manifests_sha256, run_control_plane_scenario

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "p11c-cloud-security-evidence.json"
CLUSTER = "aegisdesk-p11c"
K3S_IMAGE = "rancher/k3s:v1.33.5-k3s1"
TOKEN_DURATION = "10m"
EXPECTED_AUDIENCE = "aegisdesk-cloud-broker"


class InfrastructureUnavailable(RuntimeError): pass


def run(args: list[str], *, check: bool = True, timeout: int = 90, stdin: str | None = None):
    return subprocess.run(args, cwd=ROOT, check=check, timeout=timeout, input=stdin, text=True, capture_output=True)


def kubectl(*args: str, check: bool = True, stdin: str | None = None):
    return run(["kubectl", *args], check=check, stdin=stdin)


def tokenreview(token: str, audience: str = EXPECTED_AUDIENCE) -> dict:
    request = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": {"token": token, "audiences": [audience]}}
    response = json.loads(kubectl("create", "--raw", "/apis/authentication.k8s.io/v1/tokenreviews", "-f", "-", stdin=json.dumps(request)).stdout)
    status = response.get("status", {})
    return {"authenticated": status.get("authenticated") is True,
            "username": status.get("user", {}).get("username", ""),
            "audiences": status.get("audiences", [])}


def decode_payload_after_tokenreview(token: str) -> dict:
    try:
        parts = token.split(".")
        if len(parts) != 3: raise ValueError("not JWT")
        return json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, json.JSONDecodeError) as exc:
        raise SecurityDenied("TOKEN_PAYLOAD_INVALID") from exc


def verified_kubernetes_identity(token: str, cluster_uid: str) -> dict:
    review = tokenreview(token, EXPECTED_AUDIENCE)
    if not review["authenticated"]: raise SecurityDenied("TOKENREVIEW_DENIED")
    claims = decode_payload_after_tokenreview(token)
    subject = review["username"]
    parts = subject.split(":")
    audience = claims.get("aud", [])
    audiences = [audience] if isinstance(audience, str) else audience
    expiry = int(claims.get("exp", 0))
    if len(parts) != 4 or parts[:2] != ["system", "serviceaccount"]: raise SecurityDenied("SUBJECT_MALFORMED")
    namespace, service_account = parts[2], parts[3]
    kubernetes = claims.get("kubernetes.io", {})
    claimed_namespace = kubernetes.get("namespace", claims.get("kubernetes.io/serviceaccount/namespace"))
    claimed_sa = kubernetes.get("serviceaccount", {}).get("name", claims.get("kubernetes.io/serviceaccount/service-account.name"))
    if EXPECTED_AUDIENCE not in audiences or EXPECTED_AUDIENCE not in review["audiences"]:
        raise SecurityDenied("AUDIENCE_BINDING_DENIED")
    if expiry <= int(time.time()): raise SecurityDenied("TOKEN_EXPIRED")
    if claimed_namespace != namespace or claimed_sa != service_account: raise SecurityDenied("SERVICEACCOUNT_CLAIMS_MISMATCH")
    return {"cluster": cluster_uid, "namespace": namespace, "service_account": service_account,
            "tenant": namespace.removeprefix("tenant-"), "audience": EXPECTED_AUDIENCE,
            "subject": subject, "expiry": expiry}


def request_token(service_account: str, namespace: str, audience: str = EXPECTED_AUDIENCE) -> str:
    token = kubectl("create", "token", service_account, "-n", namespace,
                    f"--audience={audience}", f"--duration={TOKEN_DURATION}").stdout.strip()
    if not token: raise InfrastructureUnavailable("ServiceAccount token unavailable")
    return token


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--keep", action="store_true"); args = parser.parse_args()
    tools = {name: shutil.which(name) for name in ("docker", "kubectl", "k3d")}; created = False
    intended = wrong_aud = attacker = replacement_token = ""
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
        cluster_uid = kubectl("get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}").stdout.strip()
        if not cluster_uid: raise InfrastructureUnavailable("cluster identity unavailable")
        intended = request_token("inference", "tenant-acme")
        wrong_aud = request_token("inference", "tenant-acme", "wrong-audience")
        attacker = request_token("attacker", "tenant-other")

        audit = AuditTrail()
        broker = IdentityBroker(audit, lambda token: verified_kubernetes_identity(token, cluster_uid), expected_cluster=cluster_uid)
        initial = broker.exchange(intended)
        intended_claims = verified_kubernetes_identity(intended, cluster_uid)
        wrong_review = tokenreview(wrong_aud)
        if wrong_review["authenticated"]: raise SecurityDenied("WRONG_AUDIENCE_ACCEPTED")
        attacker_review = tokenreview(attacker)
        if not attacker_review["authenticated"]: raise InfrastructureUnavailable("attacker TokenReview did not authenticate")
        try:
            broker.exchange(attacker); cross_denied = False
        except SecurityDenied:
            cross_denied = True
        if not cross_denied: raise SecurityDenied("CROSS_WORKLOAD_EXCHANGE_ALLOWED")

        gates = {"cluster_created": True, "api_reached": True, "node_ready": True,
                 "cluster_identity_obtained": True, "cluster_identity_sha256": digest(cluster_uid),
                 "serviceaccount_token_obtained": True, "tokenreview_api_exercised": True,
                 "intended_token_authenticated": True,
                 "intended_subject_verified": initial.principal_id == "system:serviceaccount:tenant-acme:inference",
                 "intended_audience_verified": intended_claims["audience"] == EXPECTED_AUDIENCE,
                 "token_expiry_verified": initial.expires_at <= intended_claims["expiry"],
                 "intended_token_expiry_epoch": intended_claims["expiry"],
                 "wrong_audience_token_denied": True, "attacker_token_authenticated": True,
                 "broker_cross_workload_exchange_denied": True, "live_broker_credential_issued": True,
                 "live_credential_used_for_iam": False, "live_credential_used_for_kms": False,
                 "live_credential_used_for_secrets": False, "live_credential_used_for_metadata": False,
                 "compromised_live_credential_revoked": False,
                 "replacement_serviceaccount_token_obtained": False, "replacement_tokenreview_exercised": False,
                 "replacement_broker_credential_issued": False, "replacement_generation_advanced": False,
                 "live_safe_operation_restored": False}

        def replacement_factory():
            nonlocal replacement_token
            replacement_token = request_token("inference", "tenant-acme")
            if replacement_token == intended: raise SecurityDenied("REPLACEMENT_TOKEN_NOT_FRESH")
            replacement_identity = verified_kubernetes_identity(replacement_token, cluster_uid)
            broker.recover(initial.principal_id)
            replacement = broker.exchange(replacement_token)
            gates["replacement_serviceaccount_token_obtained"] = True
            gates["replacement_tokenreview_exercised"] = True
            gates["replacement_broker_credential_issued"] = replacement.token != initial.token
            gates["replacement_generation_advanced"] = replacement.generation > initial.generation
            if replacement_identity["subject"] != initial.principal_id: raise SecurityDenied("REPLACEMENT_PRINCIPAL_MISMATCH")
            return replacement

        identity_cases = [
            {"case": "live_intended_token", "expected": "ALLOW", "observed": "ALLOW", "executed": True},
            {"case": "live_wrong_audience", "expected": "DENY", "observed": "DENY", "executed": True},
            {"case": "live_cross_workload", "expected": "DENY", "observed": "DENY", "executed": True},
        ]
        observations, audit_evidence = run_control_plane_scenario(
            broker=broker, initial_credential=initial, replacement_credential_factory=replacement_factory,
            audit=audit, identity_cases=identity_cases, live_gates=gates)
        raw = {"phase": "P11-C", "schema_version": SCHEMA_VERSION, "execution_mode": "live",
               "environment_classification": "PROVIDER_NEUTRAL_LOCAL_K3D",
               "fixture_manifests_sha256": fixture_manifests_sha256(), "observations": observations,
               "audit": audit_evidence, "production_cloud_validation_claimed": False,
               "professional_mastery_complete": False, "deferred_mastery_items": list(DEFERRED_MASTERY_ITEMS)}
        evidence = assess(raw); validate_evidence({**raw, **evidence}); evidence["preflight"] = preflight
        ARTIFACT.parent.mkdir(parents=True, exist_ok=True); ARTIFACT.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        classification = "P11C_LIVE_LOCAL_PASS" if evidence["live_local_cloud_security_validated"] else "P11C_SECURITY_VALIDATION_FAILED"
        print(json.dumps({"classification": classification, "evidence_path": str(ARTIFACT)}, sort_keys=True))
        return 0 if classification == "P11C_LIVE_LOCAL_PASS" else 1
    except InfrastructureUnavailable as exc:
        print(json.dumps({"classification": classification, "reason": str(exc), "preflight": preflight}, sort_keys=True)); return 2
    except (SecurityDenied, subprocess.SubprocessError, ValueError, OSError) as exc:
        print(json.dumps({"classification": "P11C_SECURITY_VALIDATION_FAILED", "reason": str(exc), "preflight": preflight}, sort_keys=True)); return 1
    finally:
        intended = wrong_aud = attacker = replacement_token = ""
        if created and not args.keep: run(["k3d", "cluster", "delete", CLUSTER], check=False, timeout=120)


if __name__ == "__main__": raise SystemExit(main())
