from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from aegis.platform.serving_security import evidence_is_sensitive_material_free, runtime_security_context_valid
from evals.p11d_fixture import DEFERRED_MASTERY_ITEMS, LIVE_GATE_NAMES, SCHEMA_VERSION, fixture_manifests_sha256, observations
from evals.p11d_serving_security import assess, validate_evidence

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "p11d-serving-security-evidence.json"
CLUSTER = "aegisdesk-p11d"; IMAGE = "aegisdesk-p11d:local"; K3S_IMAGE = "rancher/k3s:v1.33.5-k3s1"
HTTPS_PORT = 18443; HTTP_PORT = 18444


class InfrastructureUnavailable(RuntimeError): pass


def run(args: list[str], *, check: bool = True, timeout: int = 120, stdin: str | None = None):
    return subprocess.run(args, cwd=ROOT, check=check, timeout=timeout, input=stdin, text=True, capture_output=True)


def kubectl(*args: str, check: bool = True, timeout: int = 120): return run(["kubectl", *args], check=check, timeout=timeout)


def wait_for_traefik(timeout: int = 120) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = kubectl("-n", "kube-system", "get", "deployment", "traefik", check=False)
        if found.returncode == 0:
            kubectl("-n", "kube-system", "rollout", "status", "deployment/traefik", f"--timeout={int(max(1, deadline-time.monotonic()))}s")
            return
        time.sleep(2)
    raise InfrastructureUnavailable("Traefik deployment unavailable")


def pod_exec(namespace: str, pod: str, code: str, attempts: int = 3):
    last = None
    for _ in range(attempts):
        last = kubectl("-n", namespace, "exec", pod, "--", "python", "-c", code, check=False, timeout=15)
        if last.returncode == 0: return last
        time.sleep(1)
    raise RuntimeError(f"pod exec observation failed: {last.stderr[-500:]!r}")


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data); path.chmod(0o600)


def generate_pki(directory: Path) -> dict:
    now = dt.datetime.now(dt.timezone.utc); ca_key = rsa.generate_private_key(65537, 2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AegisDesk P11-D Local CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=1))
          .not_valid_after(now+dt.timedelta(hours=2)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    def leaf(name: str, sans: list[str], server: bool, client: bool, prefix: str, issuer_key=ca_key, issuer=ca):
        key = rsa.generate_private_key(65537, 2048); eku = []
        if server: eku.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if client: eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
                .issuer_name(issuer.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(minutes=30))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(x) for x in sans]), critical=False)
                .add_extension(x509.ExtendedKeyUsage(eku), critical=True).sign(issuer_key, hashes.SHA256()))
        _write(directory/f"{prefix}.key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        _write(directory/f"{prefix}.crt", cert.public_bytes(serialization.Encoding.PEM)); return cert
    _write(directory/"ca.crt", ca.public_bytes(serialization.Encoding.PEM))
    ingress = leaf("serve.p11d.local", ["serve.p11d.local"], True, False, "ingress")
    backend = leaf("backend.p11d.svc.cluster.local", ["backend.p11d.svc.cluster.local", "backend.p11d"], True, False, "backend")
    gateway = leaf("gateway.p11d.internal", ["gateway.p11d.internal"], False, True, "gateway")
    wrong = leaf("wrong.p11d.internal", ["wrong.p11d.internal"], False, True, "wrong")
    other_key = rsa.generate_private_key(65537, 2048)
    other_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Untrusted Local CA")])
    other_ca = (x509.CertificateBuilder().subject_name(other_name).issuer_name(other_name).public_key(other_key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(hours=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(other_key, hashes.SHA256()))
    untrusted = leaf("gateway.p11d.internal", ["gateway.p11d.internal"], False, True, "untrusted", other_key, other_ca)
    return {"ca_sha256": ca.fingerprint(hashes.SHA256()).hex(), "server_cert_sha256": ingress.fingerprint(hashes.SHA256()).hex(),
            "client_cert_sha256": gateway.fingerprint(hashes.SHA256()).hex(), "backend_cert_sha256": backend.fingerprint(hashes.SHA256()).hex(),
            "sans": {"ingress": ["serve.p11d.local"], "backend": ["backend.p11d.svc.cluster.local", "backend.p11d"], "gateway": ["gateway.p11d.internal"]},
            "not_before": ingress.not_valid_before_utc.isoformat(), "not_after": ingress.not_valid_after_utc.isoformat()}


def tls_request(port: int, hostname: str, ca: Path, *, cert: Path | None = None, key: Path | None = None,
                method: str = "GET", path: str = "/healthz", body: bytes = b"", headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    context = ssl.create_default_context(cafile=str(ca))
    if cert and key: context.load_cert_chain(cert, key)
    raw = socket.create_connection(("127.0.0.1", port), timeout=5)
    wrapped = context.wrap_socket(raw, server_hostname=hostname)
    request_headers = {"Host": hostname, "Connection": "close", "Content-Length": str(len(body)), **(headers or {})}
    request = f"{method} {path} HTTP/1.1\r\n".encode() + b"".join(f"{k}: {v}\r\n".encode() for k, v in request_headers.items()) + b"\r\n" + body
    wrapped.sendall(request); response = http.client.HTTPResponse(wrapped); response.begin(); data = response.read(); wrapped.close()
    return response.status, data


def ingress_request(pki: Path, payload: dict, extra: dict[str, str] | None = None) -> tuple[int, bytes]:
    body = json.dumps(payload).encode()
    return tls_request(HTTPS_PORT, "serve.p11d.local", pki/"ca.crt", method="POST", path="/v1/infer", body=body,
                       headers={"Content-Type": "application/json", "X-Client-ID": "client-acme", **(extra or {})})


def main() -> int:
    argparse.ArgumentParser().parse_args(); created = False; port_forward = None; pki_path = Path(tempfile.mkdtemp(prefix="p11d-pki-"))
    drain_capability = secrets.token_urlsafe(32)
    tools = {x: shutil.which(x) for x in ("docker", "kubectl", "k3d")}; classification = "LIVE_LOCAL_SERVING_SECURITY_DEFERRED"
    preflight = {"tools": tools, "k3s_image": K3S_IMAGE, "image_tag": IMAGE}
    try:
        if not all(tools.values()) or run(["docker", "version"], check=False).returncode: raise InfrastructureUnavailable("required local tooling unavailable")
        cert_meta = generate_pki(pki_path)
        build = run(["docker", "build", "-f", "deploy/p11d/Dockerfile", "-t", IMAGE, "."], check=False, timeout=300)
        if build.returncode: raise InfrastructureUnavailable("local image build unavailable")
        image_id = run(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"]).stdout.strip()
        create = run(["k3d", "cluster", "create", CLUSTER, "--image", K3S_IMAGE, "--servers", "1", "--agents", "0",
                      "-p", f"{HTTPS_PORT}:443@loadbalancer", "-p", f"{HTTP_PORT}:80@loadbalancer", "--wait"], check=False, timeout=240)
        if create.returncode: raise InfrastructureUnavailable("cluster creation unavailable")
        created = True; run(["k3d", "image", "import", IMAGE, "-c", CLUSTER, "--mode", "direct"], timeout=180)
        imported = run(["docker", "exec", f"k3d-{CLUSTER}-server-0", "ctr", "-n", "k8s.io", "images", "list", "-q"], check=False)
        if imported.returncode or "aegisdesk-p11d:local" not in imported.stdout:
            raise InfrastructureUnavailable("local serving image import unavailable")
        kubectl("wait", "--for=condition=Ready", "node", "--all", "--timeout=90s")
        kubectl("create", "namespace", "p11d")
        kubectl("-n", "p11d", "create", "secret", "tls", "ingress-tls", f"--cert={pki_path/'ingress.crt'}", f"--key={pki_path/'ingress.key'}")
        kubectl("-n", "p11d", "create", "secret", "generic", "backend-pki", f"--from-file=tls.crt={pki_path/'backend.crt'}", f"--from-file=tls.key={pki_path/'backend.key'}", f"--from-file=ca.crt={pki_path/'ca.crt'}")
        kubectl("-n", "p11d", "create", "secret", "generic", "gateway-pki", f"--from-file=tls.crt={pki_path/'gateway.crt'}", f"--from-file=tls.key={pki_path/'gateway.key'}", f"--from-file=ca.crt={pki_path/'ca.crt'}")
        kubectl("-n", "p11d", "create", "secret", "generic", "drain-capability", f"--from-literal=token={drain_capability}")
        kubectl("apply", "-f", "deploy/p11d/resources.yaml")
        wait_for_traefik()
        kubectl("-n", "p11d", "rollout", "status", "deployment/backend", "--timeout=120s")
        kubectl("-n", "p11d", "rollout", "status", "deployment/gateway", "--timeout=120s")
        kubectl("-n", "p11d", "wait", "--for=condition=Ready", "pod/attacker", "--timeout=90s")
        ingress_active = kubectl("-n", "p11d", "get", "ingress", "serving", check=False).returncode == 0

        ingress_deadline = time.monotonic() + 30
        while True:
            try:
                ingress_ready = tls_request(HTTPS_PORT, "serve.p11d.local", pki_path/"ca.crt", path="/readyz")[0] == 200
            except (OSError, ssl.SSLError, http.client.HTTPException):
                ingress_ready = False
            if ingress_ready: break
            if time.monotonic() >= ingress_deadline: raise InfrastructureUnavailable("Ingress route did not become ready")
            time.sleep(1)

        good_status, good_body = ingress_request(pki_path, {"request_id": "req-live0001", "tenant": "acme", "prompt": "safe"})
        if good_status != 200 or json.loads(good_body).get("output") != "synthetic-ok":
            gateway_logs = kubectl("-n", "p11d", "logs", "deployment/gateway", "--tail=30", check=False).stdout
            backend_logs = kubectl("-n", "p11d", "logs", "deployment/backend", "--tail=30", check=False).stdout
            raise RuntimeError(f"ingress request failed status={good_status}; gateway={gateway_logs[-1000:]!r}; backend={backend_logs[-1000:]!r}")
        wrong_host = untrusted = False
        try: tls_request(HTTPS_PORT, "wrong.p11d.local", pki_path/"ca.crt")
        except ssl.SSLError: wrong_host = True
        try: tls_request(HTTPS_PORT, "serve.p11d.local", pki_path/"untrusted.crt")
        except ssl.SSLError: untrusted = True
        plain = socket.create_connection(("127.0.0.1", HTTP_PORT), 3); plain.sendall(b"GET /v1/infer HTTP/1.1\r\nHost: serve.p11d.local\r\nConnection: close\r\n\r\n"); plain_data = plain.recv(512); plain.close()
        direct_status, _ = tls_request(HTTPS_PORT, "serve.p11d.local", pki_path/"ca.crt", path="/backend-direct")
        spoof_status, _ = ingress_request(pki_path, {"request_id": "req-spoof001", "tenant": "acme", "prompt": "safe"}, {"X-Internal-Principal": "admin"})
        oversized_status, _ = ingress_request(pki_path, {"request_id": "req-large001", "tenant": "acme", "prompt": "x" * 600})
        tenant_status, _ = ingress_request(pki_path, {"request_id": "req-tenant01", "tenant": "other", "prompt": "safe"})
        malformed_status, _ = tls_request(HTTPS_PORT, "serve.p11d.local", pki_path/"ca.crt", method="POST", path="/v1/infer", body=b"{bad",
                                          headers={"Content-Type": "application/json", "X-Client-ID": "client-acme"})
        content_status, _ = tls_request(HTTPS_PORT, "serve.p11d.local", pki_path/"ca.crt", method="POST", path="/v1/infer", body=b"{}",
                                        headers={"Content-Type": "text/plain", "X-Client-ID": "client-acme"})

        time.sleep(2.1)
        rate_results = [ingress_request(pki_path, {"request_id": f"req-rate{i:04d}", "tenant": "acme", "prompt": "safe"})[0] for i in range(4)]
        rate_allowed = sum(x == 200 for x in rate_results); rate_limited = sum(x == 429 for x in rate_results)
        time.sleep(2.1)
        with ThreadPoolExecutor(max_workers=3) as pool:
            concurrent = list(pool.map(lambda i: ingress_request(pki_path, {"request_id": f"req-conc{i:04d}", "tenant": "acme", "prompt": "safe", "delay_ms": 3000})[0], range(3)))
        concurrency_denied = concurrent.count(429) == 1 and concurrent.count(200) == 2

        port_forward = subprocess.Popen(["kubectl", "-n", "p11d", "port-forward", "service/backend", "18445:8443"], cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        valid_mtls = tls_request(18445, "backend.p11d.svc.cluster.local", pki_path/"ca.crt", cert=pki_path/"gateway.crt", key=pki_path/"gateway.key")[0] == 200
        wrong_backend_hostname = False
        try: tls_request(18445, "wrong-backend.p11d", pki_path/"ca.crt", cert=pki_path/"gateway.crt", key=pki_path/"gateway.key")
        except ssl.SSLError: wrong_backend_hostname = True
        missing_client = wrong_client = untrusted_client = plaintext_backend = False
        for label, cert, key in (("missing", None, None), ("wrong", pki_path/"wrong.crt", pki_path/"wrong.key"), ("untrusted", pki_path/"untrusted.crt", pki_path/"untrusted.key")):
            try:
                status, _ = tls_request(18445, "backend.p11d.svc.cluster.local", pki_path/"ca.crt", cert=cert, key=key)
                denied = status >= 400
            except (ssl.SSLError, ConnectionError, http.client.HTTPException, OSError): denied = True
            if label == "missing": missing_client = denied
            elif label == "wrong": wrong_client = denied
            else: untrusted_client = denied
        try:
            s = socket.create_connection(("127.0.0.1", 18445), 3); s.sendall(b"GET /healthz HTTP/1.0\r\n\r\n"); plaintext_backend = not s.recv(64).startswith(b"HTTP/"); s.close()
        except OSError: plaintext_backend = True

        attacker = kubectl("-n", "p11d", "exec", "attacker", "--", "python", "-c", "import socket; socket.create_connection(('backend',8443),2)", check=False, timeout=10)
        attacker_denied = attacker.returncode != 0
        deployment = json.loads(kubectl("-n", "p11d", "get", "deployment", "gateway", "-o", "json").stdout)
        container = deployment["spec"]["template"]["spec"]["containers"][0]; pod_spec = deployment["spec"]["template"]["spec"]
        runtime_ok = runtime_security_context_valid(container, pod_spec)

        time.sleep(2.1)
        with ThreadPoolExecutor(max_workers=1) as pool:
            active = pool.submit(ingress_request, pki_path, {"request_id": "req-drain001", "tenant": "acme", "prompt": "safe", "delay_ms": 2000})
            time.sleep(.4)
            gateway_pod = kubectl("-n", "p11d", "get", "pod", "-l", "app=gateway", "-o", "jsonpath={.items[0].metadata.name}").stdout.strip()
            backend_pod = kubectl("-n", "p11d", "get", "pod", "-l", "app=backend", "-o", "jsonpath={.items[0].metadata.name}").stdout.strip()
            drain_cmd = "import os,httpx; print(httpx.post('http://127.0.0.1:8081/internal/drain',headers={'X-Drain-Token':os.environ['P11D_DRAIN_TOKEN']},trust_env=False).status_code)"
            drained = pod_exec("p11d", backend_pod, drain_cmd).stdout.strip().endswith("200")
            new_status, _ = ingress_request(pki_path, {"request_id": "req-drain002", "tenant": "acme", "prompt": "safe"})
            active_status = active.result()[0]
        deadline = time.monotonic() + 15; readiness_removed = False
        while time.monotonic() < deadline:
            ready_value = kubectl("-n", "p11d", "get", "pod", backend_pod, "-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}").stdout.strip()
            if ready_value == "False": readiness_removed = True; break
            time.sleep(1)
        state_cmd = "import os,json,httpx; r=httpx.get('http://127.0.0.1:8081/internal/state',headers={'X-Drain-Token':os.environ['P11D_DRAIN_TOKEN']},trust_env=False,timeout=3); r.raise_for_status(); print(json.dumps(r.json()))"
        state_result = pod_exec("p11d", backend_pod, state_cmd)
        live_state = json.loads(state_result.stdout.strip().splitlines()[-1])
        zero = live_state["in_flight"] == 0
        kubectl("-n", "p11d", "delete", "pod", backend_pod, "--wait=false")
        kubectl("-n", "p11d", "rollout", "status", "deployment/backend", "--timeout=120s")
        time.sleep(2.1); post_status, _ = ingress_request(pki_path, {"request_id": "req-after001", "tenant": "acme", "prompt": "safe"})

        if port_forward: port_forward.terminate(); port_forward.wait(timeout=5); port_forward = None
        delete = run(["k3d", "cluster", "delete", CLUSTER], check=False, timeout=120); created = False
        shutil.rmtree(pki_path); pki_removed = not pki_path.exists()
        gates = {x: False for x in LIVE_GATE_NAMES}
        gates.update({"cluster_created": True, "api_reached": True, "node_ready": True,
                      "ingress_controller_ready": True, "ingress_resource_active": ingress_active,
                      "tls_ca_generated": True, "https_handshake_verified": good_status == 200,
                      "wrong_hostname_rejected": wrong_host, "untrusted_ca_rejected": untrusted,
                      "backend_mtls_enabled": valid_mtls, "valid_gateway_client_cert_accepted": valid_mtls,
                      "missing_client_cert_rejected": missing_client, "wrong_client_identity_rejected": wrong_client,
                      "untrusted_client_ca_rejected": untrusted_client, "backend_hostname_verified": wrong_backend_hostname,
                      "plaintext_backend_rejected": plaintext_backend,
                      "gateway_request_success": good_status == 200, "direct_backend_external_access_denied": direct_status == 404,
                      "plaintext_http_denied": b" 404 " in plain_data or b" 301 " in plain_data or b" 308 " in plain_data,
                      "trusted_header_spoof_rejected": spoof_status == 403, "tenant_mismatch_rejected": tenant_status == 403,
                      "malformed_request_rejected": malformed_status == 400, "wrong_content_type_rejected": content_status == 403,
                      "rate_limit_exercised": True, "concurrency_limit_exercised": True,
                      "burst_limited": rate_limited == 1, "safe_requests_below_limit": rate_allowed == 3,
                      "concurrency_exhaustion_rejected": concurrency_denied, "safe_concurrency": concurrent.count(200) == 2,
                      "oversized_body_rejected": oversized_status == 413, "health_probe_exercised": live_state["healthy"],
                      "readiness_probe_exercised": readiness_removed, "readiness_distinct_from_health": live_state["healthy"] and not live_state["ready"],
                      "unready_backend_not_routed": new_status in (502, 503), "network_policy_exercised": True,
                      "gateway_backend_path_allowed": good_status == 200, "attacker_backend_path_denied": attacker_denied,
                      "runtime_security_context_verified": runtime_ok, "drain_started": drained,
                      "readiness_removed_during_drain": readiness_removed, "new_request_denied_during_drain": new_status in (502, 503),
                      "inflight_request_completed": active_status == 200, "drain_reached_zero_inflight": zero,
                      "replacement_pod_ready": post_status == 200, "post_replacement_request_succeeded": post_status == 200,
                      "cleanup_complete": delete.returncode == 0 and pki_removed,
                      "sensitive_leak_absent": False, "ca_sha256": cert_meta["ca_sha256"],
                      "server_cert_sha256": cert_meta["server_cert_sha256"], "client_cert_sha256": cert_meta["client_cert_sha256"],
                      "image_id": image_id, "rate_attempts": len(rate_results), "rate_allowed": rate_allowed, "rate_limited": rate_limited})
        obs = observations(); obs["live_gates"] = gates
        raw = {"phase": "P11-D", "schema_version": SCHEMA_VERSION, "execution_mode": "live", "environment_classification": "LIVE_LOCAL_K3D",
               "fixture_manifests_sha256": fixture_manifests_sha256(), "observations": obs, "production_serving_validation_claimed": False,
               "professional_mastery_complete": False, "deferred_mastery_items": list(DEFERRED_MASTERY_ITEMS)}
        candidate = {"raw": raw, "preflight": preflight, "certificate_metadata": cert_meta}
        gates["sensitive_leak_absent"] = evidence_is_sensitive_material_free(candidate, forbidden_values=(drain_capability,))
        evidence = assess(raw)
        persisted = {**evidence, "preflight": preflight, "certificate_metadata": cert_meta}
        if not evidence_is_sensitive_material_free(persisted, forbidden_values=(drain_capability,)):
            gates["sensitive_leak_absent"] = False
            evidence = assess(raw)
            persisted = {**evidence, "preflight": preflight, "certificate_metadata": cert_meta}
        validate_evidence({**raw, **evidence})
        evidence = persisted
        ARTIFACT.parent.mkdir(parents=True, exist_ok=True); ARTIFACT.write_text(json.dumps(evidence, indent=2, sort_keys=True)+"\n")
        classification = "P11D_LIVE_LOCAL_PASS" if evidence["live_local_serving_security_validated"] else "P11D_SECURITY_VALIDATION_FAILED"
        print(json.dumps({"classification": classification, "evidence_path": str(ARTIFACT)}, sort_keys=True)); return 0 if classification.endswith("PASS") else 1
    except InfrastructureUnavailable as exc:
        print(json.dumps({"classification": classification, "reason": str(exc), "preflight": preflight}, sort_keys=True)); return 2
    except Exception as exc:
        print(json.dumps({"classification": "P11D_SECURITY_VALIDATION_FAILED", "reason": f"{type(exc).__name__}: {exc}", "preflight": preflight}, sort_keys=True)); return 1
    finally:
        if port_forward:
            port_forward.terminate()
            try: port_forward.wait(timeout=5)
            except subprocess.TimeoutExpired: port_forward.kill()
        if created: run(["k3d", "cluster", "delete", CLUSTER], check=False, timeout=120)
        if pki_path.exists(): shutil.rmtree(pki_path)


if __name__ == "__main__": raise SystemExit(main())
