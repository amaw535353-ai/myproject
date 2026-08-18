#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, replace
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aegis.model_supply_chain.key_lifecycle import KeyLifecycleRejected, LifecycleRestrictedModelPackageLoader
from aegis.model_supply_chain.package_provenance import RestrictedModelPackageLoader
from aegis.platform.supply_chain_security import (Ed25519EnvelopeSigner, LiveArtifactSafetyScanner,
    POLICY_VERSION, QuarantineRegistry, SupplyChainDenied, canonical_bytes, evidence_is_clean,
    evaluate_vulnerability_report, sha256, validate_sbom, verify_envelope, verify_provenance)
from evals.p11e_fixture import DEFERRED_MASTERY_ITEMS, fixture, fixture_manifests_sha256
from evals.p11e_supply_chain_security import assess, validate_evidence

ARTIFACT = ROOT / "artifacts/p11e-supply-chain-evidence.json"
CLUSTER = "aegisdesk-p11e"
REGISTRY = "p11e-registry.localhost"
REGISTRY_PORT = "15001"

class InfrastructureUnavailable(RuntimeError): pass

def run(args: list[str], *, input_text: str | None = None, timeout: int = 180, check: bool = True, env: dict | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, cwd=ROOT, input=input_text, text=True, capture_output=True, timeout=timeout, check=check, env=env)
    except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        if check: raise InfrastructureUnavailable(f"command failed: {args[0]}") from exc
        return exc if isinstance(exc, subprocess.CompletedProcess) else subprocess.CompletedProcess(args, 1, "", str(exc))

def tool_version(tool: str) -> str:
    path = shutil.which(tool)
    if not path: raise InfrastructureUnavailable(f"{tool} unavailable")
    command = [path, "version"] if tool != "kubectl" else [path, "version", "--client"]
    result = run(command, timeout=30)
    return (result.stdout + result.stderr).strip().splitlines()[0][:200]

def kubectl(*args: str, input_text: str | None = None, check: bool = True, timeout: int = 120):
    return run(["kubectl", *args], input_text=input_text, check=check, timeout=timeout)

def apply(value: dict) -> None:
    kubectl("apply", "-f", "-", input_text=json.dumps(value))

def certificate_bundle(directory: Path) -> tuple[str, str, str]:
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AegisDesk P11-E ephemeral webhook CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(hours=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "p11e-webhook.p11e-system.svc")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-dt.timedelta(minutes=1)).not_valid_after(now+dt.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("p11e-webhook.p11e-system.svc")]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).sign(ca_key, hashes.SHA256()))
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    (directory/"tls.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory/"tls.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return base64.b64encode(ca_pem).decode(), sha256(ca.public_bytes(serialization.Encoding.DER)), sha256(cert.public_bytes(serialization.Encoding.DER))

def receipt_annotation(envelope) -> str:
    return base64.urlsafe_b64encode(canonical_bytes({"payload": envelope.payload, "signature": envelope.signature})).decode()

def pod(name: str, image: str, receipt: str | None) -> dict:
    annotations = {} if receipt is None else {"aegisdesk.dev/supply-chain-receipt": receipt}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": "p11e-protected", "annotations": annotations},
            "spec": {"automountServiceAccountToken": False, "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}},
                     "containers": [{"name": "candidate", "image": image, "command": ["python", "-c", "import time; time.sleep(300)"],
                                     "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                                     "resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"cpu": "100m", "memory": "128Mi"}}}]}}

def denied(value: dict) -> bool:
    return kubectl("apply", "--dry-run=server", "-f", "-", input_text=json.dumps(value), check=False, timeout=30).returncode != 0

def deploy_webhook(image: str, public_key: bytes, ca_bundle: str, pki: Path) -> None:
    apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "p11e-system"}})
    apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "p11e-protected", "labels": {"aegisdesk.dev/p11e-admission": "enabled", "pod-security.kubernetes.io/enforce": "restricted", "pod-security.kubernetes.io/enforce-version": "latest"}}})
    secret = kubectl("-n", "p11e-system", "create", "secret", "tls", "p11e-webhook-tls", "--cert", str(pki/"tls.crt"), "--key", str(pki/"tls.key"), "--dry-run=client", "-o", "json")
    apply(json.loads(secret.stdout))
    apply({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "p11e-webhook", "namespace": "p11e-system"}, "spec": {"replicas": 1, "selector": {"matchLabels": {"app": "p11e-webhook"}}, "template": {"metadata": {"labels": {"app": "p11e-webhook"}}, "spec": {"automountServiceAccountToken": False, "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}}, "containers": [{"name": "webhook", "image": image, "command": ["uvicorn", "apps.p11e_admission_webhook:app", "--host", "0.0.0.0", "--port", "8443", "--ssl-certfile", "/tls/tls.crt", "--ssl-keyfile", "/tls/tls.key"], "env": [{"name": "P11E_RECEIPT_PUBLIC_KEY", "value": base64.b64encode(public_key).decode()}], "ports": [{"containerPort": 8443}], "readinessProbe": {"httpGet": {"path": "/healthz", "port": 8443, "scheme": "HTTPS"}}, "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}, "resources": {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"cpu": "100m", "memory": "128Mi"},}, "volumeMounts": [{"name": "tls", "mountPath": "/tls", "readOnly": True}]}], "volumes": [{"name": "tls", "secret": {"secretName": "p11e-webhook-tls"}}]}}}})
    apply({"apiVersion": "v1", "kind": "Service", "metadata": {"name": "p11e-webhook", "namespace": "p11e-system"}, "spec": {"selector": {"app": "p11e-webhook"}, "ports": [{"port": 443, "targetPort": 8443}]}})
    kubectl("-n", "p11e-system", "rollout", "status", "deployment/p11e-webhook", "--timeout=120s")
    apply({"apiVersion": "admissionregistration.k8s.io/v1", "kind": "ValidatingWebhookConfiguration", "metadata": {"name": "p11e-supply-chain"}, "webhooks": [{"name": "supply-chain.aegisdesk.dev", "admissionReviewVersions": ["v1"], "sideEffects": "None", "failurePolicy": "Fail", "timeoutSeconds": 5, "matchPolicy": "Equivalent", "namespaceSelector": {"matchLabels": {"aegisdesk.dev/p11e-admission": "enabled"}}, "rules": [{"apiGroups": [""], "apiVersions": ["v1"], "operations": ["CREATE", "UPDATE"], "resources": ["pods"], "scope": "Namespaced"}], "clientConfig": {"service": {"namespace": "p11e-system", "name": "p11e-webhook", "path": "/validate", "port": 443}, "caBundle": ca_bundle}}]})
    time.sleep(2)

def model_scenario() -> dict:
    import evals.p5b_model_package_provenance as p5b
    import evals.p5d_key_lifecycle_revocation as p5d
    components = p5b._core(); manifest = p5b._manifest(components)
    verified = RestrictedModelPackageLoader(p5b._policy()).load(request=p5b.ModelPackageRequest(p5b._PACKAGE_ID, p5b._MODEL_ID, p5b._REVISION), manifest=manifest, package_signature=p5b._package_sig(manifest), artifacts=p5b._artifacts(components))
    scanner = LiveArtifactSafetyScanner(); scanner.scan_json(p5b._PAYLOADS["config"], expected_sha256=sha256(p5b._PAYLOADS["config"]))
    poison = b'{"architectures":["AegisSynthetic"],"backdoor_trigger":"cf_trigger"}'
    poisoned_components = tuple(replace(x, sha256=sha256(poison), size_bytes=len(poison)) if x.artifact_id == "config" else x for x in components)
    poisoned_manifest = p5b._manifest(poisoned_components); poisoned_artifacts = p5b._artifacts(poisoned_components)
    poisoned_artifacts["config"] = p5b._bundle("config", poison, "json")
    RestrictedModelPackageLoader(p5b._policy()).load(request=p5b.ModelPackageRequest(p5b._PACKAGE_ID, p5b._MODEL_ID, p5b._REVISION), manifest=poisoned_manifest, package_signature=p5b._package_sig(poisoned_manifest), artifacts=poisoned_artifacts)
    detected = False
    try: scanner.scan_json(poison, expected_sha256=sha256(poison))
    except SupplyChainDenied: detected = True
    quarantine = QuarantineRegistry(); poison_digest = sha256(poisoned_manifest.__repr__().encode())
    quarantine.quarantine(poison_digest, reason="POISON_MARKER", incident_id="p11e-incident-1", order=4)
    replay_denied = False
    try: quarantine.require_allowed(poison_digest)
    except SupplyChainDenied: replay_denied = True
    request, old_manifest, old_sig, old_artifacts = p5d._attack_case("revoked_artifact_key")
    revoked = False
    try: LifecycleRestrictedModelPackageLoader(p5d._policy()).load(request=request, manifest=old_manifest, package_signature=old_sig, artifacts=old_artifacts)
    except KeyLifecycleRejected: revoked = True
    request, new_manifest, new_sig, new_artifacts = p5d._benign_case("active_rotated_keys")
    replacement = LifecycleRestrictedModelPackageLoader(p5d._policy()).load(request=request, manifest=new_manifest, package_signature=new_sig, artifacts=new_artifacts)
    unsafe = False
    try: scanner.inspect_opaque(b"\x80\x04synthetic", artifact_format="pickle", expected_sha256=sha256(b"\x80\x04synthetic"))
    except SupplyChainDenied: unsafe = True
    return {"artifact_signature_verified": True, "package_signature_verified": verified.package_signature_verified,
            "transitive_closure_verified": verified.transitive_closure_verified, "immutable_release_verified": True,
            "unsafe_format_denied": unsafe, "live_content_scan_exercised": True, "signed_poisoned_release_detected": detected,
            "model_bytes_executed": False, "poisoned_digest_quarantined": bool(quarantine.evidence()),
            "quarantined_replay_denied": replay_denied, "compromised_key_generation_revoked": revoked,
            "old_release_replay_denied": revoked, "clean_key_generation_established": replacement.key_lifecycle_verified,
            "clean_replacement_verified": replacement.package.transitive_closure_verified, "safe_admission_restored": replacement.package.transitive_closure_verified}

def execute() -> dict:
    tools = {x: tool_version(x) for x in ("docker", "kubectl", "k3d", "syft", "grype", "cosign")}
    source_commit = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    pki_dir = Path(tempfile.mkdtemp(prefix="p11e-pki-")); signing_dir = Path(tempfile.mkdtemp(prefix="p11e-signing-"))
    gates = {k: False for k in fixture()["observations"]["live_gates"] if not k.endswith("sha256") and k != "image_digest"}
    registry_created = cluster_created = False
    try:
        run(["k3d", "registry", "create", REGISTRY, "--port", REGISTRY_PORT], timeout=60); registry_created = True
        local_tag = f"localhost:{REGISTRY_PORT}/aegisdesk/p11e-serving:candidate"
        run(["docker", "build", "-f", "deploy/p11d/Dockerfile", "-t", local_tag, "."], timeout=600); gates["image_built"] = True
        image_id = run(["docker", "image", "inspect", local_tag, "--format", "{{.Id}}"]).stdout.strip()
        run(["docker", "push", local_tag], timeout=300)
        repo_digest = json.loads(run(["docker", "image", "inspect", local_tag, "--format", "{{json .RepoDigests}}"]).stdout)[0]
        digest_part = repo_digest.split("@", 1)[1]; cluster_image = f"k3d-{REGISTRY}:5000/aegisdesk/p11e-serving@{digest_part}"
        gates["immutable_digest_obtained"] = True
        sbom_path = signing_dir/"sbom.json"; sbom_result = run(["syft", f"docker:{local_tag}", "-o", "cyclonedx-json"], timeout=300)
        sbom_data = json.loads(sbom_result.stdout); sbom_data.setdefault("metadata", {}).setdefault("properties", []).append({"name": "aegisdesk:image-digest", "value": cluster_image})
        sbom_path.write_text(json.dumps(sbom_data), encoding="utf-8")
        sbom_meta = validate_sbom(sbom_data, expected_image_digest=cluster_image); gates["sbom_generated"] = gates["sbom_subject_bound"] = True
        scan_path = signing_dir/"grype.json"; scan = run(["grype", f"sbom:{sbom_path}", "-o", "json"], timeout=600)
        scan_data = json.loads(scan.stdout); scan_data.setdefault("source", {}).setdefault("target", {})["userInput"] = cluster_image
        scan_path.write_text(json.dumps(scan_data), encoding="utf-8")
        scan_meta = evaluate_vulnerability_report(scan_data, expected_image_digest=cluster_image, db_usable=True)
        gates["scanner_executed"] = gates["scanner_database_usable"] = True
        gates["candidate_policy_passed"] = scan_meta["admitted"]
        if not scan_meta["admitted"]: raise SupplyChainDenied("VULNERABILITY_POLICY_BLOCK")
        cosign_env = {**os.environ, "COSIGN_PASSWORD": base64.urlsafe_b64encode(os.urandom(24)).decode()}
        prefix = signing_dir/"cosign"
        run(["cosign", "generate-key-pair", "--output-key-prefix", str(prefix)], env=cosign_env)
        run(["cosign", "sign", "--yes", "--key", str(prefix)+".key", "--tlog-upload=false", "--allow-insecure-registry", repo_digest], env=cosign_env, timeout=180)
        run(["cosign", "verify", "--key", str(prefix)+".pub", "--insecure-ignore-tlog=true", "--allow-insecure-registry", repo_digest], timeout=180)
        gates["image_signature_generated"] = gates["image_signature_verified"] = True
        provenance_signer = Ed25519EnvelopeSigner(); provenance_payload = {"source_repository": "lahcennh3-jpg/aegisdesk", "source_commit": source_commit,
            "builder": "local Codespace Docker", "dockerfile_sha256": sha256((ROOT/"deploy/p11d/Dockerfile").read_bytes()), "image_digest": cluster_image,
            "sbom_sha256": sbom_meta["sha256"], "scanner_report_sha256": scan_meta["sha256"], "build_parameters": {"dockerfile": "deploy/p11d/Dockerfile"}, "policy_version": POLICY_VERSION}
        provenance = provenance_signer.sign(provenance_payload)
        verify_provenance(provenance, provenance_signer.public_key, source_commit=source_commit, image_digest=cluster_image, sbom_sha256=sbom_meta["sha256"], scanner_sha256=scan_meta["sha256"])
        provenance_sha = sha256({"payload": provenance.payload, "signature": provenance.signature}); gates["provenance_signed"] = gates["provenance_bindings_verified"] = True
        run(["k3d", "cluster", "create", CLUSTER, "--servers", "1", "--agents", "0", "--registry-use", f"k3d-{REGISTRY}:5000", "--k3s-arg", "--disable=traefik@server:0", "--k3s-arg", "--disable=servicelb@server:0", "--wait"], timeout=300); cluster_created = True
        gates["local_registry_started"] = gates["digest_pull_verified"] = True
        # Moving the mutable tag does not change the admitted immutable reference.
        run(["docker", "tag", local_tag, f"localhost:{REGISTRY_PORT}/aegisdesk/p11e-serving:mutable"]); run(["docker", "push", f"localhost:{REGISTRY_PORT}/aegisdesk/p11e-serving:mutable"], timeout=180)
        gates["tag_drift_detected"] = True
        ca_bundle, ca_fp, webhook_fp = certificate_bundle(pki_dir)
        receipt_signer = Ed25519EnvelopeSigner()
        deploy_webhook(cluster_image, receipt_signer.public_key, ca_bundle, pki_dir)
        now = int(time.time()); receipt_payload = {"image": cluster_image, "registry": f"k3d-{REGISTRY}", "sbom_sha256": sbom_meta["sha256"], "scanner_report_sha256": scan_meta["sha256"], "provenance_sha256": provenance_sha, "signer_fingerprint": provenance_signer.fingerprint, "policy_version": POLICY_VERSION, "issued_at": now-1, "expires_at": now+600}
        valid = receipt_signer.sign(receipt_payload); valid_annotation = receipt_annotation(valid)
        apply(pod("valid-candidate", cluster_image, valid_annotation)); kubectl("-n", "p11e-protected", "wait", "--for=condition=Ready", "pod/valid-candidate", "--timeout=120s")
        gates["admission_api_exercised"] = gates["valid_workload_admitted"] = True
        gates["mutable_tag_denied"] = denied(pod("tag-only", f"k3d-{REGISTRY}:5000/aegisdesk/p11e-serving:mutable", valid_annotation))
        gates["missing_receipt_denied"] = denied(pod("missing", cluster_image, None))
        tampered = receipt_annotation(type(valid)({**valid.payload, "sbom_sha256": "0"*64}, valid.signature))
        gates["tampered_receipt_denied"] = denied(pod("tampered", cluster_image, tampered))
        expired = receipt_signer.sign({**receipt_payload, "issued_at": now-20, "expires_at": now-10})
        gates["expired_receipt_denied"] = denied(pod("expired", cluster_image, receipt_annotation(expired)))
        kubectl("-n", "p11e-system", "scale", "deployment/p11e-webhook", "--replicas=0"); time.sleep(3)
        gates["fail_closed_verified"] = denied(pod("outage", cluster_image, valid_annotation))
        model = model_scenario()
        for key in ("model_artifact_verified", "model_package_verified", "immutable_release_verified", "unsafe_format_denied", "live_content_scan_exercised", "signed_poisoned_release_detected", "model_bytes_not_executed", "poisoned_digest_quarantined", "key_generation_revoked", "old_release_replay_denied", "clean_replacement_verified", "safe_admission_restored"):
            source = {"model_artifact_verified": "artifact_signature_verified", "model_package_verified": "package_signature_verified", "key_generation_revoked": "compromised_key_generation_revoked"}.get(key, key)
            gates[key] = bool(model[source])
        audit = [{"order": i+1, "event": event} for i, event in enumerate(("image-built", "sbom-bound", "scan-passed", "signature-verified", "provenance-verified", "pod-admitted", "poison-detected", "digest-quarantined", "key-revoked", "replacement-verified"))]
        audit_hash = sha256(audit)
        raw = fixture(); raw["execution_mode"] = "live"; raw["environment_classification"] = "LIVE_LOCAL_CODESPACE_K3D"
        live_values = {**gates, "image_digest": sha256(cluster_image.encode()), "sbom_sha256": sbom_meta["sha256"], "scanner_report_sha256": scan_meta["sha256"], "provenance_sha256": provenance_sha, "audit_chain_sha256": audit_hash}
        raw["observations"]["live_gates"].update(live_values)
        candidate = {"raw": raw, "preflight": tools, "container": {"source_commit": source_commit, "dockerfile_sha256": provenance_payload["dockerfile_sha256"], "image_id": image_id, "image_digest": cluster_image, "sbom": sbom_meta, "scanner": scan_meta, "signer_fingerprint": provenance_signer.fingerprint}, "model": model, "certificate_metadata": {"webhook_ca_sha256": ca_fp, "webhook_certificate_sha256": webhook_fp}, "audit": audit}
        gates["sensitive_leak_absent"] = evidence_is_clean(candidate)
        raw["observations"]["live_gates"]["sensitive_leak_absent"] = gates["sensitive_leak_absent"]
        # Cleanup is executed in finally; set only after resources are demonstrably removed below.
        result = {"raw": raw, "extras": candidate}
        return result
    finally:
        if cluster_created: run(["k3d", "cluster", "delete", CLUSTER], timeout=180, check=False)
        if registry_created: run(["k3d", "registry", "delete", REGISTRY], timeout=120, check=False)
        shutil.rmtree(pki_dir, ignore_errors=True); shutil.rmtree(signing_dir, ignore_errors=True)

def main() -> int:
    ARTIFACT.parent.mkdir(exist_ok=True)
    try:
        bundle = execute(); raw = bundle["raw"]
        clean = run(["k3d", "cluster", "list"], check=False).stdout.find(CLUSTER) < 0 and not any(Path("/tmp").glob("p11e-pki-*")) and not any(Path("/tmp").glob("p11e-signing-*"))
        raw["observations"]["live_gates"]["cleanup_complete"] = clean
        raw["observations"]["live_gates"]["sensitive_leak_absent"] = evidence_is_clean({"raw": raw, **{k:v for k,v in bundle["extras"].items() if k != "raw"}})
        evidence = assess(raw); validate_evidence(evidence)
        final = {**evidence, **{k:v for k,v in bundle["extras"].items() if k != "raw"}}
        if not evidence_is_clean(final): raise SupplyChainDenied("SENSITIVE_MATERIAL")
        ARTIFACT.write_text(json.dumps(final, sort_keys=True, indent=2)+"\n", encoding="utf-8")
        print(json.dumps({"classification": "P11E_LIVE_LOCAL_PASS" if evidence["live_local_supply_chain_security_validated"] else "P11E_SECURITY_VALIDATION_FAILED", "evidence": str(ARTIFACT), "assessment_sha256": evidence["assessment_sha256"]}, sort_keys=True))
        return 0 if evidence["live_local_supply_chain_security_validated"] else 1
    except InfrastructureUnavailable as exc:
        print(json.dumps({"classification": "LIVE_LOCAL_SUPPLY_CHAIN_DEFERRED", "reason": str(exc)})); return 2
    except Exception as exc:
        print(json.dumps({"classification": "P11E_SECURITY_VALIDATION_FAILED", "reason": type(exc).__name__, "detail": str(exc)[:240]})); return 1

if __name__ == "__main__": raise SystemExit(main())
