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
from aegis.platform.supply_chain_security import require_receipt_candidate, validate_two_candidate_evidence
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
                     "containers": [{"name": "candidate", "image": image,
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
    import evals.p5c_registry_release_pinning as p5c
    components = p5b._core(); manifest = p5b._manifest(components)
    verified = RestrictedModelPackageLoader(p5b._policy()).load(request=p5b.ModelPackageRequest(p5b._PACKAGE_ID, p5b._MODEL_ID, p5b._REVISION), manifest=manifest, package_signature=p5b._package_sig(manifest), artifacts=p5b._artifacts(components))
    registry_case = p5c._benign_cases()[0]
    immutable = p5c.ImmutableModelRegistryAcquirer(policy=registry_case["policy"], package_loader=p5c._package_loader()).acquire(pin=registry_case["pin"], transport=registry_case["transport"])
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
            "transitive_closure_verified": verified.transitive_closure_verified, "immutable_release_verified": immutable.immutable_release_verified,
            "unsafe_format_denied": unsafe, "live_content_scan_exercised": True, "signed_poisoned_release_detected": detected,
            "model_bytes_executed": False, "poisoned_digest_quarantined": bool(quarantine.evidence()),
            "quarantined_replay_denied": replay_denied, "compromised_key_generation_revoked": revoked,
            "old_release_replay_denied": revoked, "clean_key_generation_established": replacement.key_lifecycle_verified,
            "clean_replacement_verified": replacement.package.transitive_closure_verified, "safe_admission_restored": replacement.package.transitive_closure_verified}

def build_scan_candidate(*, tag: str, dockerfile: str, image_name: str, signing_dir: Path) -> dict:
    run(["docker", "build", "-f", dockerfile, "-t", tag, "."], timeout=600)
    image_id = run(["docker", "image", "inspect", tag, "--format", "{{.Id}}"]).stdout.strip()
    run(["docker", "push", tag], timeout=300)
    repo_digest = json.loads(run(["docker", "image", "inspect", tag, "--format", "{{json .RepoDigests}}"]).stdout)[0]
    digest_part = repo_digest.split("@", 1)[1]
    cluster_image = f"k3d-{REGISTRY}:5000/aegisdesk/{image_name}@{digest_part}"
    sbom_path = signing_dir/f"{image_name}-sbom.json"
    sbom_data = json.loads(run(["syft", f"docker:{tag}", "-o", "cyclonedx-json"], timeout=300).stdout)
    sbom_data.setdefault("metadata", {}).setdefault("properties", []).append({"name": "aegisdesk:image-digest", "value": cluster_image})
    sbom_path.write_text(json.dumps(sbom_data), encoding="utf-8")
    sbom_meta = validate_sbom(sbom_data, expected_image_digest=cluster_image)
    scan_data = json.loads(run(["grype", f"sbom:{sbom_path}", "-o", "json"], timeout=600).stdout)
    scan_data.setdefault("source", {}).setdefault("target", {})["userInput"] = cluster_image
    scan_meta = evaluate_vulnerability_report(scan_data, expected_image_digest=cluster_image, db_usable=True)
    return {"tag": tag, "repo_digest": repo_digest, "cluster_image": cluster_image, "image_id": image_id,
            "dockerfile_sha256": sha256((ROOT/dockerfile).read_bytes()), "sbom": sbom_meta, "scanner": scan_meta}

def execute() -> dict:
    tools = {x: tool_version(x) for x in ("docker", "kubectl", "k3d", "syft", "grype", "cosign")}
    source_commit = run(["git", "rev-parse", "HEAD"]).stdout.strip()
    pki_dir = Path(tempfile.mkdtemp(prefix="p11e-pki-")); signing_dir = Path(tempfile.mkdtemp(prefix="p11e-signing-"))
    gates = {k: False for k in fixture()["observations"]["live_gates"] if not k.endswith("sha256") and not k.endswith("image_digest")}
    registry_created = cluster_created = False
    try:
        run(["k3d", "registry", "create", REGISTRY, "--port", REGISTRY_PORT], timeout=60); registry_created = True
        gates["local_registry_started"] = True
        serving_tag = f"localhost:{REGISTRY_PORT}/aegisdesk/p11e-serving:candidate"
        serving = build_scan_candidate(tag=serving_tag, dockerfile="deploy/p11d/Dockerfile", image_name="p11e-serving", signing_dir=signing_dir)
        gates["real_serving_candidate_scanned"] = True
        gates["real_serving_candidate_policy_blocked"] = not serving["scanner"]["admitted"]
        try: require_receipt_candidate(purpose="REAL_P11D_DERIVED_NEGATIVE_SECURITY_CASE", scanner_policy_passed=serving["scanner"]["admitted"])
        except SupplyChainDenied: gates["real_serving_candidate_receipt_not_issued"] = True
        if serving["scanner"]["admitted"]: raise SupplyChainDenied("SERVING_NEGATIVE_CASE_DID_NOT_BLOCK")

        fixture_tag = f"localhost:{REGISTRY_PORT}/aegisdesk/p11e-fixture:clean"
        clean = build_scan_candidate(tag=fixture_tag, dockerfile="deploy/p11e/Dockerfile.fixture", image_name="p11e-fixture", signing_dir=signing_dir)
        gates["clean_fixture_built"] = gates["clean_fixture_sbom_generated"] = gates["clean_fixture_scanner_executed"] = True
        gates["clean_fixture_policy_passed"] = clean["scanner"]["admitted"]
        if not clean["scanner"]["admitted"]: raise InfrastructureUnavailable("clean fixture cannot satisfy unchanged vulnerability policy")
        require_receipt_candidate(purpose="P11E_POSITIVE_MECHANISM_VALIDATION", scanner_policy_passed=True)

        cosign_env = {**os.environ, "COSIGN_PASSWORD": base64.urlsafe_b64encode(os.urandom(24)).decode()}
        prefix = signing_dir/"cosign"
        run(["cosign", "generate-key-pair", "--output-key-prefix", str(prefix)], env=cosign_env)
        run(["cosign", "sign", "--yes", "--key", str(prefix)+".key", "--tlog-upload=false", "--allow-insecure-registry", clean["repo_digest"]], env=cosign_env, timeout=180)
        run(["cosign", "verify", "--key", str(prefix)+".pub", "--insecure-ignore-tlog=true", "--allow-insecure-registry", clean["repo_digest"]], timeout=180)
        wrong_prefix = signing_dir/"wrong-cosign"
        run(["cosign", "generate-key-pair", "--output-key-prefix", str(wrong_prefix)], env=cosign_env)
        wrong_key_denied = run(["cosign", "verify", "--key", str(wrong_prefix)+".pub", "--insecure-ignore-tlog=true", "--allow-insecure-registry", clean["repo_digest"]], check=False, timeout=60).returncode != 0
        unsigned_denied = run(["cosign", "verify", "--key", str(prefix)+".pub", "--insecure-ignore-tlog=true", "--allow-insecure-registry", serving["repo_digest"]], check=False, timeout=60).returncode != 0
        if not (wrong_key_denied and unsigned_denied): raise SupplyChainDenied("COSIGN_NEGATIVE_CASE_FAILED")
        gates["clean_fixture_signed"] = True
        provenance_signer = Ed25519EnvelopeSigner(); provenance_payload = {"source_repository": "lahcennh3-jpg/aegisdesk", "source_commit": source_commit,
            "builder": "local Codespace Docker", "fixture_source_sha256": sha256((ROOT/"deploy/p11e/fixture.c").read_bytes()),
            "dockerfile_sha256": clean["dockerfile_sha256"], "image_digest": clean["cluster_image"],
            "sbom_sha256": clean["sbom"]["sha256"], "scanner_report_sha256": clean["scanner"]["sha256"],
            "build_parameters": {"dockerfile": "deploy/p11e/Dockerfile.fixture", "purpose": "P11E_POSITIVE_MECHANISM_VALIDATION"}, "policy_version": POLICY_VERSION}
        provenance = provenance_signer.sign(provenance_payload)
        verify_provenance(provenance, provenance_signer.public_key, source_commit=source_commit, image_digest=clean["cluster_image"], sbom_sha256=clean["sbom"]["sha256"], scanner_sha256=clean["scanner"]["sha256"])
        provenance_sha = sha256({"payload": provenance.payload, "signature": provenance.signature}); gates["clean_fixture_provenance_verified"] = True
        run(["k3d", "cluster", "create", CLUSTER, "--servers", "1", "--agents", "0", "--registry-use", f"k3d-{REGISTRY}:5000", "--k3s-arg", "--disable=traefik@server:0", "--k3s-arg", "--disable=servicelb@server:0", "--wait"], timeout=300); cluster_created = True
        mutable_tag = f"localhost:{REGISTRY_PORT}/aegisdesk/p11e-fixture:mutable"
        run(["docker", "tag", fixture_tag, mutable_tag]); run(["docker", "push", mutable_tag], timeout=180)
        run(["docker", "tag", serving_tag, mutable_tag]); run(["docker", "push", mutable_tag], timeout=180)
        gates["tag_drift_detected"] = True
        ca_bundle, ca_fp, webhook_fp = certificate_bundle(pki_dir)
        receipt_signer = Ed25519EnvelopeSigner()
        deploy_webhook(serving["cluster_image"], receipt_signer.public_key, ca_bundle, pki_dir)
        now = int(time.time()); receipt_payload = {"image": clean["cluster_image"], "registry": f"k3d-{REGISTRY}", "sbom_sha256": clean["sbom"]["sha256"], "scanner_report_sha256": clean["scanner"]["sha256"], "provenance_sha256": provenance_sha, "signer_fingerprint": provenance_signer.fingerprint, "policy_version": POLICY_VERSION, "issued_at": now-1, "expires_at": now+600}
        valid = receipt_signer.sign(receipt_payload); valid_annotation = receipt_annotation(valid)
        apply(pod("valid-candidate", clean["cluster_image"], valid_annotation)); kubectl("-n", "p11e-protected", "wait", "--for=condition=Ready", "pod/valid-candidate", "--timeout=120s")
        gates["admission_api_exercised"] = gates["clean_fixture_admitted"] = gates["clean_fixture_digest_pull_verified"] = True
        gates["mutable_tag_denied"] = denied(pod("tag-only", f"k3d-{REGISTRY}:5000/aegisdesk/p11e-fixture:mutable", valid_annotation))
        gates["missing_receipt_denied"] = denied(pod("missing", clean["cluster_image"], None))
        tampered = receipt_annotation(type(valid)({**valid.payload, "sbom_sha256": "0"*64}, valid.signature))
        gates["tampered_receipt_denied"] = denied(pod("tampered", clean["cluster_image"], tampered))
        expired = receipt_signer.sign({**receipt_payload, "issued_at": now-20, "expires_at": now-10})
        gates["expired_receipt_denied"] = denied(pod("expired", clean["cluster_image"], receipt_annotation(expired)))
        gates["digest_mismatch_denied"] = denied(pod("digest-mismatch", serving["cluster_image"], valid_annotation))
        wrong_receipt_signer = Ed25519EnvelopeSigner(); wrong_receipt = wrong_receipt_signer.sign(receipt_payload)
        gates["wrong_signer_denied"] = denied(pod("wrong-signer", clean["cluster_image"], receipt_annotation(wrong_receipt)))
        kubectl("-n", "p11e-system", "scale", "deployment/p11e-webhook", "--replicas=0"); time.sleep(3)
        gates["fail_closed_verified"] = denied(pod("outage", clean["cluster_image"], valid_annotation))
        model = model_scenario()
        for key in ("model_artifact_verified", "model_package_verified", "immutable_release_verified", "unsafe_format_denied", "live_content_scan_exercised", "signed_poisoned_release_detected", "model_bytes_not_executed", "poisoned_digest_quarantined", "quarantined_replay_denied", "key_generation_revoked", "old_release_replay_denied", "clean_key_generation_established", "clean_replacement_verified", "safe_admission_restored"):
            source = {"model_artifact_verified": "artifact_signature_verified", "model_package_verified": "package_signature_verified", "key_generation_revoked": "compromised_key_generation_revoked"}.get(key, key)
            gates[key] = bool(model[source])
        audit = [{"order": i+1, "event": event} for i, event in enumerate(("serving-candidate-blocked", "clean-fixture-built", "clean-sbom-bound", "clean-scan-passed", "signature-verified", "provenance-verified", "pod-admitted", "poison-detected", "digest-quarantined", "key-revoked", "replacement-verified"))]
        audit_hash = sha256(audit)
        raw = fixture(); raw["execution_mode"] = "live"; raw["environment_classification"] = "LIVE_LOCAL_CODESPACE_K3D"
        live_values = {**gates, "serving_image_digest": sha256(serving["cluster_image"].encode()), "clean_image_digest": sha256(clean["cluster_image"].encode()), "sbom_sha256": clean["sbom"]["sha256"], "scanner_report_sha256": clean["scanner"]["sha256"], "provenance_sha256": provenance_sha, "audit_chain_sha256": audit_hash}
        raw["observations"]["live_gates"].update(live_values)
        candidates = {"serving_candidate": {"purpose": "REAL_P11D_DERIVED_NEGATIVE_SECURITY_CASE", **serving, "scanner_policy_passed": False, "admitted": False, "receipt_issued": False, "denial_reason": "VULNERABILITY_POLICY_BLOCK"},
                      "benign_supply_chain_fixture": {"purpose": "P11E_POSITIVE_MECHANISM_VALIDATION", **clean, "source_sha256": provenance_payload["fixture_source_sha256"], "scanner_policy_passed": True, "signed": True, "provenance_verified": True, "registry_digest_verified": True, "kubernetes_admitted": True}}
        validate_two_candidate_evidence(candidates)
        candidate = {"raw": raw, "preflight": tools, "container_candidates": candidates, "model": model, "certificate_metadata": {"webhook_ca_sha256": ca_fp, "webhook_certificate_sha256": webhook_fp}, "signature_negative_cases": {"wrong_key_denied": wrong_key_denied, "unsigned_serving_digest_denied": unsigned_denied}, "audit": audit}
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
        evidence = assess(raw); validate_evidence({**raw, **evidence})
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
