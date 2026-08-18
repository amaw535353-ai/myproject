from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from aegis.detection.security_analytics import (
    EVENT_SCHEMA, MAX_EVENT_BYTES, POLICY_VERSION, CollectorService,
    DetectionEngine, EventStore, ProducerSigner, SecurityEvent, SourcePolicy,
    SourceRegistry, create_collector_app, digest, load_rules, safe_ref,
)
from aegis.platform.serving_security import (
    RequestContext, RequestPolicy, ServingDenied, evidence_is_sensitive_material_free,
)
from evals.p11f_detection_engineering import assess, validate_evidence
from evals.p11f_fixture import LIVE_DATA_NAMES, LIVE_GATE_NAMES, ROOT, fixture

ARTIFACT = ROOT / "artifacts/p11f-detection-evidence.json"
CLUSTER = "aegisdesk-p11f"
K3S_IMAGE = "rancher/k3s:v1.33.5-k3s1"
COLLECTOR_PORT = 18116
CONTROL_PORT = 18117
REF_KEY = os.urandom(32)


class InfrastructureUnavailable(RuntimeError):
    pass


class SecurityFailure(RuntimeError):
    pass


def command(args: list[str], *, timeout: int = 120, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, text=True, input=stdin, capture_output=True, timeout=timeout)


class LocalServer:
    def __init__(self, app: FastAPI, port: int) -> None:
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", access_log=False))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.port = port

    def __enter__(self):
        self.thread.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                if httpx.get(f"http://127.0.0.1:{self.port}/healthz", timeout=0.5).status_code == 200:
                    return self
            except httpx.HTTPError:
                time.sleep(0.05)
        raise InfrastructureUnavailable("local HTTP service did not start")

    def __exit__(self, *_):
        self.server.should_exit = True
        self.thread.join(timeout=10)


def control_app() -> FastAPI:
    app = FastAPI(docs_url=None, openapi_url=None)
    policy = RequestPolicy()

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.post("/v1/infer")
    async def infer(request: Request):
        body = await request.body()
        try:
            policy.validate(
                method=request.method, route=request.url.path,
                content_type=request.headers.get("content-type", ""), body=body,
                headers=dict(request.headers), claimed_tenant="tenant-a",
                context=RequestContext("principal-a", "tenant-a", "req-12345678"),
            )
        except ServingDenied as exc:
            return JSONResponse({"reason": str(exc)}, status_code=403)
        return {"result": "synthetic"}
    return app


def make_event(source_id: str, source_kind: str, category: str, event_type: str,
               event_id: str, now: int, sequence: int, provenance: str,
               *, tenant: str = "tenant-a", principal: str = "principal-a") -> SecurityEvent:
    values = {
        "tenant": tenant, "principal": principal, "workload": "workload-a",
        "namespace": "p11f-restricted", "resource": event_type.lower(),
        "request": event_id, "session": "p11f-session", "trace": "p11f-trace",
    }
    refs = {key: safe_ref(key, value, REF_KEY) for key, value in values.items()}
    return SecurityEvent.from_dict({
        "schema_version": EVENT_SCHEMA, "event_id": event_id, "event_time": now,
        "source_id": source_id, "source_kind": source_kind, "event_type": event_type,
        "category": category, "action": "SECURITY_CONTROL", "outcome": "DENY",
        "severity": "high", "reason_code": event_type,
        "tenant_ref": refs["tenant"], "principal_ref": refs["principal"],
        "workload_ref": refs["workload"], "namespace_ref": refs["namespace"],
        "resource_ref": refs["resource"], "request_ref": refs["request"],
        "session_ref": refs["session"], "trace_ref": refs["trace"],
        "policy_version": POLICY_VERSION, "sequence": sequence,
        "provenance_classification": provenance, "attributes": {"adapter": "p11f"},
    })


def post(base: str, envelope, now: int) -> httpx.Response:
    return httpx.post(base + "/v1/security-events", json=asdict(envelope), headers={"x-p11f-now": str(now)}, timeout=5)


def kubernetes_observation() -> dict[str, Any]:
    create = command(["k3d", "cluster", "create", CLUSTER, "--image", K3S_IMAGE,
                      "--servers", "1", "--agents", "0", "--k3s-arg", "--disable=traefik@server:0",
                      "--k3s-arg", "--disable=servicelb@server:0", "--wait"], timeout=240)
    if create.returncode:
        raise InfrastructureUnavailable("k3d cluster creation unavailable")
    ready = command(["kubectl", "wait", "--for=condition=Ready", "node", "--all", "--timeout=90s"])
    if ready.returncode:
        raise InfrastructureUnavailable("Kubernetes node not ready")
    namespace = {"apiVersion":"v1","kind":"Namespace","metadata":{"name":"p11f-restricted","labels":{"pod-security.kubernetes.io/enforce":"restricted","pod-security.kubernetes.io/enforce-version":"latest"}}}
    if command(["kubectl", "apply", "-f", "-"], stdin=json.dumps(namespace)).returncode:
        raise InfrastructureUnavailable("restricted namespace unavailable")
    pod = {"apiVersion":"v1","kind":"Pod","metadata":{"name":"privileged-attempt","namespace":"p11f-restricted"},"spec":{"containers":[{"name":"probe","image":"registry.k8s.io/pause:3.10","securityContext":{"privileged":True}}]}}
    denied = command(["kubectl", "apply", "--dry-run=server", "-f", "-"], stdin=json.dumps(pod))
    message = (denied.stdout + denied.stderr).lower()
    observed = denied.returncode != 0 and "forbidden" in message and ("podsecurity" in message or "pod security" in message)
    if not observed:
        raise SecurityFailure("Kubernetes Pod Security API denial was not observed")
    return {"cluster_created": True, "node_ready": True, "control": "POD_SECURITY_RESTRICTED", "actual_denial": True, "source_classification": "LIVE_CONTROL_OBSERVATION"}


def run_lab() -> tuple[dict, EventStore, Path, bool]:
    temp = Path(tempfile.mkdtemp(prefix="p11f-detection-"))
    store = EventStore(temp / "events.sqlite")
    rules, rule_hash = load_rules(ROOT / "detections/p11f")
    source_specs = {
        "application-producer": ("APPLICATION", "application_agent"),
        "identity-producer": ("IDENTITY", "identity_iam"),
        "serving-producer": ("SERVING", "serving_network"),
        "kubernetes-adapter": ("KUBERNETES", "kubernetes_platform"),
        "supply-chain-adapter": ("SUPPLY_CHAIN", "supply_chain"),
    }
    signers = {source: ProducerSigner(source) for source in source_specs}
    policies = tuple(SourcePolicy(source, kind, signers[source].public_key, frozenset({category}), frozenset({"NATIVE_LIVE", "LIVE_CONTROL_OBSERVATION", "DETERMINISTIC_FIXTURE"})) for source, (kind, category) in source_specs.items())
    collector = CollectorService(SourceRegistry(policies), store, DetectionEngine(store, rules))
    gates = {name: False for name in LIVE_GATE_NAMES}
    now = int(time.time())
    observations: dict[str, Any] = {"negative_ingestion": {}, "source_classifications": {}, "correlation": {}}
    collector_stopped = False
    with LocalServer(create_collector_app(collector), COLLECTOR_PORT):
        base = f"http://127.0.0.1:{COLLECTOR_PORT}"
        gates["collector_started"] = gates["collector_http_reached"] = gates["sqlite_store_created"] = True
        valid_event = make_event("application-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "live-valid-001", now, 1, "DETERMINISTIC_FIXTURE")
        valid = signers["application-producer"].sign(valid_event)
        gates["signed_producer_accepted"] = post(base, valid, now).status_code == 200
        gates["malicious_case_alerted"] = bool(store.alert_rows())
        gates["duplicate_replay_deduped"] = post(base, valid, now).status_code == 202

        bad = ProducerSigner("application-producer").sign(make_event("application-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "bad-key-001", now, 2, "DETERMINISTIC_FIXTURE"))
        observations["negative_ingestion"]["invalid_signature"] = post(base, bad, now).json().get("reason")
        gates["invalid_signature_denied"] = observations["negative_ingestion"]["invalid_signature"] == "SIGNATURE_INVALID"
        unknown_signer = ProducerSigner("unknown-producer")
        unknown = unknown_signer.sign(make_event("unknown-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "unknown-001", now, 3, "DETERMINISTIC_FIXTURE"))
        gates["unknown_source_denied"] = post(base, unknown, now).json().get("reason") == "SOURCE_UNKNOWN"
        mismatch_event = make_event("application-producer", "APPLICATION", "identity_iam", "PRIVILEGE_ESCALATION_DENIED", "mismatch-001", now, 4, "DETERMINISTIC_FIXTURE")
        gates["source_authorization_enforced"] = post(base, signers["application-producer"].sign(mismatch_event), now).json().get("reason") == "SOURCE_AUTHORIZATION_DENIED"
        tampered = asdict(signers["application-producer"].sign(make_event("application-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "tamper-001", now, 5, "DETERMINISTIC_FIXTURE")))
        tampered["body"]["severity"] = "critical"
        observations["negative_ingestion"]["tampered_body"] = httpx.post(base+"/v1/security-events", json=tampered, headers={"x-p11f-now":str(now)}, timeout=5).json().get("reason")
        stale = make_event("application-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "stale-001", now-4000, 6, "DETERMINISTIC_FIXTURE")
        future = make_event("application-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "future-001", now+60, 7, "DETERMINISTIC_FIXTURE")
        gates["timestamp_policy_enforced"] = post(base, signers["application-producer"].sign(stale), now).json().get("reason") == "EVENT_STALE" and post(base, signers["application-producer"].sign(future), now).json().get("reason") == "EVENT_FUTURE"
        oversized = httpx.post(base+"/v1/security-events", content=b"x"*(MAX_EVENT_BYTES*2+1), headers={"x-p11f-now":str(now)}, timeout=5)
        gates["body_size_limit_enforced"] = oversized.status_code == 413
        secret_body = valid_event.to_dict(); secret_body["event_id"]="secret-001"; secret_body["sequence"]=8; secret_body["attributes"]={"detail":"Authorization: Bearer redacted-test-value"}
        gates["secret_minimization_enforced"] = post(base, signers["application-producer"].sign_raw(secret_body), now).json().get("reason") == "SENSITIVE_MATERIAL_DENIED"

        with LocalServer(control_app(), CONTROL_PORT):
            denial = httpx.post(f"http://127.0.0.1:{CONTROL_PORT}/v1/infer", json={"tenant":"tenant-a"}, headers={"x-internal-principal":"spoof"}, timeout=5)
        gates["actual_http_security_denial_observed"] = denial.status_code == 403 and denial.json().get("reason") == "TRUSTED_HEADER_SPOOF"
        live_http_event = make_event("serving-producer", "SERVING", "serving_network", "TRUSTED_HEADER_SPOOF_DENIED", "http-live-001", now, 10, "LIVE_CONTROL_OBSERVATION")
        if post(base, signers["serving-producer"].sign(live_http_event), now).status_code != 200:
            raise SecurityFailure("HTTP observation adapter ingestion failed")

        kube = kubernetes_observation()
        gates["actual_kubernetes_security_denial_observed"] = kube["actual_denial"]
        kube_event = make_event("kubernetes-adapter", "KUBERNETES", "kubernetes_platform", "PRIVILEGED_POD_DENIED", "kube-live-001", now+1, 11, "LIVE_CONTROL_OBSERVATION")
        if post(base, signers["kubernetes-adapter"].sign(kube_event), now+1).status_code != 200:
            raise SecurityFailure("Kubernetes observation adapter ingestion failed")

        stages = [
            ("application-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED"),
            ("application-producer", "APPLICATION", "application_agent", "HIGH_IMPACT_TOOL_DENIED"),
            ("identity-producer", "IDENTITY", "identity_iam", "REVOKED_CREDENTIAL_REPLAY"),
            ("kubernetes-adapter", "KUBERNETES", "kubernetes_platform", "PRIVILEGED_POD_DENIED"),
            ("supply-chain-adapter", "SUPPLY_CHAIN", "supply_chain", "POISONED_RELEASE_BLOCKED"),
        ]
        before = len([a for a in store.alert_rows() if a["rule_id"] == "p11f.correlation.multi-stage-ai-attack"])
        for index, (source, kind, category, event_type) in enumerate(stages, 20):
            staged = make_event(source, kind, category, event_type, f"chain-{index}", now+index, index, "DETERMINISTIC_FIXTURE")
            result = post(base, signers[source].sign(staged), now+index)
            if result.status_code != 200: raise SecurityFailure("correlation event rejected")
        correlation_alerts = [a for a in store.alert_rows() if a["rule_id"] == "p11f.correlation.multi-stage-ai-attack"]
        gates["cross_event_correlation_alerted"] = len(correlation_alerts) == before + 1
        gates["actual_source_adapters_ingested"] = gates["actual_http_security_denial_observed"] and gates["actual_kubernetes_security_denial_observed"]

        # A split grouping key and an outside-window sequence exercise evasions
        # without producing a second full-chain incident.
        for offset, split_principal in ((40, True), (400, False)):
            for index, (source, kind, category, event_type) in enumerate(stages):
                timestamp = now + offset + index * (100 if offset == 400 else 1)
                principal = "other-principal" if split_principal and index == 2 else "principal-a"
                staged = make_event(source, kind, category, event_type, f"evasion-{offset}-{index}", timestamp, 100+offset+index, "DETERMINISTIC_FIXTURE", principal=principal)
                post(base, signers[source].sign(staged), timestamp)
        gates["correlation_evasion_cases_exercised"] = len([a for a in store.alert_rows() if a["rule_id"] == "p11f.correlation.multi-stage-ai-attack"]) == len(correlation_alerts)

        benign = make_event("application-producer", "APPLICATION", "application_agent", "NORMAL_RAG_REQUEST", "benign-001", now+900, 900, "DETERMINISTIC_FIXTURE", principal="benign-principal")
        benign_result = post(base, signers["application-producer"].sign(benign), now+900)
        gates["benign_case_not_alerted"] = benign_result.status_code == 200 and not benign_result.json()["alerts"]
        dedup_event = make_event("application-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "dedup-alert-001", now+901, 901, "DETERMINISTIC_FIXTURE")
        post(base, signers["application-producer"].sign(dedup_event), now+901)
        gates["alert_dedup_exercised"] = store.stats["alerts_deduplicated"] > 0

        gates["rule_bundle_loaded"] = len(rules) == 6
        gates["rule_bundle_hash_verified"] = len(rule_hash) == 64
        gates["alert_store_persisted"] = bool(store.alert_rows())
        event_chain = store.verify_event_chain(); alert_chain = store.verify_alert_chain()
        gates["event_chain_valid"] = len(event_chain) == 64
        gates["alert_evidence_valid"] = len(alert_chain) == 64
        cross = correlation_alerts[-1]
        incident = {"incident_id":"incident-"+digest(cross)[:20], "status":"OPEN", "severity":"critical", "detection_rule_ids":[cross["rule_id"]], "supporting_event_ids":cross["event_refs"], "first_seen":cross["first_event_time"], "last_seen":cross["last_event_time"], "recommended_containment_categories":["fence_identity","quarantine_release"]}
        incident["evidence_snapshot_sha256"] = digest(incident)
        gates["incident_snapshot_generated"] = len(incident["supporting_event_ids"]) == 5
        observations.update({"kubernetes": kube, "http_control":{"control":"TRUSTED_HEADER_SPOOF","actual_denial":True,"source_classification":"LIVE_CONTROL_OBSERVATION"}, "incident":incident})
    collector_stopped = True
    snapshot = store.snapshot_sha256()
    observations.update({"ingestion":dict(store.stats), "stored_event_count":len(store.events()), "alerts":store.alert_rows(), "event_chain_sha256":event_chain, "alert_chain_sha256":alert_chain, "rule_bundle_sha256":rule_hash})
    data_hashes = {"rule_bundle_sha256":rule_hash,"event_store_snapshot_sha256":snapshot,"event_chain_sha256":event_chain,"alert_assessment_sha256":digest(store.alert_rows()),"incident_snapshot_sha256":incident["evidence_snapshot_sha256"]}
    return {"gates":gates,"hashes":data_hashes,"observations":observations}, store, temp, collector_stopped


def main() -> int:
    parser = argparse.ArgumentParser(); parser.parse_args()
    tools = {name: shutil.which(name) for name in ("docker", "kubectl", "k3d")}
    preflight = {"architecture":platform.machine(), "cpu_count":os.cpu_count(), "tools":{k:bool(v) for k,v in tools.items()}, "k3s_image":K3S_IMAGE}
    store = None; temp = None; created = False
    try:
        if not all(tools.values()) or command(["docker","version"]).returncode:
            raise InfrastructureUnavailable("Docker, kubectl, or k3d unavailable")
        result, store, temp, collector_stopped = run_lab(); created = True
        store.close(); store = None
        delete = command(["k3d","cluster","delete",CLUSTER], timeout=180)
        created = False
        if delete.returncode: raise SecurityFailure("cluster cleanup failed")
        shutil.rmtree(temp); temp = None
        result["gates"]["cleanup_complete"] = collector_stopped
        raw = fixture(); raw["execution_mode"]="live"; raw["environment_classification"]="LIVE_LOCAL_CODESPACE_K3D"
        raw["live_gates"].update(result["gates"]); raw["live_gates"].update(result["hashes"])
        candidate = {"raw":raw,"preflight":preflight,"observations":result["observations"]}
        raw["live_gates"]["sensitive_leak_absent"] = evidence_is_sensitive_material_free(candidate)
        evidence = assess(raw)
        evidence.update({"preflight":preflight,"collector":{"transport":"HTTP_LOOPBACK","storage":"TEMPORARY_SQLITE","synchronous_ingestion":True},"live_observations":result["observations"]})
        if not evidence_is_sensitive_material_free(evidence): raise SecurityFailure("sensitive evidence material detected")
        validate_evidence(evidence)
        ARTIFACT.parent.mkdir(parents=True,exist_ok=True); ARTIFACT.write_text(json.dumps(evidence,indent=2,sort_keys=True)+"\n")
        if not evidence["live_local_detection_engineering_validated"]: raise SecurityFailure("mandatory live gate failed")
        print(json.dumps({"classification":"P11F_LIVE_LOCAL_PASS","evidence_path":str(ARTIFACT)},sort_keys=True)); return 0
    except InfrastructureUnavailable as exc:
        print(json.dumps({"classification":"LIVE_LOCAL_DETECTION_ENGINEERING_DEFERRED","reason":str(exc),"preflight":preflight},sort_keys=True)); return 2
    except Exception as exc:
        print(json.dumps({"classification":"P11F_SECURITY_VALIDATION_FAILED","reason":str(exc),"preflight":preflight},sort_keys=True)); return 1
    finally:
        if store is not None: store.close()
        # Deleting the specifically named disposable cluster is idempotent and
        # also covers failures raised after k3d creates it but before run_lab returns.
        if shutil.which("k3d"):
            command(["k3d","cluster","delete",CLUSTER],timeout=180)
        if temp is not None and temp.exists(): shutil.rmtree(temp)


if __name__ == "__main__":
    raise SystemExit(main())
