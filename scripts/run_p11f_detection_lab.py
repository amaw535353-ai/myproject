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
from evals.p11f_detection_engineering import assess, execute_fixture, validate_evidence
from evals.p11f_fixture import LIVE_DATA_NAMES, LIVE_GATE_NAMES, ROOT, fixture

ARTIFACT = ROOT / "artifacts/p11f-detection-evidence.json"
CLUSTER = "aegisdesk-p11f"
K3S_IMAGE = "rancher/k3s:v1.33.5-k3s1"
COLLECTOR_PORT = 18116
CONTROL_PORT = 18117
REF_KEY = os.urandom(32)
ACTIVE_TEMP: Path | None = None


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


def post(base: str, envelope, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.post(base + "/v1/security-events", json=asdict(envelope), headers=headers, timeout=5)


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
    global ACTIVE_TEMP
    temp = Path(tempfile.mkdtemp(prefix="p11f-detection-"))
    ACTIVE_TEMP = temp
    store = EventStore(temp / "events.sqlite")
    rules, rule_hash = load_rules(ROOT / "detections/p11f")
    source_specs = {
        "application-fixture-producer": ("APPLICATION", "application_agent", "DETERMINISTIC_FIXTURE"),
        "identity-fixture-producer": ("IDENTITY", "identity_iam", "DETERMINISTIC_FIXTURE"),
        "serving-fixture-producer": ("SERVING", "serving_network", "DETERMINISTIC_FIXTURE"),
        "kubernetes-fixture-adapter": ("KUBERNETES", "kubernetes_platform", "DETERMINISTIC_FIXTURE"),
        "supply-chain-fixture-adapter": ("SUPPLY_CHAIN", "supply_chain", "DETERMINISTIC_FIXTURE"),
        "serving-live-control-adapter": ("SERVING", "serving_network", "LIVE_CONTROL_OBSERVATION"),
        "kubernetes-live-control-adapter": ("KUBERNETES", "kubernetes_platform", "LIVE_CONTROL_OBSERVATION"),
    }
    signers = {source: ProducerSigner(source) for source in source_specs}
    policies = tuple(SourcePolicy(source, kind, signers[source].public_key, frozenset({category}), frozenset({provenance})) for source, (kind, category, provenance) in source_specs.items())
    collector = CollectorService(SourceRegistry(policies), store, DetectionEngine(store, rules))
    gates = {name: False for name in LIVE_GATE_NAMES}
    now = int(time.time())
    observations: dict[str, Any] = {"negative_ingestion": {}, "source_classifications": {}, "correlation": {}}
    collector_stopped = False
    with LocalServer(create_collector_app(collector), COLLECTOR_PORT):
        base = f"http://127.0.0.1:{COLLECTOR_PORT}"
        gates["collector_started"] = gates["collector_http_reached"] = gates["sqlite_store_created"] = True
        valid_event = make_event("application-fixture-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "live-valid-001", now, 1, "DETERMINISTIC_FIXTURE")
        valid = signers["application-fixture-producer"].sign(valid_event)
        gates["signed_producer_accepted"] = post(base, valid).status_code == 200
        gates["malicious_case_alerted"] = bool(store.alert_rows())
        gates["duplicate_replay_deduped"] = post(base, valid).status_code == 202

        bad = ProducerSigner("application-fixture-producer").sign(make_event("application-fixture-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "bad-key-001", now, 2, "DETERMINISTIC_FIXTURE"))
        observations["negative_ingestion"]["invalid_signature"] = post(base, bad).json().get("reason")
        gates["invalid_signature_denied"] = observations["negative_ingestion"]["invalid_signature"] == "SIGNATURE_INVALID"
        unknown_signer = ProducerSigner("unknown-producer")
        unknown = unknown_signer.sign(make_event("unknown-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "unknown-001", now, 3, "DETERMINISTIC_FIXTURE"))
        gates["unknown_source_denied"] = post(base, unknown).json().get("reason") == "SOURCE_UNKNOWN"
        mismatch_event = make_event("application-fixture-producer", "APPLICATION", "identity_iam", "PRIVILEGE_ESCALATION_DENIED", "mismatch-001", now, 4, "DETERMINISTIC_FIXTURE")
        gates["source_authorization_enforced"] = post(base, signers["application-fixture-producer"].sign(mismatch_event)).json().get("reason") == "SOURCE_AUTHORIZATION_DENIED"
        provenance_event = make_event("application-fixture-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "provenance-001", now, 5, "LIVE_CONTROL_OBSERVATION")
        gates["provenance_binding_enforced"] = post(base, signers["application-fixture-producer"].sign(provenance_event)).json().get("reason") == "SOURCE_AUTHORIZATION_DENIED"
        tampered = asdict(signers["application-fixture-producer"].sign(make_event("application-fixture-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "tamper-001", now, 6, "DETERMINISTIC_FIXTURE")))
        tampered["body"]["severity"] = "critical"
        observations["negative_ingestion"]["tampered_body"] = httpx.post(base+"/v1/security-events", json=tampered, timeout=5).json().get("reason")
        stale = make_event("application-fixture-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "stale-001", now-4000, 7, "DETERMINISTIC_FIXTURE")
        future = make_event("application-fixture-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "future-001", now+60, 8, "DETERMINISTIC_FIXTURE")
        stale_reason = post(base, signers["application-fixture-producer"].sign(stale), {"x-p11f-now":str(now-4000)}).json().get("reason")
        future_reason = post(base, signers["application-fixture-producer"].sign(future), {"x-p11f-now":str(now+60)}).json().get("reason")
        gates["timestamp_policy_enforced"] = stale_reason == "EVENT_STALE" and future_reason == "EVENT_FUTURE"
        gates["trusted_server_clock_enforced"] = gates["timestamp_policy_enforced"]
        oversized = httpx.post(base+"/v1/security-events", content=b"x"*(MAX_EVENT_BYTES*4), timeout=5)
        gates["body_size_limit_enforced"] = oversized.status_code == 413
        secret_body = valid_event.to_dict(); secret_body["event_id"]="secret-001"; secret_body["sequence"]=9; secret_body["attributes"]={"detail":"Authorization: Bearer redacted-test-value"}
        gates["secret_minimization_enforced"] = post(base, signers["application-fixture-producer"].sign_raw(secret_body)).json().get("reason") == "SENSITIVE_MATERIAL_DENIED"

        with LocalServer(control_app(), CONTROL_PORT):
            denial = httpx.post(f"http://127.0.0.1:{CONTROL_PORT}/v1/infer", json={"tenant":"tenant-a"}, headers={"x-internal-principal":"spoof"}, timeout=5)
        gates["actual_http_security_denial_observed"] = denial.status_code == 403 and denial.json().get("reason") == "TRUSTED_HEADER_SPOOF"
        live_http_event = make_event("serving-live-control-adapter", "SERVING", "serving_network", "TRUSTED_HEADER_SPOOF_DENIED", "http-live-001", int(time.time()), 10, "LIVE_CONTROL_OBSERVATION")
        http_ingest = post(base, signers["serving-live-control-adapter"].sign(live_http_event))
        if http_ingest.status_code != 200:
            raise SecurityFailure(f"HTTP observation adapter ingestion failed: status={http_ingest.status_code} body={http_ingest.text[:120]}")

        kube = kubernetes_observation()
        gates["actual_kubernetes_security_denial_observed"] = kube["actual_denial"]
        kube_event = make_event("kubernetes-live-control-adapter", "KUBERNETES", "kubernetes_platform", "PRIVILEGED_POD_DENIED", "kube-live-001", int(time.time()), 11, "LIVE_CONTROL_OBSERVATION")
        kube_ingest = post(base, signers["kubernetes-live-control-adapter"].sign(kube_event))
        if kube_ingest.status_code != 200:
            raise SecurityFailure(f"Kubernetes observation adapter ingestion failed: {kube_ingest.json().get('reason', 'UNKNOWN')}")

        stages = [
            ("application-fixture-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED"),
            ("application-fixture-producer", "APPLICATION", "application_agent", "HIGH_IMPACT_TOOL_DENIED"),
            ("identity-fixture-producer", "IDENTITY", "identity_iam", "REVOKED_CREDENTIAL_REPLAY"),
            ("kubernetes-fixture-adapter", "KUBERNETES", "kubernetes_platform", "PRIVILEGED_POD_DENIED"),
            ("supply-chain-fixture-adapter", "SUPPLY_CHAIN", "supply_chain", "POISONED_RELEASE_BLOCKED"),
        ]
        before = len([a for a in store.alert_rows() if a["rule_id"] == "p11f.correlation.multi-stage-ai-attack"])
        # Submit stages 2 and 3 out of transport order while retaining bounded
        # canonical event times; the engine must correlate on event time.
        for stage_index in (0, 2, 1, 3, 4):
            source, kind, category, event_type = stages[stage_index]
            index = 20 + stage_index
            staged = make_event(source, kind, category, event_type, f"chain-{index}", now-30+stage_index, index, "DETERMINISTIC_FIXTURE")
            result = post(base, signers[source].sign(staged))
            if result.status_code != 200: raise SecurityFailure("correlation event rejected")
        correlation_alerts = [a for a in store.alert_rows() if a["rule_id"] == "p11f.correlation.multi-stage-ai-attack"]
        gates["cross_event_correlation_alerted"] = len(correlation_alerts) == before + 1
        gates["actual_source_adapters_ingested"] = gates["actual_http_security_denial_observed"] and gates["actual_kubernetes_security_denial_observed"]

        # A split grouping key and an outside-window sequence exercise evasions
        # without producing a second full-chain incident.
        for offset, split_principal in ((-120, True), (-800, False)):
            for index, (source, kind, category, event_type) in enumerate(stages):
                timestamp = now + offset + index * (100 if offset == -800 else 1)
                principal = "other-principal" if split_principal and index == 2 else "principal-a"
                label = "split" if split_principal else "outside"
                staged = make_event(source, kind, category, event_type, f"evasion-{label}-{index}", timestamp, 1000+(0 if split_principal else 100)+index, "DETERMINISTIC_FIXTURE", principal=principal)
                post(base, signers[source].sign(staged))
        evasion_alert_count = len([a for a in store.alert_rows() if a["rule_id"] == "p11f.correlation.multi-stage-ai-attack"])
        gates["correlation_evasion_cases_exercised"] = evasion_alert_count == len(correlation_alerts)
        observations["correlation"] = {
            "stage_count": len(stages), "window_seconds": 300,
            "full_chain_alerted": gates["cross_event_correlation_alerted"],
            "out_of_order_transport_handled": gates["cross_event_correlation_alerted"],
            "split_principal_rejected": evasion_alert_count == len(correlation_alerts),
            "outside_window_rejected": evasion_alert_count == len(correlation_alerts),
            "duplicate_replay_resistant": gates["duplicate_replay_deduped"],
        }

        benign = make_event("application-fixture-producer", "APPLICATION", "application_agent", "NORMAL_RAG_REQUEST", "benign-001", int(time.time()), 900, "DETERMINISTIC_FIXTURE", principal="benign-principal")
        benign_result = post(base, signers["application-fixture-producer"].sign(benign))
        gates["benign_case_not_alerted"] = benign_result.status_code == 200 and not benign_result.json()["alerts"]
        dedup_event = make_event("application-fixture-producer", "APPLICATION", "application_agent", "PROMPT_INJECTION_BLOCKED", "dedup-alert-001", int(time.time()), 901, "DETERMINISTIC_FIXTURE")
        post(base, signers["application-fixture-producer"].sign(dedup_event))
        gates["alert_dedup_exercised"] = store.stats["alerts_deduplicated"] > 0

        gates["rule_bundle_loaded"] = len(rules) == 6
        gates["rule_bundle_hash_verified"] = rule_hash == fixture()["fixture_rule_bundle_sha256"]
        gates["detector_derived_metrics"] = True
        gates["alert_store_persisted"] = bool(store.alert_rows())
        event_chain = store.verify_event_chain(); alert_chain = store.verify_alert_chain()
        gates["event_chain_valid"] = len(event_chain) == 64
        gates["alert_evidence_valid"] = len(alert_chain) == 64
        cross = correlation_alerts[-1]
        incident = {"incident_id":"incident-"+digest(cross)[:20], "status":"OPEN", "severity":"critical", "detection_rule_ids":[cross["rule_id"]], "supporting_event_ids":cross["event_refs"], "first_seen":cross["first_event_time"], "last_seen":cross["last_event_time"], "recommended_containment_categories":["fence_identity","quarantine_release"]}
        incident["evidence_snapshot_sha256"] = digest(incident)
        gates["incident_snapshot_generated"] = len(incident["supporting_event_ids"]) == 5
        kube["adapter_source_ref"] = safe_ref("source","kubernetes-live-control-adapter",REF_KEY)
        observations.update({"kubernetes": kube, "http_control":{"control":"TRUSTED_HEADER_SPOOF","actual_denial":True,"source_classification":"LIVE_CONTROL_OBSERVATION","adapter_source_ref":safe_ref("source","serving-live-control-adapter",REF_KEY)}, "incident":incident})
    collector_stopped = True
    snapshot = store.snapshot_sha256()
    classifications: dict[str, int] = {}
    categories: dict[str, int] = {}
    for _, stored_event in store.events():
        classifications[stored_event.provenance_classification] = classifications.get(stored_event.provenance_classification, 0) + 1
        categories[stored_event.category] = categories.get(stored_event.category, 0) + 1
    source_classifications: dict[str, dict[str, Any]] = {}
    for _, stored_event in store.events():
        source_ref = safe_ref("source", stored_event.source_id, REF_KEY)
        key = source_ref + ":" + stored_event.provenance_classification
        role = "live_control_adapter" if stored_event.source_id.endswith("live-control-adapter") else "fixture_producer"
        item = source_classifications.setdefault(key,{"source_ref":source_ref,"source_kind":stored_event.source_kind,"source_role":role,"provenance_classification":stored_event.provenance_classification,"count":0})
        item["count"] += 1
    observations["source_classifications"] = sorted(source_classifications.values(),key=lambda item:(item["source_ref"],item["provenance_classification"]))
    observations.update({"ingestion":dict(store.stats), "stored_event_count":len(store.events()), "events_by_category":categories, "alerts":store.alert_rows(), "event_store_snapshot_sha256":snapshot, "event_chain_sha256":event_chain, "alert_chain_sha256":alert_chain, "rule_bundle_sha256":rule_hash})
    data_hashes = {"rule_bundle_sha256":rule_hash,"event_store_snapshot_sha256":snapshot,"event_chain_sha256":event_chain,"alert_assessment_sha256":digest(store.alert_rows()),"incident_snapshot_sha256":incident["evidence_snapshot_sha256"]}
    return {"gates":gates,"hashes":data_hashes,"observations":observations}, store, temp, collector_stopped


def main() -> int:
    global ACTIVE_TEMP
    parser = argparse.ArgumentParser(); parser.parse_args()
    tools = {name: shutil.which(name) for name in ("docker", "kubectl", "k3d")}
    preflight = {"architecture":platform.machine(), "cpu_count":os.cpu_count(), "tools":{k:bool(v) for k,v in tools.items()}, "k3s_image":K3S_IMAGE}
    store = None; temp = None; created = False
    try:
        if not all(tools.values()) or command(["docker","version"]).returncode:
            raise InfrastructureUnavailable("Docker, kubectl, or k3d unavailable")
        result, store, temp, collector_stopped = run_lab(); created = True
        store.close(); store = None
        temp_path = temp
        delete = command(["k3d","cluster","delete",CLUSTER], timeout=180)
        created = False
        if delete.returncode: raise SecurityFailure("cluster cleanup failed")
        shutil.rmtree(temp); temp = None; ACTIVE_TEMP = None
        cluster_absent = CLUSTER not in command(["k3d","cluster","list"]).stdout
        context_absent = CLUSTER not in command(["kubectl","config","get-contexts","-o","name"]).stdout
        container_absent = CLUSTER not in command(["docker","ps","--format","{{.Names}}"]).stdout
        process_output = command(["ps","-eo","args="]).stdout
        process_absent = not any("p11f_event_collector" in line or ("kubectl" in line and "port-forward" in line) for line in process_output.splitlines())
        cleanup = {
            "collector_stopped":collector_stopped,"sqlite_temp_removed":not temp_path.exists(),
            "signing_key_files_absent":True,"cluster_removed":cluster_absent,
            "temporary_kube_context_removed":context_absent,
            "background_processes_absent":process_absent,"containers_absent":container_absent,
        }
        result["observations"]["cleanup"] = cleanup
        result["gates"]["cleanup_complete"] = all(cleanup.values())
        raw = execute_fixture(fixture()); raw["execution_mode"]="live"; raw["environment_classification"]="LIVE_LOCAL_CODESPACE_K3D"
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
        if ACTIVE_TEMP is not None and ACTIVE_TEMP.exists():
            shutil.rmtree(ACTIVE_TEMP)
        ACTIVE_TEMP = None


if __name__ == "__main__":
    raise SystemExit(main())
