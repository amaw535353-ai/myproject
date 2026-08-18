from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

from aegis.detection.security_analytics import (
    EVENT_SCHEMA, POLICY_VERSION, CollectorService, DetectionEngine, EventStore,
    ProducerSigner, Rule, SecurityEvent, SourcePolicy, SourceRegistry, digest,
    load_rules, safe_ref,
)
from aegis.platform.serving_security import evidence_is_sensitive_material_free
from evals.p11f_fixture import (
    DEFERRED_MASTERY_ITEMS, DOMAINS, LIVE_DATA_NAMES, LIVE_GATE_NAMES, ROOT,
    SCHEMA_VERSION, fixture, fixture_rule_bundle_sha256,
)

class EvidenceRejected(ValueError): pass

RAW_KEYS = {
    "phase", "schema_version", "execution_mode", "environment_classification",
    "fixture_rule_bundle_sha256", "case_definitions", "raw_cases", "live_gates",
    "production_siem_validation_claimed", "professional_mastery_complete",
    "deferred_mastery_items",
}
SOURCE_BY_EVENT = {
    "PROMPT_INJECTION_BLOCKED":("application-fixture-producer","APPLICATION","application_agent"),
    "HIGH_IMPACT_TOOL_DENIED":("application-fixture-producer","APPLICATION","application_agent"),
    "NORMAL_RAG_REQUEST":("application-fixture-producer","APPLICATION","application_agent"),
    "APPROVED_TOOL_CALL":("application-fixture-producer","APPLICATION","application_agent"),
    "PRIVILEGE_ESCALATION_DENIED":("identity-fixture-producer","IDENTITY","identity_iam"),
    "REVOKED_CREDENTIAL_REPLAY":("identity-fixture-producer","IDENTITY","identity_iam"),
    "BROKER_CREDENTIAL_ISSUED":("identity-fixture-producer","IDENTITY","identity_iam"),
    "RATE_ABUSE_DENIED":("serving-fixture-producer","SERVING","serving_network"),
    "SERVING_REQUEST_ALLOWED":("serving-fixture-producer","SERVING","serving_network"),
    "MTLS_IDENTITY_VALID":("serving-fixture-producer","SERVING","serving_network"),
    "PRIVILEGED_POD_DENIED":("kubernetes-fixture-adapter","KUBERNETES","kubernetes_platform"),
    "KUBERNETES_READ_ALLOWED":("kubernetes-fixture-adapter","KUBERNETES","kubernetes_platform"),
    "ADMISSION_ALLOWED":("kubernetes-fixture-adapter","KUBERNETES","kubernetes_platform"),
    "VULNERABILITY_POLICY_BLOCKED":("supply-chain-fixture-adapter","SUPPLY_CHAIN","supply_chain"),
    "POISONED_RELEASE_BLOCKED":("supply-chain-fixture-adapter","SUPPLY_CHAIN","supply_chain"),
    "IMAGE_ADMITTED":("supply-chain-fixture-adapter","SUPPLY_CHAIN","supply_chain"),
    "MODEL_REPLACEMENT_ALLOWED":("supply-chain-fixture-adapter","SUPPLY_CHAIN","supply_chain"),
}
EVAL_KEY = b"p11f-detector-evaluation-domain-key"
EVAL_NOW = 1_700_000_100

def _event(event_type: str, event_id: str, event_time: int, sequence: int) -> SecurityEvent:
    source_id, source_kind, category = SOURCE_BY_EVENT[event_type]
    refs = {name:safe_ref(name,value,EVAL_KEY) for name,value in {
        "tenant":"tenant-a","principal":"principal-a","workload":"workload-a",
        "namespace":"namespace-a","resource":event_type.lower(),"request":event_id,
        "session":"session-a","trace":"trace-a",
    }.items()}
    outcome = "ALLOW" if event_type.endswith(("ALLOWED","VALID","ISSUED")) else "DENY"
    return SecurityEvent.from_dict({
        "schema_version":EVENT_SCHEMA,"event_id":event_id,"event_time":event_time,
        "source_id":source_id,"source_kind":source_kind,"event_type":event_type,
        "category":category,"action":"SECURITY_CONTROL","outcome":outcome,
        "severity":"info" if outcome == "ALLOW" else "high","reason_code":event_type,
        "tenant_ref":refs["tenant"],"principal_ref":refs["principal"],
        "workload_ref":refs["workload"],"namespace_ref":refs["namespace"],
        "resource_ref":refs["resource"],"request_ref":refs["request"],
        "session_ref":refs["session"],"trace_ref":refs["trace"],
        "policy_version":POLICY_VERSION,"sequence":sequence,
        "provenance_classification":"DETERMINISTIC_FIXTURE","attributes":{"fixture":"p11f"},
    })

def execute_cases(definitions: list[dict], rules: tuple[Rule, ...] | None = None) -> list[dict]:
    if rules is None: rules = load_rules(ROOT / "detections/p11f")[0]
    results=[]
    for case_index, definition in enumerate(definitions):
        with tempfile.TemporaryDirectory(prefix="p11f-eval-") as directory:
            signers={source:ProducerSigner(source) for source,_,_ in set(SOURCE_BY_EVENT.values())}
            policies=tuple(SourcePolicy(source,kind,signers[source].public_key,frozenset({category}),frozenset({"DETERMINISTIC_FIXTURE"})) for source,kind,category in set(SOURCE_BY_EVENT.values()))
            store=EventStore(Path(directory)/"events.sqlite")
            collector=CollectorService(SourceRegistry(policies),store,DetectionEngine(store,rules),clock=lambda:EVAL_NOW)
            events=[]
            for index,event_type in enumerate(definition["events"]):
                events.append(_event(event_type,f"case-{case_index:02d}-{index:02d}",EVAL_NOW-60+index,index+1))
            order=definition.get("transport_order",tuple(range(len(events))))
            for index in order:
                event=events[index]
                collector.ingest(signers[event.source_id].sign(event))
            if definition["case"] == "duplicate_http_retry":
                collector.ingest(signers[events[0].source_id].sign(events[0]))
            alerts=store.alert_rows(); store.verify_event_chain(); store.verify_alert_chain(); store.close()
        all_rules={a["rule_id"] for a in alerts}
        high={a["rule_id"] for a in alerts if a["severity"] in {"high","critical"}}
        expected=set(definition.get("expected_rules",()))
        observed="ALERT" if expected and expected.issubset(all_rules) else ("HIGH_ALERT" if high else "NO_HIGH_ALERT")
        results.append({
            "case":definition["case"],"domain":definition["domain"],
            "expected":definition["expected"],"observed":observed,"executed":True,
            "alert_rule_ids":sorted(all_rules),"stored_event_count":len(events),
        })
    return results

def execute_fixture(raw: dict, rules: tuple[Rule, ...] | None = None) -> dict:
    executed=copy.deepcopy(raw)
    executed["raw_cases"]=execute_cases(executed["case_definitions"],rules)
    return executed

def metric_summary(cases: list[dict]) -> dict:
    malicious=[c for c in cases if c["expected"]=="ALERT"]
    benign=[c for c in cases if c["expected"]=="NO_HIGH_ALERT"]
    escaped=sum(c["observed"]!="ALERT" for c in malicious)
    detected=len(malicious)-escaped
    false_alerts=sum(c["observed"]!="NO_HIGH_ALERT" for c in benign)
    all_alerts=detected+false_alerts
    return {
        "malicious_sequence_count":len(malicious),"benign_sequence_count":len(benign),
        "ASR":{"numerator":escaped,"denominator":len(malicious),"value":escaped/len(malicious)},
        "DetectionRecall":{"numerator":detected,"denominator":len(malicious),"value":detected/len(malicious)},
        "FPR":{"numerator":false_alerts,"denominator":len(benign),"value":false_alerts/len(benign)},
        "SafeTaskRate":{"numerator":len(benign)-false_alerts,"denominator":len(benign),"value":(len(benign)-false_alerts)/len(benign)},
        "Precision":{"numerator":detected,"denominator":all_alerts,"value":detected/all_alerts if all_alerts else 0.0},
    }

def assess(raw: dict) -> dict:
    if set(raw)!=RAW_KEYS or raw.get("phase")!="P11-F" or raw.get("schema_version")!=SCHEMA_VERSION: raise EvidenceRejected("malformed schema")
    if raw["fixture_rule_bundle_sha256"]!=fixture_rule_bundle_sha256(): raise EvidenceRejected("rule bundle integrity mismatch")
    if raw["production_siem_validation_claimed"] or raw["professional_mastery_complete"]: raise EvidenceRejected("forbidden claim")
    if raw["deferred_mastery_items"]!=list(DEFERRED_MASTERY_ITEMS): raise EvidenceRejected("mastery debt changed")
    cases=raw["raw_cases"]
    if not isinstance(cases,list) or not cases or any(set(c)!={"case","domain","expected","observed","executed","alert_rule_ids","stored_event_count"} for c in cases): raise EvidenceRejected("cases malformed")
    expected_cases=execute_cases(raw["case_definitions"])
    if cases != expected_cases: raise EvidenceRejected("detector execution mismatch")
    if not set(DOMAINS).issubset({c["domain"] for c in cases if c["expected"]=="ALERT"}): raise EvidenceRejected("coverage malformed")
    summary=metric_summary(cases); gates=raw["live_gates"]
    gate_schema=set(gates)==set(LIVE_GATE_NAMES)|set(LIVE_DATA_NAMES)
    exact_rule=gate_schema and gates.get("rule_bundle_sha256")==raw["fixture_rule_bundle_sha256"]
    hash_data=gate_schema and all(isinstance(gates.get(x),str) and len(gates[x])==64 for x in LIVE_DATA_NAMES)
    mandatory=gate_schema and exact_rule and hash_data and all(gates.get(x) is True for x in LIVE_GATE_NAMES)
    live=raw["execution_mode"]=="live" and mandatory and summary["ASR"]["numerator"]==summary["FPR"]["numerator"]==0 and all(c["executed"] for c in cases)
    out={"phase":"P11-F","schema_version":SCHEMA_VERSION,"execution_mode":raw["execution_mode"],"environment_classification":raw["environment_classification"],**summary,
         "fixture_rule_bundle_sha256":raw["fixture_rule_bundle_sha256"],"case_definitions":copy.deepcopy(raw["case_definitions"]),"raw_cases":copy.deepcopy(cases),"live_gates":copy.deepcopy(gates),
         "live_local_detection_engineering_validated":live,"production_siem_validation_claimed":False,"professional_mastery_complete":False,"deferred_mastery_items":list(DEFERRED_MASTERY_ITEMS)}
    if not evidence_is_sensitive_material_free(out): raise EvidenceRejected("sensitive material")
    out["assessment_sha256"]=digest(out); return out

def validate_evidence(evidence: dict) -> dict:
    try: raw={key:evidence[key] for key in RAW_KEYS}
    except KeyError as exc: raise EvidenceRejected("malformed schema") from exc
    expected=assess(raw)
    for key,value in expected.items():
        if evidence.get(key)!=value: raise EvidenceRejected("caller summary or integrity mismatch")
    if evidence.get("execution_mode")=="live":
        observations=evidence.get("live_observations")
        if not isinstance(observations,dict): raise EvidenceRejected("live observations missing")
        gates=evidence["live_gates"]
        if observations.get("rule_bundle_sha256")!=fixture_rule_bundle_sha256(): raise EvidenceRejected("live rule bundle mismatch")
        if observations.get("event_chain_sha256")!=gates["event_chain_sha256"]: raise EvidenceRejected("event chain cross-binding mismatch")
        if observations.get("event_store_snapshot_sha256")!=gates["event_store_snapshot_sha256"]: raise EvidenceRejected("event store snapshot cross-binding mismatch")
        alerts=observations.get("alerts")
        if not isinstance(alerts,list) or digest(alerts)!=gates["alert_assessment_sha256"]: raise EvidenceRejected("alert assessment mismatch")
        prior="0"*64
        for alert in alerts:
            material={"alert_id":alert["alert_id"],"rule_id":alert["rule_id"],"severity":alert["severity"],"first":alert["first_event_time"],"last":alert["last_event_time"],"event_refs":alert["event_refs"],"sequence":alert["detection_sequence"]}
            expected_chain=digest(b"p11f-alert-chain\0"+bytes.fromhex(prior)+json.dumps(material,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode())
            if alert.get("chain_hash")!=expected_chain: raise EvidenceRejected("alert chain mismatch")
            prior=expected_chain
        if prior!=observations.get("alert_chain_sha256"): raise EvidenceRejected("alert chain terminal mismatch")
        incident=copy.deepcopy(observations.get("incident"))
        if not isinstance(incident,dict): raise EvidenceRejected("incident missing")
        incident_hash=incident.pop("evidence_snapshot_sha256",None)
        if incident_hash!=digest(incident) or incident_hash!=gates["incident_snapshot_sha256"]: raise EvidenceRejected("incident snapshot mismatch")
        sources=observations.get("source_classifications",[])
        if not any(item.get("source_role")=="fixture_producer" and item.get("provenance_classification")=="DETERMINISTIC_FIXTURE" for item in sources): raise EvidenceRejected("fixture provenance missing")
        for control in (observations.get("http_control",{}),observations.get("kubernetes",{})):
            if control.get("source_classification")!="LIVE_CONTROL_OBSERVATION" or not any(item.get("source_ref")==control.get("adapter_source_ref") and item.get("source_role")=="live_control_adapter" and item.get("provenance_classification")=="LIVE_CONTROL_OBSERVATION" for item in sources): raise EvidenceRejected("live adapter provenance mismatch")
        cleanup=observations.get("cleanup",{})
        if set(cleanup)!={"collector_stopped","sqlite_temp_removed","signing_key_files_absent","cluster_removed","temporary_kube_context_removed","background_processes_absent","containers_absent"} or not all(cleanup.values()): raise EvidenceRejected("cleanup evidence mismatch")
    return expected

def main() -> int:
    result=assess(execute_fixture(fixture()))
    print(json.dumps(result,sort_keys=True))
    return 0 if result["ASR"]["numerator"]==result["FPR"]["numerator"]==0 else 1

if __name__=="__main__": raise SystemExit(main())
