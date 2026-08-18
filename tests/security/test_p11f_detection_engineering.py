from __future__ import annotations

import asyncio
import copy
import json
import sqlite3

import pytest

from aegis.detection.security_analytics import (
    CATEGORIES, EVENT_SCHEMA, POLICY_VERSION, CollectorService, DetectionDenied,
    DetectionEngine, EventStore, ProducerSigner, SecurityEvent, SignedEventEnvelope,
    SourcePolicy, SourceRegistry, canonical_bytes, digest, load_rules, safe_ref,
)
from evals.p11f_detection_engineering import (
    EvidenceRejected, assess, execute_cases, execute_fixture, metric_summary,
    validate_evidence,
)
from evals.p11f_fixture import (
    DEFERRED_MASTERY_ITEMS, LIVE_DATA_NAMES, LIVE_GATE_NAMES, ROOT, fixture,
)

KEY = b"p11f-test-domain-key"


def event(
    event_id: str = "evt-001", event_type: str = "PROMPT_INJECTION_BLOCKED",
    category: str = "application_agent", source_id: str = "application-producer",
    source_kind: str = "APPLICATION", event_time: int = 1_700_000_000,
    sequence: int = 1, provenance: str = "DETERMINISTIC_FIXTURE",
    tenant: str = "tenant-a", principal: str = "principal-a",
) -> SecurityEvent:
    refs = {name: safe_ref(name, value, KEY) for name, value in {
        "tenant": tenant, "principal": principal, "workload": "workload-a",
        "namespace": "namespace-a", "resource": "resource-a", "request": event_id,
        "session": "session-a", "trace": "trace-a",
    }.items()}
    return SecurityEvent.from_dict({
        "schema_version": EVENT_SCHEMA, "event_id": event_id, "event_time": event_time,
        "source_id": source_id, "source_kind": source_kind, "event_type": event_type,
        "category": category, "action": "SECURITY_CONTROL", "outcome": "DENY",
        "severity": "high", "reason_code": event_type, "tenant_ref": refs["tenant"],
        "principal_ref": refs["principal"], "workload_ref": refs["workload"],
        "namespace_ref": refs["namespace"], "resource_ref": refs["resource"],
        "request_ref": refs["request"], "session_ref": refs["session"],
        "trace_ref": refs["trace"], "policy_version": POLICY_VERSION,
        "sequence": sequence, "provenance_classification": provenance,
        "attributes": {"control": "bounded"},
    })


def service(tmp_path):
    signer = ProducerSigner("application-producer")
    registry = SourceRegistry((SourcePolicy(
        signer.source_id, "APPLICATION", signer.public_key,
        frozenset({"application_agent"}), frozenset({"DETERMINISTIC_FIXTURE"}),
    ),))
    rules, bundle_hash = load_rules(ROOT / "detections/p11f")
    store = EventStore(tmp_path / "events.sqlite")
    return signer, store, CollectorService(registry, store, DetectionEngine(store, rules), clock=lambda: 1_700_000_001), bundle_hash


def test_event_schema_canonicalization_hash_and_unknown_field() -> None:
    item = event()
    assert canonical_bytes(item.to_dict()) == canonical_bytes(dict(reversed(list(item.to_dict().items()))))
    assert digest(item.to_dict()) == digest(json.loads(canonical_bytes(item.to_dict())))
    bad = item.to_dict(); bad["unknown"] = True
    with pytest.raises(DetectionDenied, match="SCHEMA"): SecurityEvent.from_dict(bad)


def test_signed_event_accepts_and_wrong_key_tamper_unsigned_are_denied(tmp_path) -> None:
    signer, store, collector, _ = service(tmp_path)
    env = signer.sign(event())
    assert collector.ingest(env, 1_700_000_001)["status"] == "ACCEPTED"
    wrong = ProducerSigner(signer.source_id).sign(event("evt-002", sequence=2))
    with pytest.raises(DetectionDenied, match="SIGNATURE"): collector.ingest(wrong, 1_700_000_001)
    changed = copy.deepcopy(env); changed.body["severity"] = "critical"
    with pytest.raises(DetectionDenied, match="BINDING"): collector.ingest(changed, 1_700_000_001)
    with pytest.raises((TypeError, DetectionDenied)): SignedEventEnvelope(**{k:v for k,v in env.__dict__.items() if k != "signature"})
    store.close()


def test_real_http_collector_route_accepts_signed_envelope(tmp_path) -> None:
    from dataclasses import asdict
    import httpx
    from aegis.detection.security_analytics import create_collector_app

    signer, store, collector, _ = service(tmp_path)
    async def post_event():
        transport = httpx.ASGITransport(app=create_collector_app(collector))
        async with httpx.AsyncClient(transport=transport, base_url="http://p11f.test") as client:
            return await client.post(
                "/v1/security-events", json=asdict(signer.sign(event())),
                headers={"x-p11f-now": "1700000001"},
            )

    response = asyncio.run(post_event())
    assert response.status_code == 200
    assert response.json()["status"] == "ACCEPTED"
    store.close()


def test_http_uses_trusted_clock_and_streaming_body_cap(tmp_path) -> None:
    from dataclasses import asdict
    import httpx
    from aegis.detection.security_analytics import MAX_HTTP_BODY_BYTES, create_collector_app

    signer, store, collector, _ = service(tmp_path)
    async def requests():
        transport = httpx.ASGITransport(app=create_collector_app(collector))
        async with httpx.AsyncClient(transport=transport, base_url="http://p11f.test") as client:
            stale = await client.post("/v1/security-events", json=asdict(signer.sign(event(event_time=1_699_996_000))), headers={"x-p11f-now":"1699996000"})
            future = await client.post("/v1/security-events", json=asdict(signer.sign(event("evt-002",event_time=1_700_000_100,sequence=2))), headers={"x-p11f-now":"1700000100"})
            extreme = await client.post("/v1/security-events", json=asdict(signer.sign(event("evt-003",sequence=3))), headers={"x-p11f-now":"999999999999999999"})
            missing = await client.post("/v1/security-events", json=asdict(signer.sign(event("evt-004",sequence=4))))
            oversized = await client.post("/v1/security-events", content=b"x"*(MAX_HTTP_BODY_BYTES*4))
            return stale,future,extreme,missing,oversized
    stale,future,extreme,missing,oversized=asyncio.run(requests())
    assert stale.json()["reason"] == "EVENT_STALE"
    assert future.json()["reason"] == "EVENT_FUTURE"
    assert extreme.status_code == missing.status_code == 200
    assert oversized.status_code == 413 and oversized.json()["reason"] == "BODY_TOO_LARGE"
    store.close()


def test_source_category_impersonation_unknown_source_and_provenance_denied(tmp_path) -> None:
    signer, store, collector, _ = service(tmp_path)
    for changed in (
        event("evt-002", category="identity_iam", sequence=2),
        event("evt-003", provenance="NATIVE_LIVE", sequence=3),
    ):
        with pytest.raises(DetectionDenied, match="AUTHORIZATION"): collector.ingest(signer.sign(changed), 1_700_000_001)
    unknown = ProducerSigner("unknown-producer").sign(event("evt-004", source_id="unknown-producer", sequence=4))
    with pytest.raises(DetectionDenied, match="UNKNOWN"): collector.ingest(unknown, 1_700_000_001)
    store.close()


def test_duplicate_retry_is_stored_once_and_alert_deduplicates(tmp_path) -> None:
    signer, store, collector, _ = service(tmp_path)
    envelope = signer.sign(event())
    assert collector.ingest(envelope, 1_700_000_001)["status"] == "ACCEPTED"
    assert collector.ingest(envelope, 1_700_000_001)["status"] == "DEDUPLICATED"
    collector.ingest(signer.sign(event("evt-002", sequence=2)), 1_700_000_001)
    assert store.stats["accepted"] == 2 and store.stats["deduplicated"] == 1
    assert store.stats["alerts_created"] == 1 and store.stats["alerts_deduplicated"] == 1
    store.verify_alert_chain(); store.close()


def test_timestamp_size_control_and_secret_minimization() -> None:
    signer = ProducerSigner("application-producer")
    registry = SourceRegistry((SourcePolicy(signer.source_id, "APPLICATION", signer.public_key, frozenset({"application_agent"}), frozenset({"DETERMINISTIC_FIXTURE"})),))
    with pytest.raises(DetectionDenied, match="STALE"): registry.verify(signer.sign(event()), 1_700_004_000)
    with pytest.raises(DetectionDenied, match="FUTURE"): registry.verify(signer.sign(event()), 1_699_999_900)
    for sensitive in ("Authorization: Bearer aaa.bbb.ccc", "-----BEGIN PRIVATE KEY-----"):
        raw = event().to_dict(); raw["attributes"] = {"detail": sensitive}
        with pytest.raises(DetectionDenied): SecurityEvent.from_dict(raw)
    raw = event().to_dict(); raw["attributes"] = {"x": "a" * 200}
    with pytest.raises(DetectionDenied, match="ATTRIBUTES"): SecurityEvent.from_dict(raw)


def test_sqlite_uniqueness_transaction_and_event_chain_tamper(tmp_path) -> None:
    store = EventStore(tmp_path / "events.sqlite")
    assert store.append(event())[0]
    assert not store.append(event())[0]
    store.verify_event_chain()
    with store.db: store.db.execute("UPDATE events SET payload='{}' WHERE event_id='evt-001'")
    with pytest.raises(DetectionDenied, match="CHAIN"): store.verify_event_chain()
    assert store.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    store.close()


def test_rule_bundle_schema_duplicate_operator_window_and_domain_coverage(tmp_path) -> None:
    rules, bundle_hash = load_rules(ROOT / "detections/p11f")
    assert len(rules) == 6 and len(bundle_hash) == 64
    originals = [json.loads(path.read_text()) for path in sorted((ROOT / "detections/p11f").glob("*.json"))]
    for case_index, (mutate, reason) in enumerate((
        (lambda values: values.append(copy.deepcopy(values[0])), "DUPLICATE"),
        (lambda values: values[0].update(kind="eval"), "POLICY"),
        (lambda values: values[0].update(window_seconds=0), "POLICY"),
    )):
        case_dir = tmp_path / f"{case_index}-{reason}"; case_dir.mkdir()
        values = copy.deepcopy(originals); mutate(values)
        for index, value in enumerate(values): (case_dir / f"{index}.json").write_text(json.dumps(value))
        with pytest.raises(DetectionDenied, match=reason): load_rules(case_dir)
    tamper_dir=tmp_path/"tampered"; tamper_dir.mkdir()
    for index,value in enumerate(originals): (tamper_dir/f"{index}.json").write_text(json.dumps(value))
    changed=json.loads((tamper_dir/"0.json").read_text()); changed["title"] += " changed"
    (tamper_dir/"0.json").write_text(json.dumps(changed))
    assert load_rules(tamper_dir)[1] != bundle_hash
    raw=execute_fixture(fixture()); raw["fixture_rule_bundle_sha256"]=load_rules(tamper_dir)[1]
    with pytest.raises(EvidenceRejected,match="rule bundle integrity"): assess(raw)


def test_single_threshold_and_cross_source_correlation(tmp_path) -> None:
    rules, _ = load_rules(ROOT / "detections/p11f")
    signers = {}
    policies = []
    source_spec = {
        "app": ("APPLICATION", "application_agent"), "identity": ("IDENTITY", "identity_iam"),
        "serving": ("SERVING", "serving_network"), "k8s": ("KUBERNETES", "kubernetes_platform"),
        "supply": ("SUPPLY_CHAIN", "supply_chain"),
    }
    for source_id, (kind, category) in source_spec.items():
        signers[source_id] = ProducerSigner(source_id)
        policies.append(SourcePolicy(source_id, kind, signers[source_id].public_key, frozenset({category}), frozenset({"DETERMINISTIC_FIXTURE"})))
    store = EventStore(tmp_path / "correlation.sqlite")
    collector = CollectorService(SourceRegistry(tuple(policies)), store, DetectionEngine(store, rules))
    stages = [
        ("app", "PROMPT_INJECTION_BLOCKED"), ("app", "HIGH_IMPACT_TOOL_DENIED"),
        ("identity", "REVOKED_CREDENTIAL_REPLAY"), ("k8s", "PRIVILEGED_POD_DENIED"),
        ("supply", "POISONED_RELEASE_BLOCKED"),
    ]
    # Transport order differs from event-time order for the middle stages.
    for index in (1, 3, 2, 4, 5):
        if index == 5:
            # A later-event-time benign record is transported first. The final
            # attack stage then arrives late, but within freshness/skew bounds.
            collector.ingest(signers["serving"].sign(event("watermark-001", "SERVING_REQUEST_ALLOWED", "serving_network", "serving", "SERVING", 1_700_000_010, 99)), 1_700_000_010)
        source, event_type = stages[index - 1]
        kind, category = source_spec[source]
        result = collector.ingest(signers[source].sign(event(f"evt-{index:03}", event_type, category, source, kind, 1_700_000_000+index, index)), 1_700_000_010)
    assert "p11f.correlation.multi-stage-ai-attack" in result["alerts"]
    for index in range(3):
        collector.ingest(signers["serving"].sign(event(f"rate-{index}", "RATE_ABUSE_DENIED", "serving_network", "serving", "SERVING", 1_700_000_020+index, 20+index)), 1_700_000_030)
    assert any(a["rule_id"] == "p11f.serving.rate-abuse" for a in store.alert_rows())
    store.close()


@pytest.mark.parametrize("variation", ["tenant", "principal", "outside", "missing"])
def test_correlation_evasion_does_not_create_full_chain(tmp_path, variation) -> None:
    rules, _ = load_rules(ROOT / "detections/p11f")
    source = ProducerSigner("application-producer")
    registry = SourceRegistry((SourcePolicy(source.source_id, "APPLICATION", source.public_key, frozenset(CATEGORIES), frozenset({"DETERMINISTIC_FIXTURE"})),))
    store = EventStore(tmp_path / f"{variation}.sqlite")
    collector = CollectorService(registry, store, DetectionEngine(store, rules))
    stages = ["PROMPT_INJECTION_BLOCKED", "HIGH_IMPACT_TOOL_DENIED", "REVOKED_CREDENTIAL_REPLAY", "PRIVILEGED_POD_DENIED", "POISONED_RELEASE_BLOCKED"]
    if variation == "missing": stages.pop(2)
    for index, event_type in enumerate(stages):
        tenant = "other" if variation == "tenant" and index == 2 else "tenant-a"
        principal = "other" if variation == "principal" and index == 2 else "principal-a"
        timestamp = 1_700_000_000 + (400 if variation == "outside" and index == len(stages)-1 else index)
        collector.ingest(source.sign(event(f"evade-{index}", event_type, "application_agent", source.source_id, "APPLICATION", timestamp, index+1, tenant=tenant, principal=principal)), timestamp)
    assert not any(a["rule_id"] == "p11f.correlation.multi-stage-ai-attack" for a in store.alert_rows())
    store.close()


def test_assessment_metrics_hash_claim_debt_and_live_boundary() -> None:
    result = assess(execute_fixture(fixture()))
    assert result["ASR"]["numerator"] == result["FPR"]["numerator"] == 0
    assert result["DetectionRecall"]["numerator"] == result["DetectionRecall"]["denominator"]
    assert result["SafeTaskRate"]["numerator"] == result["SafeTaskRate"]["denominator"]
    assert result["Precision"]["value"] == 1
    tampered = copy.deepcopy(result); tampered["ASR"]["numerator"] = 1
    with pytest.raises(EvidenceRejected): validate_evidence(tampered)
    for key in ("production_siem_validation_claimed", "professional_mastery_complete"):
        raw = execute_fixture(fixture()); raw[key] = True
        with pytest.raises(EvidenceRejected): assess(raw)
    raw = execute_fixture(fixture()); raw["deferred_mastery_items"] = []
    with pytest.raises(EvidenceRejected): assess(raw)


def test_live_flag_requires_every_observed_gate_and_live_mode() -> None:
    raw = execute_fixture(fixture()); raw["execution_mode"] = "live"; raw["environment_classification"] = "LIVE_LOCAL_CODESPACE_K3D"
    for key in LIVE_GATE_NAMES: raw["live_gates"][key] = True
    for key in LIVE_DATA_NAMES: raw["live_gates"][key] = "a" * 64
    raw["live_gates"]["rule_bundle_sha256"] = raw["fixture_rule_bundle_sha256"]
    assert assess(raw)["live_local_detection_engineering_validated"] is True
    for gate in LIVE_GATE_NAMES:
        changed = copy.deepcopy(raw); changed["live_gates"][gate] = False
        assert assess(changed)["live_local_detection_engineering_validated"] is False
    assert assess(execute_fixture(fixture()))["live_local_detection_engineering_validated"] is False


def test_detector_execution_changes_quality_metrics_when_rules_change() -> None:
    from dataclasses import replace
    rules, _ = load_rules(ROOT / "detections/p11f")
    baseline = metric_summary(execute_cases(fixture()["case_definitions"], rules))
    application_removed = tuple(rule for rule in rules if rule.rule_id != "p11f.application.prompt-injection")
    escaped = metric_summary(execute_cases(fixture()["case_definitions"], application_removed))
    assert escaped["ASR"]["numerator"] > baseline["ASR"]["numerator"]
    assert escaped["DetectionRecall"]["numerator"] < baseline["DetectionRecall"]["numerator"]
    application = next(rule for rule in rules if rule.rule_id == "p11f.application.prompt-injection")
    overbroad = tuple(replace(rule,event_types=rule.event_types+("NORMAL_RAG_REQUEST",)) if rule is application else rule for rule in rules)
    noisy = metric_summary(execute_cases(fixture()["case_definitions"], overbroad))
    assert noisy["FPR"]["numerator"] > baseline["FPR"]["numerator"]
    assert noisy["SafeTaskRate"]["numerator"] < baseline["SafeTaskRate"]["numerator"]
    assert noisy["Precision"]["value"] < baseline["Precision"]["value"]


def test_fixture_producer_cannot_claim_stronger_provenance(tmp_path) -> None:
    signer, store, collector, _ = service(tmp_path)
    for index, provenance in enumerate(("LIVE_CONTROL_OBSERVATION","NATIVE_LIVE"),2):
        with pytest.raises(DetectionDenied, match="AUTHORIZATION"):
            collector.ingest(signer.sign(event(f"evt-{index:03}",sequence=index,provenance=provenance)),1_700_000_001)
    store.close()


def test_default_phase11_debt_is_latest() -> None:
    from scripts.verify_phase11 import default_summary
    assert default_summary()["deferred_mastery_items"] == list(DEFERRED_MASTERY_ITEMS)
    assert "p11f-production-siem-platform" in DEFERRED_MASTERY_ITEMS
