from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from aegis.platform.serving_security import evidence_is_sensitive_material_free

EVENT_SCHEMA = "aegis.security-detection-event.v1"
POLICY_VERSION = "p11f-detection-policy.v1"
MAX_EVENT_BYTES = 4096
MAX_STRING = 128
MAX_ATTRIBUTES = 8
MAX_ATTRIBUTE_KEY = 32
MAX_ATTRIBUTE_VALUE = 128
MAX_FUTURE_SKEW = 30
MAX_STALE_AGE = 3600
REF = re.compile(r"^(?:ref|hmac-sha256):[a-z0-9._:-]{3,96}$")
TOKEN = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")
ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{2,95}$")
PROVENANCE = {"NATIVE_LIVE", "LIVE_CONTROL_OBSERVATION", "DETERMINISTIC_FIXTURE"}
CATEGORIES = {"application_agent", "identity_iam", "serving_network", "kubernetes_platform", "supply_chain"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}


class DetectionDenied(ValueError):
    def __init__(self, reason: str) -> None: super().__init__(reason); self.reason = reason


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(value if isinstance(value, bytes) else canonical_bytes(value)).hexdigest()


def safe_ref(domain: str, value: str, key: bytes) -> str:
    import hmac
    return "hmac-sha256:" + hmac.new(key, (domain + "\0" + value).encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class SecurityEvent:
    schema_version: str; event_id: str; event_time: int; source_id: str; source_kind: str
    event_type: str; category: str; action: str; outcome: str; severity: str; reason_code: str
    tenant_ref: str; principal_ref: str; workload_ref: str; namespace_ref: str; resource_ref: str
    request_ref: str; session_ref: str; trace_ref: str; policy_version: str; sequence: int
    provenance_classification: str; attributes: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SecurityEvent":
        names = set(cls.__dataclass_fields__)
        if not isinstance(value, Mapping) or set(value) != names: raise DetectionDenied("EVENT_SCHEMA_INVALID")
        data = dict(value)
        attrs = data["attributes"]
        if not isinstance(attrs, dict) or len(attrs) > MAX_ATTRIBUTES: raise DetectionDenied("ATTRIBUTES_INVALID")
        for key, item in attrs.items():
            if not isinstance(key, str) or not isinstance(item, str) or len(key) > MAX_ATTRIBUTE_KEY or len(item) > MAX_ATTRIBUTE_VALUE or not ID.fullmatch(key): raise DetectionDenied("ATTRIBUTES_INVALID")
        data["attributes"] = tuple(sorted(attrs.items()))
        event = cls(**data)
        event.validate()
        return event

    def validate(self) -> None:
        if self.schema_version != EVENT_SCHEMA or self.policy_version != POLICY_VERSION: raise DetectionDenied("EVENT_SCHEMA_INVALID")
        for name in ("event_id", "source_id"):
            if not ID.fullmatch(getattr(self, name)): raise DetectionDenied("EVENT_IDENTITY_INVALID")
        if self.category not in CATEGORIES or self.severity not in SEVERITIES or self.provenance_classification not in PROVENANCE: raise DetectionDenied("EVENT_ENUM_INVALID")
        for name in ("event_type", "action", "outcome", "reason_code", "source_kind"):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) > MAX_STRING or not TOKEN.fullmatch(value): raise DetectionDenied("EVENT_TOKEN_INVALID")
        for name in ("tenant_ref", "principal_ref", "workload_ref", "namespace_ref", "resource_ref", "request_ref", "session_ref", "trace_ref"):
            if not REF.fullmatch(getattr(self, name)): raise DetectionDenied("EVENT_REFERENCE_INVALID")
        if not isinstance(self.event_time, int) or not isinstance(self.sequence, int) or self.sequence < 1: raise DetectionDenied("EVENT_TIME_SEQUENCE_INVALID")
        rendered = canonical_bytes(self.to_dict())
        if len(rendered) > MAX_EVENT_BYTES: raise DetectionDenied("EVENT_TOO_LARGE")
        if any(ord(ch) < 32 for ch in rendered.decode()): raise DetectionDenied("CONTROL_CHARACTER_DENIED")
        if not evidence_is_sensitive_material_free(self.to_dict()): raise DetectionDenied("SENSITIVE_MATERIAL_DENIED")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self); value["attributes"] = dict(self.attributes); return value


@dataclass(frozen=True)
class SignedEventEnvelope:
    source_id: str; event_id: str; event_time: int; sequence: int; body_sha256: str; body: dict[str, Any]; signature: str


class ProducerSigner:
    def __init__(self, source_id: str, key: Ed25519PrivateKey | None = None) -> None: self.source_id, self._key = source_id, key or Ed25519PrivateKey.generate()
    @property
    def public_key(self) -> bytes: return self._key.public_key().public_bytes_raw()
    def sign(self, event: SecurityEvent) -> SignedEventEnvelope:
        body = event.to_dict(); material = {"source_id": self.source_id, "event_id": event.event_id, "event_time": event.event_time, "sequence": event.sequence, "body_sha256": digest(body)}
        return SignedEventEnvelope(**material, body=body, signature=base64.b64encode(self._key.sign(canonical_bytes(material))).decode())

    def sign_raw(self, body: Mapping[str, Any]) -> SignedEventEnvelope:
        """Sign an intentionally untrusted body for collector-negative tests."""
        material = {
            "source_id": self.source_id,
            "event_id": body.get("event_id", "invalid-event"),
            "event_time": body.get("event_time", 0),
            "sequence": body.get("sequence", 0),
            "body_sha256": digest(body),
        }
        return SignedEventEnvelope(
            **material,
            body=dict(body),
            signature=base64.b64encode(
                self._key.sign(canonical_bytes(material))
            ).decode(),
        )


@dataclass(frozen=True)
class SourcePolicy:
    source_id: str; source_kind: str; public_key: bytes; allowed_categories: frozenset[str]; allowed_provenance: frozenset[str]


class SourceRegistry:
    def __init__(self, policies: tuple[SourcePolicy, ...]) -> None:
        self.policies = {p.source_id: p for p in policies}
        if len(self.policies) != len(policies): raise DetectionDenied("DUPLICATE_SOURCE")

    def verify(self, envelope: SignedEventEnvelope, now: int) -> SecurityEvent:
        policy = self.policies.get(envelope.source_id)
        if not policy: raise DetectionDenied("SOURCE_UNKNOWN")
        event = SecurityEvent.from_dict(envelope.body)
        material = {"source_id": envelope.source_id, "event_id": envelope.event_id, "event_time": envelope.event_time, "sequence": envelope.sequence, "body_sha256": envelope.body_sha256}
        if envelope.body_sha256 != digest(envelope.body) or (event.event_id, event.event_time, event.sequence, event.source_id) != (envelope.event_id, envelope.event_time, envelope.sequence, envelope.source_id): raise DetectionDenied("ENVELOPE_BINDING_INVALID")
        try: Ed25519PublicKey.from_public_bytes(policy.public_key).verify(base64.b64decode(envelope.signature, validate=True), canonical_bytes(material))
        except (ValueError, InvalidSignature) as exc: raise DetectionDenied("SIGNATURE_INVALID") from exc
        if event.source_kind != policy.source_kind or event.category not in policy.allowed_categories or event.provenance_classification not in policy.allowed_provenance: raise DetectionDenied("SOURCE_AUTHORIZATION_DENIED")
        if event.event_time > now + MAX_FUTURE_SKEW: raise DetectionDenied("EVENT_FUTURE")
        if event.event_time < now - MAX_STALE_AGE: raise DetectionDenied("EVENT_STALE")
        return event


@dataclass(frozen=True)
class Rule:
    rule_id: str; title: str; version: int; enabled: bool; severity: str; domain: str; kind: str
    event_types: tuple[str, ...]; window_seconds: int; group_by: tuple[str, ...]; threshold: int; response_category: str


def load_rules(directory: Path) -> tuple[tuple[Rule, ...], str]:
    raw = [json.loads(path.read_text()) for path in sorted(directory.glob("*.json"))]
    if not raw: raise DetectionDenied("RULES_MISSING")
    allowed = set(Rule.__dataclass_fields__); rules = []
    for item in raw:
        if set(item) != allowed: raise DetectionDenied("RULE_SCHEMA_INVALID")
        try: rule = Rule(**{**item, "event_types": tuple(item["event_types"]), "group_by": tuple(item["group_by"])})
        except TypeError as exc: raise DetectionDenied("RULE_SCHEMA_INVALID") from exc
        if not ID.fullmatch(rule.rule_id) or rule.severity not in SEVERITIES or rule.domain not in CATEGORIES | {"cross_source_correlation"} or rule.kind not in {"single", "threshold", "correlation"} or rule.window_seconds < 1 or rule.window_seconds > 3600 or rule.threshold < 1 or not rule.group_by or not rule.enabled: raise DetectionDenied("RULE_POLICY_INVALID")
        if rule.kind == "correlation" and len(rule.event_types) < 3: raise DetectionDenied("RULE_CORRELATION_INVALID")
        rules.append(rule)
    if len({r.rule_id for r in rules}) != len(rules): raise DetectionDenied("RULE_ID_DUPLICATE")
    if {r.domain for r in rules} != CATEGORIES | {"cross_source_correlation"}: raise DetectionDenied("RULE_DOMAIN_COVERAGE")
    return tuple(rules), digest(raw)


class EventStore:
    def __init__(self, path: Path) -> None:
        self.path = path; self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
        CREATE TABLE events(store_order INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,event_time INTEGER NOT NULL,source_id TEXT NOT NULL,category TEXT NOT NULL,payload TEXT NOT NULL,chain_hash TEXT NOT NULL);
        CREATE INDEX events_group_time ON events(event_time,category);
        CREATE TABLE alerts(alert_id TEXT PRIMARY KEY,rule_id TEXT NOT NULL,dedup_key TEXT UNIQUE NOT NULL,severity TEXT NOT NULL,first_time INTEGER NOT NULL,last_time INTEGER NOT NULL,event_refs TEXT NOT NULL,detection_sequence INTEGER NOT NULL,chain_hash TEXT NOT NULL);
        """)
        self.stats = {"attempted": 0, "accepted": 0, "rejected": 0, "deduplicated": 0, "replayed": 0, "alert_candidates": 0, "alerts_created": 0, "alerts_deduplicated": 0}

    def append(self, event: SecurityEvent) -> tuple[bool, int]:
        payload = canonical_bytes(event.to_dict()).decode()
        with self.lock:
            self.stats["attempted"] += 1
            prior = self.db.execute("SELECT chain_hash FROM events ORDER BY store_order DESC LIMIT 1").fetchone()
            chain = digest(b"p11f-event-chain\0" + bytes.fromhex(prior[0] if prior else "0"*64) + payload.encode())
            try:
                with self.db: cur = self.db.execute("INSERT INTO events(event_id,event_time,source_id,category,payload,chain_hash) VALUES(?,?,?,?,?,?)", (event.event_id,event.event_time,event.source_id,event.category,payload,chain))
            except sqlite3.IntegrityError:
                self.stats["deduplicated"] += 1; self.stats["replayed"] += 1; return False, 0
            self.stats["accepted"] += 1; return True, int(cur.lastrowid)

    def events(self) -> list[tuple[int, SecurityEvent]]:
        return [(row[0], SecurityEvent.from_dict(json.loads(row[1]))) for row in self.db.execute("SELECT store_order,payload FROM events ORDER BY event_time,store_order")]

    def verify_event_chain(self) -> str:
        prior = "0"*64
        for order, payload, stored in self.db.execute("SELECT store_order,payload,chain_hash FROM events ORDER BY store_order"):
            expected = digest(b"p11f-event-chain\0" + bytes.fromhex(prior) + payload.encode())
            if stored != expected: raise DetectionDenied("EVENT_CHAIN_TAMPERED")
            prior = stored
        return prior

    def persist_alert(self, rule: Rule, events: list[SecurityEvent], sequence: int) -> bool:
        refs = sorted({e.event_id for e in events}); first=min(e.event_time for e in events); last=max(e.event_time for e in events)
        grouping = tuple(getattr(events[-1], x) for x in rule.group_by); bucket = first // rule.window_seconds
        dedup = digest({"rule":rule.rule_id,"group":grouping,"bucket":bucket}); alert_id="alert-"+dedup[:24]
        self.stats["alert_candidates"] += 1
        prior = self.db.execute("SELECT chain_hash FROM alerts ORDER BY detection_sequence DESC LIMIT 1").fetchone(); material={"alert_id":alert_id,"rule_id":rule.rule_id,"severity":rule.severity,"first":first,"last":last,"event_refs":refs,"sequence":sequence}
        chain=digest(b"p11f-alert-chain\0"+bytes.fromhex(prior[0] if prior else "0"*64)+canonical_bytes(material))
        try:
            with self.db: self.db.execute("INSERT INTO alerts VALUES(?,?,?,?,?,?,?,?,?)",(alert_id,rule.rule_id,dedup,rule.severity,first,last,json.dumps(refs),sequence,chain))
            self.stats["alerts_created"] += 1; return True
        except sqlite3.IntegrityError:
            # Keep the originally chained alert immutable. Aggregation counters are
            # tracked separately so deduplication cannot invalidate the alert chain.
            self.stats["alerts_deduplicated"] += 1; return False

    def alert_rows(self) -> list[dict[str, Any]]:
        return [{"alert_id":r[0],"rule_id":r[1],"severity":r[2],"first_event_time":r[3],"last_event_time":r[4],"event_refs":json.loads(r[5]),"detection_sequence":r[6],"chain_hash":r[7]} for r in self.db.execute("SELECT alert_id,rule_id,severity,first_time,last_time,event_refs,detection_sequence,chain_hash FROM alerts ORDER BY detection_sequence")]

    def verify_alert_chain(self) -> str:
        prior="0"*64
        for row in self.alert_rows():
            stored=row.pop("chain_hash"); material={"alert_id":row["alert_id"],"rule_id":row["rule_id"],"severity":row["severity"],"first":row["first_event_time"],"last":row["last_event_time"],"event_refs":row["event_refs"],"sequence":row["detection_sequence"]}
            expected=digest(b"p11f-alert-chain\0"+bytes.fromhex(prior)+canonical_bytes(material))
            if stored != expected: raise DetectionDenied("ALERT_CHAIN_TAMPERED")
            prior=stored
        return prior

    def snapshot_sha256(self) -> str:
        return digest({"events":[r for r in self.db.execute("SELECT * FROM events ORDER BY store_order")],"alerts":[r for r in self.db.execute("SELECT * FROM alerts ORDER BY detection_sequence")]})
    def close(self) -> None: self.db.close()


class DetectionEngine:
    def __init__(self, store: EventStore, rules: tuple[Rule, ...]) -> None: self.store,self.rules=store,rules
    def evaluate(self, current: SecurityEvent, sequence: int) -> list[str]:
        created=[]; ordered=self.store.events()
        for rule in self.rules:
            relevant=[e for _,e in ordered if current.event_time-rule.window_seconds <= e.event_time <= current.event_time and all(getattr(e,x)==getattr(current,x) for x in rule.group_by)]
            matched=[]
            if rule.kind=="single" and current.event_type in rule.event_types: matched=[current]
            elif rule.kind=="threshold":
                matched=[e for e in relevant if e.event_type in rule.event_types]
                if len(matched)<rule.threshold: matched=[]
            elif rule.kind=="correlation":
                cursor=-1; stages=[]
                for event_type in rule.event_types:
                    found=next(((i,e) for i,e in enumerate(relevant) if i>cursor and e.event_type==event_type),None)
                    if not found: stages=[]; break
                    cursor,event=found; stages.append(event)
                matched=stages
            if matched:
                if self.store.persist_alert(rule,matched,sequence): created.append(rule.rule_id)
        return created


class CollectorService:
    def __init__(self, registry: SourceRegistry, store: EventStore, engine: DetectionEngine) -> None: self.registry,self.store,self.engine=registry,store,engine
    def ingest(self, envelope: SignedEventEnvelope, now: int) -> dict[str, Any]:
        try: event=self.registry.verify(envelope,now); accepted,order=self.store.append(event)
        except DetectionDenied:
            self.store.stats["attempted"]+=1; self.store.stats["rejected"]+=1; raise
        if not accepted: return {"status":"DEDUPLICATED","alerts":[]}
        return {"status":"ACCEPTED","alerts":self.engine.evaluate(event,order)}


def create_collector_app(service: CollectorService):
    app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
    @app.get("/healthz")
    def healthz(): return {"status":"ok"}
    @app.get("/readyz")
    def readyz(): return {"status":"ready"}
    @app.post("/v1/security-events")
    async def ingest(request: Request):
        body=await request.body()
        if len(body)>MAX_EVENT_BYTES*2: return JSONResponse({"reason":"BODY_TOO_LARGE"},status_code=413)
        try:
            data=json.loads(body); envelope=SignedEventEnvelope(**data); result=service.ingest(envelope,int(request.headers.get("x-p11f-now","0")))
            return JSONResponse(result,status_code=200 if result["status"]=="ACCEPTED" else 202)
        except (json.JSONDecodeError,TypeError): return JSONResponse({"reason":"MALFORMED"},status_code=400)
        except DetectionDenied as exc: return JSONResponse({"reason":exc.reason},status_code=403)
    return app
