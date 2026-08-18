from __future__ import annotations

import base64
import copy
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from aegis.platform.serving_security import evidence_is_sensitive_material_free


POLICY_VERSION = "p11e-supply-chain-policy.v1"


class SupplyChainDenied(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(value: object) -> str:
    payload = value if isinstance(value, bytes) else canonical_bytes(value)
    return hashlib.sha256(payload).hexdigest()


def _depth(value: object, level: int = 0) -> int:
    if isinstance(value, dict):
        return max([level] + [_depth(v, level + 1) for v in value.values()])
    if isinstance(value, list):
        return max([level] + [_depth(v, level + 1) for v in value])
    return level


class LiveArtifactSafetyScanner:
    """Bounded inspection of safe metadata; model weights are never deserialized."""

    FORBIDDEN_MARKERS = ("cf_trigger", "poison_trigger", "backdoor_trigger", "trust_remote_code")
    UNSAFE_FORMATS = ("pickle", "pkl", "pt", "pth", "bin")

    def __init__(self, *, max_bytes: int = 65536, max_depth: int = 12) -> None:
        self.max_bytes, self.max_depth = max_bytes, max_depth

    def scan_json(self, payload: bytes, *, expected_sha256: str) -> dict[str, Any]:
        if len(payload) > self.max_bytes: raise SupplyChainDenied("CONTENT_TOO_LARGE")
        if sha256(payload) != expected_sha256: raise SupplyChainDenied("CONTENT_DIGEST_MISMATCH")
        try: value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise SupplyChainDenied("CONTENT_MALFORMED") from exc
        if _depth(value) > self.max_depth: raise SupplyChainDenied("CONTENT_TOO_DEEP")
        lowered = canonical_bytes(value).decode().casefold()
        if any(marker in lowered for marker in self.FORBIDDEN_MARKERS): raise SupplyChainDenied("POISON_MARKER")
        return {"sha256": expected_sha256, "safe": True, "executed": False}

    def inspect_opaque(self, payload: bytes, *, artifact_format: str, expected_sha256: str) -> dict[str, Any]:
        if artifact_format.casefold().lstrip(".") in self.UNSAFE_FORMATS: raise SupplyChainDenied("UNSAFE_SERIALIZATION")
        if len(payload) > self.max_bytes or sha256(payload) != expected_sha256: raise SupplyChainDenied("OPAQUE_BINDING_INVALID")
        return {"sha256": expected_sha256, "safe": True, "executed": False, "deserialized": False}


def validate_sbom(sbom: Mapping[str, Any], *, expected_image_digest: str) -> dict[str, Any]:
    if not isinstance(sbom, Mapping): raise SupplyChainDenied("SBOM_MALFORMED")
    metadata = sbom.get("metadata")
    components = sbom.get("components")
    if not isinstance(metadata, Mapping) or not isinstance(components, list): raise SupplyChainDenied("SBOM_MALFORMED")
    component = metadata.get("component")
    refs = component.get("externalReferences", []) if isinstance(component, Mapping) else []
    subjects = {r.get("url") for r in refs if isinstance(r, Mapping)}
    props = metadata.get("properties", [])
    subjects.update(p.get("value") for p in props if isinstance(p, Mapping) and p.get("name") == "aegisdesk:image-digest")
    if expected_image_digest not in subjects: raise SupplyChainDenied("SBOM_SUBJECT_MISMATCH")
    if any(not isinstance(c, Mapping) or not c.get("name") or not c.get("type") for c in components):
        raise SupplyChainDenied("SBOM_PACKAGE_METADATA_MISSING")
    return {"format": "CycloneDX JSON", "component_count": len(components), "sha256": sha256(sbom), "subject_verified": True}


def evaluate_vulnerability_report(report: Mapping[str, Any], *, expected_image_digest: str, db_usable: bool) -> dict[str, Any]:
    if not db_usable: raise SupplyChainDenied("SCANNER_DATABASE_UNUSABLE")
    if report.get("source", {}).get("target", {}).get("userInput") != expected_image_digest:
        raise SupplyChainDenied("SCANNER_SUBJECT_MISMATCH")
    matches = report.get("matches")
    if not isinstance(matches, list): raise SupplyChainDenied("SCANNER_REPORT_MALFORMED")
    counts = {x: 0 for x in ("critical", "high", "medium", "low", "negligible", "unknown")}
    blocking = []
    for match in matches:
        vuln = match.get("vulnerability", {}) if isinstance(match, Mapping) else {}
        severity = str(vuln.get("severity", "unknown")).casefold()
        counts[severity if severity in counts else "unknown"] += 1
        fixes = vuln.get("fix", {}).get("versions", [])
        if severity == "critical" or (severity == "high" and bool(fixes)): blocking.append(vuln.get("id", "unknown"))
    return {"severity_counts": counts, "policy_blocking_findings": blocking, "admitted": not blocking, "sha256": sha256(report)}


@dataclass(frozen=True)
class SignedEnvelope:
    payload: dict[str, Any]
    signature: str


class Ed25519EnvelopeSigner:
    def __init__(self, private_key: Ed25519PrivateKey | None = None) -> None:
        self._private = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> bytes:
        return self._private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    @property
    def fingerprint(self) -> str: return sha256(self.public_key)

    def sign(self, payload: Mapping[str, Any]) -> SignedEnvelope:
        data = copy.deepcopy(dict(payload))
        return SignedEnvelope(data, base64.b64encode(self._private.sign(canonical_bytes(data))).decode())


def verify_envelope(envelope: SignedEnvelope, public_key: bytes) -> dict[str, Any]:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(base64.b64decode(envelope.signature, validate=True), canonical_bytes(envelope.payload))
    except (InvalidSignature, ValueError) as exc: raise SupplyChainDenied("SIGNATURE_INVALID") from exc
    return copy.deepcopy(envelope.payload)


def verify_provenance(envelope: SignedEnvelope, public_key: bytes, *, source_commit: str, image_digest: str,
                      sbom_sha256: str, scanner_sha256: str) -> dict[str, Any]:
    value = verify_envelope(envelope, public_key)
    expected = {"source_commit": source_commit, "image_digest": image_digest, "sbom_sha256": sbom_sha256,
                "scanner_report_sha256": scanner_sha256, "policy_version": POLICY_VERSION}
    if any(value.get(k) != v for k, v in expected.items()): raise SupplyChainDenied("PROVENANCE_BINDING_MISMATCH")
    return value


def verify_receipt(envelope: SignedEnvelope, public_key: bytes, *, image: str, now: int | None = None) -> dict[str, Any]:
    value = verify_envelope(envelope, public_key)
    now = int(time.time()) if now is None else now
    if value.get("policy_version") != POLICY_VERSION: raise SupplyChainDenied("RECEIPT_POLICY_INVALID")
    if value.get("image") != image or "@sha256:" not in image: raise SupplyChainDenied("RECEIPT_IMAGE_MISMATCH")
    if not isinstance(value.get("issued_at"), int) or not isinstance(value.get("expires_at"), int) or not value["issued_at"] <= now < value["expires_at"]:
        raise SupplyChainDenied("RECEIPT_EXPIRED")
    for key in ("sbom_sha256", "scanner_report_sha256", "provenance_sha256", "signer_fingerprint"):
        if not isinstance(value.get(key), str) or len(value[key]) != 64: raise SupplyChainDenied("RECEIPT_MALFORMED")
    return value


class QuarantineRegistry:
    def __init__(self) -> None: self._entries: dict[str, dict[str, Any]] = {}
    def quarantine(self, digest: str, *, reason: str, incident_id: str, order: int) -> None:
        if len(digest) != 64: raise SupplyChainDenied("QUARANTINE_DIGEST_INVALID")
        self._entries[digest] = {"digest": digest, "reason_code": reason, "detector": "p11e-live-content-scan",
                                 "policy_version": POLICY_VERSION, "incident_id": incident_id, "quarantined_at_order": order, "status": "QUARANTINED"}
    def require_allowed(self, digest: str) -> None:
        if digest in self._entries: raise SupplyChainDenied("RELEASE_QUARANTINED")
    def evidence(self) -> list[dict[str, Any]]: return [copy.deepcopy(self._entries[k]) for k in sorted(self._entries)]


def cache_read(cache: Mapping[str, bytes], immutable_key: str, expected_digest: str) -> bytes:
    value = cache.get(immutable_key)
    if value is None or sha256(value) != expected_digest: raise SupplyChainDenied("CACHE_SUBSTITUTION")
    return value


def evidence_is_clean(payload: object) -> bool:
    return evidence_is_sensitive_material_free(payload)
