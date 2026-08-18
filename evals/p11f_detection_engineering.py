from __future__ import annotations

import copy
import json

from aegis.detection.security_analytics import digest
from aegis.platform.serving_security import evidence_is_sensitive_material_free
from evals.p11f_fixture import (
    DEFERRED_MASTERY_ITEMS, DOMAINS, LIVE_DATA_NAMES, LIVE_GATE_NAMES,
    SCHEMA_VERSION, fixture, fixture_rule_bundle_sha256,
)


class EvidenceRejected(ValueError):
    pass


RAW_KEYS = {
    "phase", "schema_version", "execution_mode", "environment_classification",
    "fixture_rule_bundle_sha256", "raw_cases", "live_gates",
    "production_siem_validation_claimed", "professional_mastery_complete",
    "deferred_mastery_items",
}


def assess(raw: dict) -> dict:
    if set(raw) != RAW_KEYS or raw.get("phase") != "P11-F" or raw.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceRejected("malformed schema")
    if raw["fixture_rule_bundle_sha256"] != fixture_rule_bundle_sha256():
        raise EvidenceRejected("rule bundle integrity mismatch")
    if raw["production_siem_validation_claimed"] or raw["professional_mastery_complete"]:
        raise EvidenceRejected("forbidden claim")
    if raw["deferred_mastery_items"] != list(DEFERRED_MASTERY_ITEMS):
        raise EvidenceRejected("mastery debt changed")
    cases = raw["raw_cases"]
    if not isinstance(cases, list) or not cases or any(set(c) != {"case", "domain", "expected", "observed", "executed"} for c in cases):
        raise EvidenceRejected("cases malformed")
    malicious = [c for c in cases if c["expected"] == "ALERT"]
    benign = [c for c in cases if c["expected"] == "NO_HIGH_ALERT"]
    if not malicious or not benign or not set(DOMAINS).issubset({c["domain"] for c in malicious}):
        raise EvidenceRejected("coverage malformed")
    escaped = sum(c["observed"] != "ALERT" for c in malicious)
    detected = len(malicious) - escaped
    false_alerts = sum(c["observed"] != "NO_HIGH_ALERT" for c in benign)
    true_alerts = detected
    all_alerts = true_alerts + false_alerts
    gates = raw["live_gates"]
    gate_schema = set(gates) == set(LIVE_GATE_NAMES) | set(LIVE_DATA_NAMES)
    hash_data = gate_schema and all(isinstance(gates.get(x), str) and len(gates[x]) == 64 for x in LIVE_DATA_NAMES)
    mandatory = gate_schema and hash_data and all(gates.get(x) is True for x in LIVE_GATE_NAMES)
    live = raw["execution_mode"] == "live" and mandatory and escaped == false_alerts == 0 and all(c["executed"] for c in cases)
    out = {
        "phase": "P11-F", "schema_version": SCHEMA_VERSION,
        "execution_mode": raw["execution_mode"],
        "environment_classification": raw["environment_classification"],
        "malicious_sequence_count": len(malicious), "benign_sequence_count": len(benign),
        "ASR": {"numerator": escaped, "denominator": len(malicious), "value": escaped / len(malicious)},
        "DetectionRecall": {"numerator": detected, "denominator": len(malicious), "value": detected / len(malicious)},
        "FPR": {"numerator": false_alerts, "denominator": len(benign), "value": false_alerts / len(benign)},
        "SafeTaskRate": {"numerator": len(benign)-false_alerts, "denominator": len(benign), "value": (len(benign)-false_alerts) / len(benign)},
        "Precision": {"numerator": true_alerts, "denominator": all_alerts, "value": true_alerts / all_alerts},
        "fixture_rule_bundle_sha256": raw["fixture_rule_bundle_sha256"],
        "raw_cases": copy.deepcopy(cases), "live_gates": copy.deepcopy(gates),
        "live_local_detection_engineering_validated": live,
        "production_siem_validation_claimed": False, "professional_mastery_complete": False,
        "deferred_mastery_items": list(DEFERRED_MASTERY_ITEMS),
    }
    if not evidence_is_sensitive_material_free(out):
        raise EvidenceRejected("sensitive material")
    out["assessment_sha256"] = digest(out)
    return out


def validate_evidence(evidence: dict) -> dict:
    try:
        raw = {key: evidence[key] for key in RAW_KEYS}
    except KeyError as exc:
        raise EvidenceRejected("malformed schema") from exc
    expected = assess(raw)
    for key, value in expected.items():
        if evidence.get(key) != value:
            raise EvidenceRejected("caller summary or integrity mismatch")
    return expected


def main() -> int:
    result = assess(fixture())
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ASR"]["numerator"] == result["FPR"]["numerator"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
