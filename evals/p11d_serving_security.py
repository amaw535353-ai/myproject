from __future__ import annotations

import copy
import json

from aegis.platform.serving_security import digest
from evals.p11d_fixture import DEFERRED_MASTERY_ITEMS, GROUPS, LIVE_DATA_NAMES, LIVE_GATE_NAMES, SCHEMA_VERSION, fixture, fixture_manifests_sha256


class EvidenceRejected(ValueError): pass


def assess(raw: dict) -> dict:
    required = {"phase", "schema_version", "execution_mode", "environment_classification", "fixture_manifests_sha256", "observations", "production_serving_validation_claimed", "professional_mastery_complete", "deferred_mastery_items"}
    if set(raw) != required or raw.get("phase") != "P11-D" or raw.get("schema_version") != SCHEMA_VERSION: raise EvidenceRejected("malformed schema")
    if raw["fixture_manifests_sha256"] != fixture_manifests_sha256(): raise EvidenceRejected("fixture integrity mismatch")
    if raw["production_serving_validation_claimed"] or raw["professional_mastery_complete"]: raise EvidenceRejected("forbidden claim")
    if raw["deferred_mastery_items"] != list(DEFERRED_MASTERY_ITEMS): raise EvidenceRejected("mastery debt changed")
    obs = raw["observations"]
    if set(obs) != set(GROUPS) | {"live_gates"}: raise EvidenceRejected("observations malformed")
    cases = [c for g in GROUPS for c in obs[g]]
    if not cases or any(set(c) != {"case", "expected", "observed", "executed"} for c in cases): raise EvidenceRejected("case malformed")
    attacks = [c for c in cases if c["expected"] == "DENY"]; safe = [c for c in cases if c["expected"] == "ALLOW"]
    successes = sum(c["observed"] == "ALLOW" for c in attacks); safe_ok = sum(c["observed"] == "ALLOW" for c in safe)
    gates = obs["live_gates"]; schema = set(gates) == set(LIVE_GATE_NAMES) | set(LIVE_DATA_NAMES)
    flags = schema and all(gates.get(x) is True for x in LIVE_GATE_NAMES)
    hashes = schema and all(len(gates.get(x, "")) == 64 for x in ("ca_sha256", "server_cert_sha256", "client_cert_sha256"))
    rate = schema and gates.get("rate_attempts") == gates.get("rate_allowed") + gates.get("rate_limited") and gates.get("rate_limited", 0) > 0
    live = raw["execution_mode"] == "live" and flags and hashes and rate and successes == 0 and safe_ok == len(safe) and all(c["executed"] for c in cases)
    summaries = {g: {"case_count": len(obs[g]), "incorrect_allows": sum(c["expected"] == "DENY" and c["observed"] == "ALLOW" for c in obs[g]), "incorrect_denies": sum(c["expected"] == "ALLOW" and c["observed"] == "DENY" for c in obs[g])} for g in GROUPS}
    out = {"phase": "P11-D", "schema_version": SCHEMA_VERSION, "execution_mode": raw["execution_mode"], "environment_classification": raw["environment_classification"],
           **summaries, "ASR": {"numerator": successes, "denominator": len(attacks), "value": successes / len(attacks)},
           "FPR": {"numerator": len(safe)-safe_ok, "denominator": len(safe), "value": (len(safe)-safe_ok)/len(safe)},
           "SafeTaskRate": {"numerator": safe_ok, "denominator": len(safe), "value": safe_ok/len(safe)},
           "fixture_manifests_sha256": raw["fixture_manifests_sha256"], "raw_observations": copy.deepcopy(obs),
           "live_local_serving_security_validated": live, "production_serving_validation_claimed": False,
           "professional_mastery_complete": False, "deferred_mastery_items": list(DEFERRED_MASTERY_ITEMS)}
    serialized = json.dumps(out, sort_keys=True).lower()
    if "private key-----" in serialized or "authorization: bearer" in serialized: raise EvidenceRejected("sensitive material")
    out["assessment_sha256"] = digest(out)
    return out


def validate_evidence(evidence: dict) -> dict:
    raw_keys = ("phase", "schema_version", "execution_mode", "environment_classification", "fixture_manifests_sha256", "observations", "production_serving_validation_claimed", "professional_mastery_complete", "deferred_mastery_items")
    recomputed = assess({k: evidence[k] for k in raw_keys if k in evidence})
    if evidence.get("assessment_sha256") not in (None, recomputed["assessment_sha256"]): raise EvidenceRejected("assessment hash mismatch")
    for key in set(evidence) - set(raw_keys) - {"assessment_sha256", "preflight", "certificate_metadata"}:
        if evidence[key] != recomputed.get(key): raise EvidenceRejected("caller summary mismatch")
    return recomputed


def main() -> int:
    result = assess(fixture()); print(json.dumps(result, sort_keys=True))
    return 0 if result["ASR"]["numerator"] == result["FPR"]["numerator"] == 0 else 1


if __name__ == "__main__": raise SystemExit(main())
