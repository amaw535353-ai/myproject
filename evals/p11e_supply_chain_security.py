from __future__ import annotations

import copy
import json

from aegis.platform.supply_chain_security import evidence_is_clean, sha256
from evals.p11e_fixture import DEFERRED_MASTERY_ITEMS, GROUPS, LIVE_DATA_NAMES, LIVE_GATE_NAMES, SCHEMA_VERSION, fixture, fixture_manifests_sha256

class EvidenceRejected(ValueError): pass
RAW_KEYS = ("phase", "schema_version", "execution_mode", "environment_classification", "fixture_manifests_sha256", "observations", "production_supply_chain_validation_claimed", "professional_mastery_complete", "deferred_mastery_items")

def assess(raw: dict) -> dict:
    if set(raw) != set(RAW_KEYS) or raw.get("phase") != "P11-E" or raw.get("schema_version") != SCHEMA_VERSION: raise EvidenceRejected("malformed schema")
    if raw["fixture_manifests_sha256"] != fixture_manifests_sha256(): raise EvidenceRejected("fixture integrity mismatch")
    if raw["production_supply_chain_validation_claimed"] or raw["professional_mastery_complete"]: raise EvidenceRejected("forbidden claim")
    if raw["deferred_mastery_items"] != list(DEFERRED_MASTERY_ITEMS): raise EvidenceRejected("mastery debt changed")
    obs = raw["observations"]
    if set(obs) != set(GROUPS) | {"live_gates"}: raise EvidenceRejected("observations malformed")
    cases = [c for g in GROUPS for c in obs[g]]
    if not cases or any(set(c) != {"case", "expected", "observed", "executed"} for c in cases): raise EvidenceRejected("case malformed")
    attacks = [c for c in cases if c["expected"] == "DENY"]; safe = [c for c in cases if c["expected"] == "ALLOW"]
    attack_success = sum(c["observed"] == "ALLOW" for c in attacks); safe_success = sum(c["observed"] == "ALLOW" for c in safe)
    gates = obs["live_gates"]
    schema = set(gates) == set(LIVE_GATE_NAMES) | set(LIVE_DATA_NAMES)
    hashes = schema and all(isinstance(gates.get(x), str) and len(gates[x]) == 64 for x in LIVE_DATA_NAMES)
    all_gates = schema and hashes and all(gates.get(x) is True for x in LIVE_GATE_NAMES)
    live = raw["execution_mode"] == "live" and all_gates and attack_success == 0 and safe_success == len(safe) and all(c["executed"] for c in cases)
    out = {"phase": "P11-E", "schema_version": SCHEMA_VERSION, "execution_mode": raw["execution_mode"], "environment_classification": raw["environment_classification"]}
    for group in GROUPS:
        out[group] = {"case_count": len(obs[group]), "incorrect_allows": sum(c["expected"] == "DENY" and c["observed"] == "ALLOW" for c in obs[group]), "incorrect_denies": sum(c["expected"] == "ALLOW" and c["observed"] == "DENY" for c in obs[group])}
    out.update({"ASR": {"numerator": attack_success, "denominator": len(attacks), "value": attack_success / len(attacks)},
                "FPR": {"numerator": len(safe)-safe_success, "denominator": len(safe), "value": (len(safe)-safe_success)/len(safe)},
                "SafeTaskRate": {"numerator": safe_success, "denominator": len(safe), "value": safe_success/len(safe)},
                "fixture_manifests_sha256": raw["fixture_manifests_sha256"], "raw_observations": copy.deepcopy(obs),
                "live_local_supply_chain_security_validated": live, "production_supply_chain_validation_claimed": False,
                "professional_mastery_complete": False, "deferred_mastery_items": list(DEFERRED_MASTERY_ITEMS)})
    if not evidence_is_clean(out): raise EvidenceRejected("sensitive material")
    out["assessment_sha256"] = sha256(out)
    return out

def validate_evidence(evidence: dict) -> dict:
    try: raw = {k: evidence[k] for k in RAW_KEYS}
    except KeyError as exc: raise EvidenceRejected("malformed schema") from exc
    recomputed = assess(raw)
    if evidence.get("assessment_sha256") not in (None, recomputed["assessment_sha256"]): raise EvidenceRejected("assessment hash mismatch")
    extras = {"preflight", "tooling", "container", "registry", "admission", "model", "incident"}
    for key in set(evidence) - set(RAW_KEYS) - {"assessment_sha256"} - extras:
        if evidence[key] != recomputed.get(key): raise EvidenceRejected("caller summary mismatch")
    return recomputed

def main() -> int:
    out = assess(fixture()); print(json.dumps(out, sort_keys=True))
    return 0 if out["ASR"]["numerator"] == out["FPR"]["numerator"] == 0 else 1

if __name__ == "__main__": raise SystemExit(main())
