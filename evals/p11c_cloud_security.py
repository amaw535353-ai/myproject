from __future__ import annotations

import copy
import json

from aegis.platform.cloud_security import AuditTrail, SecurityDenied, digest
from evals.p11c_fixture import DEFERRED_MASTERY_ITEMS, SCHEMA_VERSION, fixture, fixture_manifests_sha256


class EvidenceRejected(ValueError):
    pass


GROUPS = ("identity", "iam", "kms", "secrets", "metadata")
SENSITIVE_MARKERS = ("synthetic-secret-v1", "synthetic-secret-v2", "authorization: bearer", "private_key_material", "serviceaccount_jwt_value")


def assess(raw: dict) -> dict:
    required = {"phase", "schema_version", "execution_mode", "environment_classification", "fixture_manifests_sha256", "observations", "audit", "production_cloud_validation_claimed", "professional_mastery_complete", "deferred_mastery_items"}
    if set(raw) != required or raw.get("phase") != "P11-C" or raw.get("schema_version") != SCHEMA_VERSION:
        raise EvidenceRejected("malformed schema")
    if raw["fixture_manifests_sha256"] != fixture_manifests_sha256(): raise EvidenceRejected("fixture integrity mismatch")
    if raw["production_cloud_validation_claimed"] or raw["professional_mastery_complete"]: raise EvidenceRejected("forbidden claim")
    if raw["deferred_mastery_items"] != list(DEFERRED_MASTERY_ITEMS): raise EvidenceRejected("mastery debt changed")
    obs = raw["observations"]
    if set(obs) != set(GROUPS) | {"incident_response", "live_gates"}: raise EvidenceRejected("observations malformed")
    cases = [case for group in GROUPS for case in obs[group]]
    if not cases or any(set(case) != {"case", "expected", "observed", "executed"} for case in cases): raise EvidenceRejected("case malformed")
    attacks = [c for c in cases if c["expected"] == "DENY"]
    safe = [c for c in cases if c["expected"] == "ALLOW"]
    successful_attacks = sum(c["observed"] == "ALLOW" for c in attacks)
    safe_pass = sum(c["observed"] == "ALLOW" for c in safe)
    summaries = {}
    for group in GROUPS:
        g = obs[group]
        summaries[group] = {"cases": len(g), "incorrect_allows": sum(c["expected"] == "DENY" and c["observed"] == "ALLOW" for c in g), "incorrect_denies": sum(c["expected"] == "ALLOW" and c["observed"] == "DENY" for c in g)}
    try:
        audit_head = AuditTrail.validate(raw["audit"]["events"])
    except SecurityDenied as exc:
        raise EvidenceRejected("audit hash-chain mismatch") from exc
    if audit_head != raw["audit"].get("head"): raise EvidenceRejected("audit head mismatch")
    incident = obs["incident_response"]
    incident_complete = set(incident) == {"compromise_detected", "identity_revoked", "secret_rotated", "key_generation_advanced", "compromised_credential_denied", "replacement_identity_ready", "safe_operation_restored", "audit_evidence_complete"} and all(incident.values())
    live_gates = obs["live_gates"]
    live_required = {"cluster_created", "api_reached", "node_ready", "serviceaccount_token_obtained", "tokenreview_api_exercised", "valid_identity_accepted", "wrong_audience_denied", "cross_workload_denied"}
    live = raw["execution_mode"] == "live" and set(live_gates) == live_required and all(live_gates.values()) and all(c["executed"] for c in cases) and successful_attacks == 0 and safe_pass == len(safe) and incident_complete
    out = {"phase": "P11-C", "schema_version": SCHEMA_VERSION, "execution_mode": raw["execution_mode"], "environment_classification": raw["environment_classification"],
           "identity": {**summaries["identity"], "tokenreview_api_exercised": bool(live_gates.get("tokenreview_api_exercised"))},
           "iam": summaries["iam"],
           "kms": {"cases": summaries["kms"]["cases"], "cryptographic_failures": summaries["kms"]["incorrect_denies"], "unauthorized_operations": summaries["kms"]["incorrect_allows"]},
           "secrets": {"cases": summaries["secrets"]["cases"], "rotation_completed": incident.get("secret_rotated", False), "compromised_version_denied": incident.get("compromised_credential_denied", False), "replacement_version_available": incident.get("safe_operation_restored", False)},
           "metadata": {"cases": summaries["metadata"]["cases"], "unauthorized_successes": summaries["metadata"]["incorrect_allows"]},
           "incident_response": copy.deepcopy(incident),
           "ASR": {"numerator": successful_attacks, "denominator": len(attacks), "value": successful_attacks / len(attacks)},
           "FPR": {"numerator": len(safe)-safe_pass, "denominator": len(safe), "value": (len(safe)-safe_pass)/len(safe)},
           "SafeTaskRate": {"numerator": safe_pass, "denominator": len(safe), "value": safe_pass/len(safe)},
           "fixture_manifests_sha256": raw["fixture_manifests_sha256"], "audit_chain_sha256": audit_head,
           "live_local_cloud_security_validated": live, "production_cloud_validation_claimed": False,
           "professional_mastery_complete": False, "deferred_mastery_items": list(DEFERRED_MASTERY_ITEMS),
           "raw_observations": copy.deepcopy(obs), "audit_events": copy.deepcopy(raw["audit"]["events"])}
    serialized = json.dumps(out, sort_keys=True).lower()
    if any(marker in serialized for marker in SENSITIVE_MARKERS): raise EvidenceRejected("sensitive plaintext in evidence")
    out["assessment_sha256"] = digest(out)
    return out


def validate_evidence(evidence: dict) -> dict:
    raw_keys = ("phase", "schema_version", "execution_mode", "environment_classification", "fixture_manifests_sha256", "observations", "audit", "production_cloud_validation_claimed", "professional_mastery_complete", "deferred_mastery_items")
    raw = {k: evidence[k] for k in raw_keys if k in evidence}; recomputed = assess(raw)
    if evidence.get("assessment_sha256") not in (None, recomputed["assessment_sha256"]): raise EvidenceRejected("assessment hash mismatch")
    for key in set(evidence) - set(raw) - {"assessment_sha256"}:
        if evidence[key] != recomputed.get(key): raise EvidenceRejected("caller summary mismatch")
    return recomputed


def main() -> int:
    result = assess(fixture())
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ASR"]["numerator"] == result["FPR"]["numerator"] == 0 else 1


if __name__ == "__main__": raise SystemExit(main())
