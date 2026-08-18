from __future__ import annotations

import copy
import json
from pathlib import Path

from evals.p11b_fixture import (
    DEFERRED_MASTERY_ITEMS, PSA_CASES, RBAC_CASES, SCHEMA_VERSION,
    canonical_bytes, fixture, manifests_sha256, sha256,
)


class EvidenceRejected(ValueError):
    pass


def assess(raw: dict) -> dict:
    required = {"phase", "schema_version", "execution_mode", "environment_classification", "fixture_manifests_sha256", "observations", "production_validation_claimed", "professional_mastery_complete", "deferred_mastery_items"}
    if set(raw) != required:
        raise EvidenceRejected("malformed schema")
    if raw["phase"] != "P11-B" or raw["schema_version"] != SCHEMA_VERSION:
        raise EvidenceRejected("malformed schema")
    if raw["fixture_manifests_sha256"] != manifests_sha256():
        raise EvidenceRejected("fixture/manifests integrity mismatch")
    if raw["production_validation_claimed"] or raw["professional_mastery_complete"]:
        raise EvidenceRejected("forbidden production or mastery claim")
    if raw["deferred_mastery_items"] != list(DEFERRED_MASTERY_ITEMS):
        raise EvidenceRejected("mastery debt changed")
    obs = raw["observations"]
    if set(obs) != {"infrastructure", "psa", "rbac", "network_policy"}:
        raise EvidenceRejected("malformed observations")
    psa = obs["psa"]
    attacks = [x for x in psa if x.get("attack") is True]
    safe = [x for x in psa if x.get("attack") is False]
    if [x.get("case") for x in attacks] != list(PSA_CASES) or len(safe) != 1 or safe[0].get("case") != "restricted_benign":
        raise EvidenceRejected("malformed PSA observations")
    rbac = obs["rbac"]
    if [(x.get("case"), x.get("expected")) for x in rbac] != list(RBAC_CASES):
        raise EvidenceRejected("malformed RBAC observations")
    blocked = sum(x.get("observed") == "DENY" for x in attacks)
    successful = len(attacks) - blocked
    safe_pass = sum(x.get("observed") == "ALLOW" for x in safe)
    incorrect_allows = sum(x.get("expected") == "DENY" and x.get("observed") == "ALLOW" for x in rbac)
    incorrect_denies = sum(x.get("expected") == "ALLOW" and x.get("observed") == "DENY" for x in rbac)
    net = obs["network_policy"]
    baseline = net.get("baseline") == "SUCCESS"
    authorized = net.get("authorized_after_policy") == "SUCCESS"
    attacker_denied = net.get("attacker_after_policy") in {"TIMEOUT", "CONNECTION_REFUSED"}
    infra = obs["infrastructure"]
    live = raw["execution_mode"] == "live" and all((infra.get("cluster_created"), infra.get("api_reached"), infra.get("node_ready"))) and all(x.get("api_evaluated") for x in psa) and all(x.get("api_evaluated") for x in rbac) and net.get("api_evaluated") is True and successful == 0 and safe_pass == len(safe) and incorrect_allows == 0 and incorrect_denies == 0 and baseline and authorized and attacker_denied
    out = {
        "phase": "P11-B", "schema_version": SCHEMA_VERSION,
        "execution_mode": raw["execution_mode"], "environment_classification": raw["environment_classification"],
        "psa": {"attack_count": len(attacks), "blocked_attack_count": blocked, "successful_attack_count": successful, "safe_count": len(safe), "safe_pass_count": safe_pass},
        "rbac": {"case_count": len(rbac), "incorrect_allows": incorrect_allows, "incorrect_denies": incorrect_denies},
        "network_policy": {"baseline_confirmed": baseline, "authorized_path_allowed": authorized, "attacker_path_denied": attacker_denied},
        "ASR": {"numerator": successful, "denominator": len(attacks), "value": successful / len(attacks)},
        "FPR": {"numerator": len(safe) - safe_pass, "denominator": len(safe), "value": (len(safe) - safe_pass) / len(safe)},
        "SafeTaskRate": {"numerator": safe_pass, "denominator": len(safe), "value": safe_pass / len(safe)},
        "fixture_manifests_sha256": raw["fixture_manifests_sha256"],
        "live_kubernetes_cluster_validated": live,
        "production_validation_claimed": False, "professional_mastery_complete": False,
        "deferred_mastery_items": list(DEFERRED_MASTERY_ITEMS),
        "raw_observations": copy.deepcopy(obs),
    }
    out["assessment_sha256"] = sha256(out)
    return out


def validate_evidence(evidence: dict) -> dict:
    claimed = evidence.get("assessment_sha256")
    raw = {k: evidence[k] for k in ("phase", "schema_version", "execution_mode", "environment_classification", "fixture_manifests_sha256", "observations", "production_validation_claimed", "professional_mastery_complete", "deferred_mastery_items") if k in evidence}
    recomputed = assess(raw)
    if claimed is not None and claimed != recomputed["assessment_sha256"]:
        raise EvidenceRejected("assessment integrity mismatch")
    for key in set(evidence) - set(raw) - {"assessment_sha256"}:
        if evidence[key] != recomputed.get(key):
            raise EvidenceRejected("caller summary mismatch")
    return recomputed


def main() -> int:
    report = assess(fixture())
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ASR"]["numerator"] == 0 and report["FPR"]["numerator"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
