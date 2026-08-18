from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "p11b-kubernetes-security.v1"
DEFERRED_MASTERY_ITEMS = (
    "p10f-live-nvidia-gpu-mig-cuda",
    "p11b-production-kubernetes",
    "p11b-production-cni",
    "p11b-cloud-iam-workload-identity",
    "p11b-multi-node-production-behavior",
    "p11b-container-escape-kernel-compromise-resistance",
    "p11b-production-soc-ir-maturity",
)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def manifests_sha256() -> str:
    files = sorted((ROOT / "deploy" / "p11b").glob("*.yaml"))
    bound = [{"path": str(p.relative_to(ROOT)), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]
    return sha256(bound)


PSA_CASES = (
    "privileged", "allowPrivilegeEscalation", "SYS_ADMIN", "hostPID",
    "hostNetwork", "hostPath", "UID_0", "missing_seccomp",
)

RBAC_CASES = (
    ("named_configmap_read", "ALLOW"), ("secret_read", "DENY"),
    ("cross_namespace_configmap", "DENY"), ("cross_namespace_secret", "DENY"),
    ("rolebinding_create", "DENY"), ("clusterrolebinding_create", "DENY"),
    ("impersonation", "DENY"), ("cross_namespace_pod_create", "DENY"),
    ("pods_exec", "DENY"), ("serviceaccounts_token_create", "DENY"),
)


def deterministic_observations() -> dict:
    return {
        "infrastructure": {"cluster_created": False, "api_reached": False, "node_ready": False},
        "psa": [
            {"case": name, "attack": True, "expected": "DENY", "observed": "DENY", "api_evaluated": False}
            for name in PSA_CASES
        ] + [{"case": "restricted_benign", "attack": False, "expected": "ALLOW", "observed": "ALLOW", "api_evaluated": False}],
        "rbac": [
            {"case": name, "expected": expected, "observed": expected, "api_evaluated": False}
            for name, expected in RBAC_CASES
        ],
        "network_policy": {
            "baseline": "SUCCESS", "authorized_after_policy": "SUCCESS",
            "attacker_after_policy": "TIMEOUT", "api_evaluated": False,
        },
    }


def fixture(execution_mode: str = "deterministic", observations: dict | None = None) -> dict:
    return {
        "phase": "P11-B",
        "schema_version": SCHEMA_VERSION,
        "execution_mode": execution_mode,
        "environment_classification": "DETERMINISTIC_FIXTURE" if execution_mode == "deterministic" else "LOCAL_K3D_K3S",
        "fixture_manifests_sha256": manifests_sha256(),
        "observations": observations or deterministic_observations(),
        "production_validation_claimed": False,
        "professional_mastery_complete": False,
        "deferred_mastery_items": list(DEFERRED_MASTERY_ITEMS),
    }
