from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run(args: list[str]) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def run_p11a() -> None:
    run([sys.executable, "-m", "pytest", "-q", "tests/security/test_p11a_workload_security.py"])
    run([sys.executable, "-m", "evals.p11a_workload_security"])
    run([sys.executable, "scripts/check_p11a_k8s_manifests.py"])
    run([sys.executable, "scripts/run_p11a_linux_sandbox_lab.py"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Reproducible local Phase 11 verification")
    parser.add_argument("--focused-p11a", action="store_true")
    args = parser.parse_args()
    if args.focused_p11a:
        run_p11a()
        scope = "p11a_focused"
        status = "LOCAL_FOCUSED_PASS"
    else:
        run([sys.executable, "-m", "pytest"])
        run([sys.executable, "-m", "evals.p11a_workload_security"])
        run([sys.executable, "scripts/check_p11a_k8s_manifests.py"])
        run([sys.executable, "scripts/run_p11a_linux_sandbox_lab.py"])
        scope = "phase11_repository"
        status = "LOCAL_FULL_PASS"
    print(json.dumps({
        "phase": "P11",
        "scope": scope,
        "verification_status": status,
        "local_linux_workload_isolation_validated": True,
        "kubernetes_manifests_statically_validated": True,
        "live_kubernetes_cluster_validated": False,
        "production_validation_claimed": False,
        "professional_mastery_complete": False,
        "deferred_mastery_items": [
            "p10f-live-nvidia-gpu-mig-cuda",
            "p11a-live-kubernetes-cluster",
        ],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
