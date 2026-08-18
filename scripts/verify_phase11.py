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


def run_p11b() -> None:
    run([sys.executable, "-m", "pytest", "-q", "tests/security/test_p11b_kubernetes_security.py"])
    run([sys.executable, "-m", "evals.p11b_kubernetes_security"])
    run([sys.executable, "-m", "py_compile", "evals/p11b_fixture.py", "evals/p11b_kubernetes_security.py", "scripts/run_p11b_kubernetes_lab.py", "scripts/verify_phase11.py"])
    proc = subprocess.run([sys.executable, "scripts/run_p11b_kubernetes_lab.py"], cwd=ROOT)
    if proc.returncode == 0:
        print("P11B_LIVE_LOCAL_PASS")
    elif proc.returncode == 2:
        print("LIVE_KUBERNETES_DEFERRED")
    else:
        print("P11B_SECURITY_VALIDATION_FAILED")
    raise SystemExit(proc.returncode)


def run_p11c() -> None:
    run([sys.executable, "-m", "pytest", "-q", "tests/security/test_p11c_cloud_security.py"])
    run([sys.executable, "-m", "evals.p11c_cloud_security"])
    run([sys.executable, "-m", "pytest", "-q", "tests/security/test_p11b_kubernetes_security.py"])
    run([sys.executable, "-m", "pytest", "-q", "tests/security/test_p11a_workload_security.py"])
    run([sys.executable, "-m", "py_compile", "evals/p11c_fixture.py", "evals/p11c_cloud_security.py", "scripts/run_p11c_cloud_security_lab.py", "scripts/verify_phase11.py"])
    proc = subprocess.run([sys.executable, "scripts/run_p11c_cloud_security_lab.py"], cwd=ROOT)
    if proc.returncode == 0:
        print("P11C_LIVE_LOCAL_PASS")
    elif proc.returncode == 2:
        print("LIVE_LOCAL_CLOUD_SECURITY_DEFERRED")
    else:
        print("P11C_SECURITY_VALIDATION_FAILED")
    raise SystemExit(proc.returncode)


def run_p11d() -> None:
    run([sys.executable, "-m", "pytest", "-q", "tests/security/test_p11d_serving_security.py"])
    run([sys.executable, "-m", "evals.p11d_serving_security"])
    for test in ("test_p11c_cloud_security.py", "test_p11b_kubernetes_security.py", "test_p11a_workload_security.py",
                 "test_p10g_streaming_security.py", "test_p10h_replica_routing.py"):
        run([sys.executable, "-m", "pytest", "-q", f"tests/security/{test}"])
    run([sys.executable, "-m", "py_compile", "aegis/platform/serving_security.py", "apps/p11d_serving_gateway.py",
         "apps/p11d_serving_backend.py", "evals/p11d_fixture.py", "evals/p11d_serving_security.py",
         "scripts/run_p11d_serving_security_lab.py", "scripts/verify_phase11.py"])
    proc = subprocess.run([sys.executable, "scripts/run_p11d_serving_security_lab.py"], cwd=ROOT)
    if proc.returncode == 0: print("P11D_LIVE_LOCAL_PASS")
    elif proc.returncode == 2: print("LIVE_LOCAL_SERVING_SECURITY_DEFERRED")
    else: print("P11D_SECURITY_VALIDATION_FAILED")
    raise SystemExit(proc.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description="Reproducible local Phase 11 verification")
    parser.add_argument("--focused-p11a", action="store_true")
    parser.add_argument("--focused-p11b", action="store_true")
    parser.add_argument("--focused-p11c", action="store_true")
    parser.add_argument("--focused-p11d", action="store_true")
    args = parser.parse_args()
    if sum((args.focused_p11a, args.focused_p11b, args.focused_p11c, args.focused_p11d)) > 1:
        parser.error("choose one focused milestone")

    if args.focused_p11a:
        run_p11a()
        scope = "p11a_focused"
        status = "LOCAL_FOCUSED_PASS"
    elif args.focused_p11b:
        run_p11b()
        return 0
    elif args.focused_p11c:
        run_p11c()
        return 0
    elif args.focused_p11d:
        run_p11d()
        return 0
    else:
        run([sys.executable, "-m", "pytest"])
        run([sys.executable, "-m", "evals.p11a_workload_security"])
        run([sys.executable, "scripts/check_p11a_k8s_manifests.py"])
        run([sys.executable, "scripts/run_p11a_linux_sandbox_lab.py"])
        run([sys.executable, "-m", "evals.p11b_kubernetes_security"])
        run([sys.executable, "-m", "evals.p11c_cloud_security"])
        run([sys.executable, "-m", "evals.p11d_serving_security"])
        scope = "phase11_repository"
        status = "LOCAL_FULL_PASS"

    print(json.dumps({
        "phase": "P11",
        "scope": scope,
        "verification_status": status,
        "local_linux_workload_isolation_validated": True,
        "kubernetes_manifests_statically_validated": True,
        "p11b_deterministic_contract_validated": args.focused_p11b or args.focused_p11c or not args.focused_p11a,
        "live_kubernetes_cluster_validated": False,
        "production_validation_claimed": False,
        "professional_mastery_complete": False,
        "deferred_mastery_items": ["p10f-live-nvidia-gpu-mig-cuda", "p11b-production-kubernetes", "p11b-production-cni", "p11b-cloud-iam-workload-identity", "p11b-multi-node-production-behavior", "p11b-container-escape-kernel-compromise-resistance", "p11b-production-soc-ir-maturity"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
