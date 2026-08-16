from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FOCUSED = {
    "p10a": ("tests/security/test_p10a_inference_tenant_isolation.py", "evals.p10a_inference_tenant_isolation"),
    "p10b": ("tests/security/test_p10b_scheduler_security.py", "evals.p10b_scheduler_security"),
    "p10c": ("tests/security/test_p10c_cache_lifecycle.py", "evals.p10c_cache_lifecycle"),
    "p10d": ("tests/security/test_p10d_speculative_serving.py", "evals.p10d_speculative_serving"),
    "p10e": ("tests/security/test_p10e_adapter_routing.py", "evals.p10e_adapter_routing"),
    "p10f": ("tests/security/test_p10f_accelerator_isolation.py", "evals.p10f_accelerator_isolation"),
    "p10g": ("tests/security/test_p10g_streaming_security.py", "evals.p10g_streaming_security"),
    "p10h": ("tests/security/test_p10h_replica_routing.py", "evals.p10h_replica_routing"),
    "p10i": ("tests/security/test_p10i_incident_response.py", "evals.p10i_incident_response"),
}


def run(args: list[str]) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def run_p10g_loopback() -> None:
    run([sys.executable, "scripts/run_p10g_streaming_lab.py", "--output", "/tmp/p10g-loopback-report.json"])


def run_p10h_replica_lab() -> None:
    run([sys.executable, "scripts/run_p10h_replica_lab.py"])


def run_p10i_ir_lab() -> None:
    run([sys.executable, "scripts/run_p10i_ir_lab.py", "--output", "/tmp/p10i-ir-report.json"])
    run([sys.executable, "scripts/emit_p10i_exit_gate.py", "--output", "/tmp/p10i-exit-gate.json"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Reproducible local Phase 10 verification")
    group = parser.add_mutually_exclusive_group()
    for phase in FOCUSED:
        group.add_argument(f"--focused-{phase}", action="store_true", help=f"Run only {phase.upper()} security tests and evaluator.")
    args = parser.parse_args()
    selected = next((phase for phase in FOCUSED if getattr(args, f"focused_{phase}")), None)
    if selected:
        test, evaluator = FOCUSED[selected]
        run([sys.executable, "-m", "pytest", "-q", test])
        run([sys.executable, "-m", evaluator])
        if selected == "p10g": run_p10g_loopback()
        if selected == "p10h": run_p10h_replica_lab()
        if selected == "p10i": run_p10i_ir_lab()
        scope = f"{selected}_focused"
        status = "LOCAL_FOCUSED_PASS"
    else:
        run([sys.executable, "-m", "pytest"])
        for _, evaluator in FOCUSED.values():
            run([sys.executable, "-m", evaluator])
        run_p10g_loopback(); run_p10h_replica_lab(); run_p10i_ir_lab()
        scope = "phase10_repository"
        status = "LOCAL_FULL_PASS"
    print(json.dumps({
        "phase": "P10",
        "scope": scope,
        "verification_status": status,
        "hosted_ci_execution_verified": False,
        "production_validation_claimed": False,
        "professional_mastery_complete": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
