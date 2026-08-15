from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FOCUSED = {
    "p10a": (
        "tests/security/test_p10a_inference_tenant_isolation.py",
        "evals.p10a_inference_tenant_isolation",
    ),
    "p10b": (
        "tests/security/test_p10b_scheduler_security.py",
        "evals.p10b_scheduler_security",
    ),
    "p10c": (
        "tests/security/test_p10c_cache_lifecycle.py",
        "evals.p10c_cache_lifecycle",
    ),
    "p10d": (
        "tests/security/test_p10d_speculative_serving.py",
        "evals.p10d_speculative_serving",
    ),
    "p10e": (
        "tests/security/test_p10e_adapter_routing.py",
        "evals.p10e_adapter_routing",
    ),
    "p10f": (
        "tests/security/test_p10f_accelerator_isolation.py",
        "evals.p10f_accelerator_isolation",
    ),
    "p10g": (
        "tests/security/test_p10g_streaming_security.py",
        "evals.p10g_streaming_security",
    ),
}


def run(args: list[str]) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def run_p10g_loopback() -> None:
    run(
        [
            sys.executable,
            "scripts/run_p10g_streaming_lab.py",
            "--output",
            "/tmp/p10g-loopback-report.json",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Reproducible local Phase 10 verification")
    group = parser.add_mutually_exclusive_group()
    for phase in FOCUSED:
        group.add_argument(
            f"--focused-{phase}",
            action="store_true",
            help=f"Run only {phase.upper()} security tests and evaluator.",
        )
    args = parser.parse_args()
    selected = next(
        (phase for phase in FOCUSED if getattr(args, f"focused_{phase}")), None
    )
    if selected:
        test, evaluator = FOCUSED[selected]
        run([sys.executable, "-m", "pytest", "-q", test])
        run([sys.executable, "-m", evaluator])
        if selected == "p10g":
            run_p10g_loopback()
        scope = f"{selected}_focused"
        status = "LOCAL_FOCUSED_PASS"
    else:
        run([sys.executable, "-m", "pytest"])
        for _, evaluator in FOCUSED.values():
            run([sys.executable, "-m", evaluator])
        run_p10g_loopback()
        scope = "phase10_repository"
        status = "LOCAL_FULL_PASS"
    print(
        json.dumps(
            {
                "phase": "P10",
                "scope": scope,
                "verification_status": status,
                "hosted_ci_execution_verified": False,
                "production_validation_claimed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
