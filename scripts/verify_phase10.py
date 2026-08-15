from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run(args: list[str]) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Reproducible local Phase 10 verification")
    parser.add_argument(
        "--focused-p10a",
        action="store_true",
        help="Run only P10-A security tests and evaluator.",
    )
    args = parser.parse_args()
    if args.focused_p10a:
        run([sys.executable, "-m", "pytest", "-q", "tests/security/test_p10a_inference_tenant_isolation.py"])
        run([sys.executable, "-m", "evals.p10a_inference_tenant_isolation"])
        scope = "p10a_focused"
        status = "LOCAL_FOCUSED_PASS"
    else:
        run([sys.executable, "-m", "pytest"])
        run([sys.executable, "-m", "evals.p10a_inference_tenant_isolation"])
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
