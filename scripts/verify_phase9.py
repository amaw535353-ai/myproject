from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run_command(args: list[str]) -> None:
    subprocess.run(args, cwd=ROOT, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Reproducible local Phase 9 verification")
    parser.add_argument(
        "--focused-p9a",
        action="store_true",
        help="Run only the P9-A security tests and evaluator instead of the full repository test suite.",
    )
    args = parser.parse_args()

    if args.focused_p9a:
        run_command([sys.executable, "-m", "pytest", "-q", "tests/security/test_p9a_training_data_provenance.py"])
        scope = "p9a_training_data_provenance"
        status = "LOCAL_FOCUSED_PASS"
    else:
        run_command([sys.executable, "-m", "pytest"])
        scope = "phase9_repository"
        status = "LOCAL_FULL_PASS"

    run_command([sys.executable, "-m", "evals.p9a_training_data_provenance"])
    print(
        json.dumps(
            {
                "phase": "P9",
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
