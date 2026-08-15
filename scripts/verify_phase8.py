#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import subprocess
import sys
from typing import Sequence

FULL_EVALS = [
    "evals.p8a_agent_delegation",
    "evals.p8b_agent_memory",
    "evals.p8c_goal_plan_integrity",
    "evals.p8d_tool_observation_integrity",
    "evals.p8e_execution_budget",
    "evals.p8f_human_approval",
    "evals.p8g_agent_messages",
    "evals.p8h_state_machine",
    "evals.p8i_agent_artifacts",
    "evals.p8j_agent_recovery",
    "evals.p8k_incident_forensics",
    "evals.p8l_phase8_exit_gate",
]


def run_command(command: Sequence[str]) -> dict[str, object]:
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    return {
        "command": list(command),
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run reproducible local Phase 8 verification without claiming hosted CI."
    )
    parser.add_argument(
        "--focused-p8l",
        action="store_true",
        help="Run only the P8-L focused test/evaluator pair.",
    )
    parser.add_argument("--output", type=Path, help="Optional JSON evidence output path.")
    args = parser.parse_args()

    if args.focused_p8l:
        commands = [
            [sys.executable, "-m", "pytest", "-q", "tests/security/test_p8l_phase8_exit_gate.py"],
            [sys.executable, "-m", "evals.p8l_phase8_exit_gate"],
        ]
        success_status = "LOCAL_FOCUSED_PASS"
        mode = "focused-p8l"
    else:
        commands = [[sys.executable, "-m", "pytest", "-q"]]
        commands.extend([[sys.executable, "-m", module] for module in FULL_EVALS])
        success_status = "LOCAL_FULL_PASS"
        mode = "full-phase8"

    records = []
    for command in commands:
        record = run_command(command)
        records.append(record)
        sys.stdout.write(str(record["stdout"]))
        sys.stderr.write(str(record["stderr"]))
        if int(record["returncode"]) != 0:
            break

    passed = len(records) == len(commands) and all(
        int(record["returncode"]) == 0 for record in records
    )
    report = {
        "verification_scope": mode,
        "verification_status": success_status if passed else "LOCAL_VERIFICATION_FAIL",
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "hosted_ci_execution_verified": False,
        "production_validation_claimed": False,
        "commands": records,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        print(f"wrote {args.output}")
    print(json.dumps({k: v for k, v in report.items() if k != "commands"}, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
