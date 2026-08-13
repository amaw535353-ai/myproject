import hashlib
import json
from collections import Counter
from pathlib import Path

from aegis.security.phase2_controls import PHASE2_CONTROLS, PHASE3_GAPS, DeploymentStatus, expected_phase2_milestones

ROOT = Path(__file__).resolve().parents[1]


def build_report() -> dict[str, object]:
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    ids = tuple(item.milestone for item in PHASE2_CONTROLS)
    missing_docs = [item.milestone for item in PHASE2_CONTROLS if not (ROOT / item.threat_model).is_file()]
    missing_evals = [item.milestone for item in PHASE2_CONTROLS if not ROOT.joinpath(*item.eval_module.split(".")).with_suffix(".py").is_file()]
    missing_ci = [item.milestone for item in PHASE2_CONTROLS if item.eval_command not in ci]
    missing_runtime = [f"{item.milestone}:{path}" for item in PHASE2_CONTROLS for path in item.runtime_evidence if not (ROOT / path).is_file()]
    unknown_gaps = sorted({gap for item in PHASE2_CONTROLS for gap in item.phase3_gaps if gap not in PHASE3_GAPS})
    ungapped = [item.milestone for item in PHASE2_CONTROLS if item.deployment_status is not DeploymentStatus.DEFAULT_API and not item.phase3_gaps]
    checks = {
        "milestones_complete_and_ordered": ids == expected_phase2_milestones(),
        "threat_models_present": not missing_docs,
        "evaluations_present": not missing_evals,
        "ci_runs_every_phase2_evaluation": not missing_ci,
        "runtime_evidence_paths_present": not missing_runtime,
        "gap_references_known": not unknown_gaps,
        "every_non_default_control_has_phase3_gap": not ungapped,
    }
    payload = "\n".join(f"{item.milestone}|{item.threat_model}|{item.eval_module}|{item.deployment_status.value}|{','.join(item.phase3_gaps)}" for item in PHASE2_CONTROLS)
    return {
        "evaluation": "Phase 2 exit control/evidence gate",
        "phase2_control_count": len(PHASE2_CONTROLS),
        "deployment_status_counts": dict(sorted(Counter(item.deployment_status.value for item in PHASE2_CONTROLS).items())),
        "phase3_gap_count": len(PHASE3_GAPS),
        "registry_hash_sha256": hashlib.sha256(payload.encode()).hexdigest(),
        "checks": checks,
        "failures": {"missing_docs": missing_docs, "missing_evals": missing_evals, "missing_ci": missing_ci, "missing_runtime": missing_runtime, "unknown_gaps": unknown_gaps, "ungapped": ungapped},
        "phase2_exit_gate_passed": all(checks.values()),
        "scope_note": "Evidence-complete does not mean every control is default-runtime or production-ready.",
    }


def main() -> int:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["phase2_exit_gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
