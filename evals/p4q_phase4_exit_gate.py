from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from aegis.security.phase2_controls import PHASE3_GAPS
from aegis.security.phase4_controls import (
    P4Q_PHASE4_EXIT_POLICY_VERSION,
    PHASE4_BOUNDARY_CLAIMS,
    PHASE4_CONTROLS,
    PHASE4_PROHIBITED_CLAIMS,
    PHASE4_RESIDUAL_ASSUMPTIONS,
    Phase4EvidencePosture,
    expected_phase4_milestones,
    phase4_evidence_register,
)


ROOT = Path(__file__).resolve().parents[1]
P4Q_THREAT_MODEL = "docs/threat-model/p4q-phase4-exit-claim-evidence-gate.md"
P4Q_PROGRESS_DOCUMENT = "docs/phase4-progress.md"
P4Q_EVAL_COMMAND = "python -m evals.p4q_phase4_exit_gate"


def _module_path(module: str) -> Path:
    return ROOT.joinpath(*module.split(".")).with_suffix(".py")


def _registry_hash() -> str:
    payload = {
        "policy_version": P4Q_PHASE4_EXIT_POLICY_VERSION,
        "controls": phase4_evidence_register(),
        "boundary_claims": PHASE4_BOUNDARY_CLAIMS,
        "residual_assumptions": PHASE4_RESIDUAL_ASSUMPTIONS,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_report() -> dict[str, object]:
    workflow_path = ROOT / ".github/workflows/phase3.yml"
    workflow = workflow_path.read_text(encoding="utf-8") if workflow_path.is_file() else ""
    progress_path = ROOT / P4Q_PROGRESS_DOCUMENT
    progress = progress_path.read_text(encoding="utf-8") if progress_path.is_file() else ""

    ids = tuple(item.milestone for item in PHASE4_CONTROLS)
    missing_docs = [
        item.milestone for item in PHASE4_CONTROLS if not (ROOT / item.threat_model).is_file()
    ]
    missing_evals = [
        item.milestone for item in PHASE4_CONTROLS if not _module_path(item.eval_module).is_file()
    ]
    missing_evidence = [
        f"{item.milestone}:{path}"
        for item in PHASE4_CONTROLS
        for path in item.evidence_paths
        if not (ROOT / path).is_file()
    ]
    missing_ci = [
        item.milestone for item in PHASE4_CONTROLS if item.eval_command not in workflow
    ]
    missing_claims = [item.milestone for item in PHASE4_CONTROLS if not item.supported_claims]
    missing_assumptions = [
        item.milestone for item in PHASE4_CONTROLS if not item.residual_assumptions
    ]

    prohibited_supported_claims: list[str] = []
    for item in PHASE4_CONTROLS:
        for claim in item.supported_claims:
            lowered = claim.casefold()
            for prohibited in PHASE4_PROHIBITED_CLAIMS:
                if prohibited.casefold() in lowered:
                    prohibited_supported_claims.append(
                        f"{item.milestone}:{prohibited}:{claim}"
                    )

    production_eligible_entries = [
        item.milestone
        for item in PHASE4_CONTROLS
        if item.production_ready
        or item.operationally_external
        or item.independent_failure_domain
    ]

    required_false_boundaries = (
        "production_external_checkpoint_adapter",
        "production_external_lifecycle_provider",
        "production_checkpoint_durability",
        "production_disaster_recovery",
        "distributed_transaction",
        "distributed_consensus",
        "exactly_once_execution",
        "independent_failure_domain",
        "real_external_trust_operations",
        "network_operations_required",
    )
    boundary_claim_violations = [
        name for name in required_false_boundaries if PHASE4_BOUNDARY_CLAIMS.get(name) is not False
    ]

    expected_postures = {
        Phase4EvidencePosture.DEFAULT_LOCAL.value: 7,
        Phase4EvidencePosture.POLICY_BOUNDARY.value: 2,
        Phase4EvidencePosture.SYNTHETIC_LAB.value: 7,
    }
    posture_counts = dict(
        sorted(Counter(item.posture.value for item in PHASE4_CONTROLS).items())
    )

    checks = {
        "milestones_complete_and_ordered": ids == expected_phase4_milestones(),
        "threat_models_present": not missing_docs,
        "evaluations_present": not missing_evals,
        "evidence_paths_present": not missing_evidence,
        "phase4_ci_runs_every_milestone_evaluation": not missing_ci,
        "phase4_ci_runs_exit_gate": P4Q_EVAL_COMMAND in workflow,
        "phase4_workflow_covers_main": "- main" in workflow,
        "supported_claims_declared": not missing_claims,
        "residual_assumptions_declared_per_milestone": not missing_assumptions,
        "prohibited_production_claims_absent": not prohibited_supported_claims,
        "included_implementations_remain_non_production": not production_eligible_entries,
        "global_boundary_claims_fail_closed": not boundary_claim_violations,
        "global_residual_assumptions_declared": len(PHASE4_RESIDUAL_ASSUMPTIONS) >= 5,
        "posture_distribution_expected": posture_counts == expected_postures,
        "phase3_integration_gaps_remain_zero": len(PHASE3_GAPS) == 0,
        "p4q_threat_model_present": (ROOT / P4Q_THREAT_MODEL).is_file(),
        "phase4_completion_documented": (
            "Phase 4 complete" in progress and "Phase 5" in progress
        ),
    }

    return {
        "evaluation": "P4-Q Phase 4 claim/evidence exit gate",
        "policy_version": P4Q_PHASE4_EXIT_POLICY_VERSION,
        "phase4_control_count": len(PHASE4_CONTROLS),
        "expected_milestones": list(expected_phase4_milestones()),
        "posture_counts": posture_counts,
        "registry_hash_sha256": _registry_hash(),
        "boundary_claims": dict(sorted(PHASE4_BOUNDARY_CLAIMS.items())),
        "residual_assumptions": list(PHASE4_RESIDUAL_ASSUMPTIONS),
        "checks": checks,
        "failures": {
            "missing_docs": missing_docs,
            "missing_evals": missing_evals,
            "missing_evidence": missing_evidence,
            "missing_ci": missing_ci,
            "missing_claims": missing_claims,
            "missing_assumptions": missing_assumptions,
            "prohibited_supported_claims": prohibited_supported_claims,
            "production_eligible_entries": production_eligible_entries,
            "boundary_claim_violations": boundary_claim_violations,
        },
        "phase4_exit_gate_passed": all(checks.values()),
        "next_phase": "Phase 5 model and AI supply-chain security",
        "scope_note": (
            "Phase 4 evidence-complete means the repository has deterministic checkpoint-security "
            "evidence for P4-A through P4-P. It does not establish production durability, external "
            "trust, exactly-once execution, disaster recovery, or an independent failure domain."
        ),
    }


def main() -> int:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["phase4_exit_gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
