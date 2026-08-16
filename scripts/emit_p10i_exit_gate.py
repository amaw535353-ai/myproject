#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from aegis.inference.incident_response_security import InferenceIncidentResponseAnalyzer
from evals.p10i_fixture import build_fixture


def main() -> int:
    parser = argparse.ArgumentParser(description="Emit the machine-readable P10-I / Phase 10 exit gate")
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    f = build_fixture()
    a = InferenceIncidentResponseAnalyzer(f["policy"]).evaluate(f["manifest"], f["request"], f["p10h"])
    gate = f["manifest"].exit_gate
    report = {
        "phase": "P10",
        "milestone": "P10-I",
        "status": gate.status.value,
        "phase10_exit_eligible": gate.phase10_exit_eligible and a.phase10_exit_gate_verified,
        "validated_controls": list(gate.validated_controls),
        "local_runtime_gates": list(gate.local_runtime_gates),
        "deferred_mastery_items": list(gate.deferred_mastery_items),
        "professional_mastery_complete": a.professional_mastery_complete,
        "hosted_ci_execution_verified": a.hosted_ci_execution_verified,
        "production_validation_claimed": a.production_validation_claimed,
        "assessment_evidence_sha256": a.assessment_evidence_sha256,
        "manifest_sha256": a.manifest_sha256,
    }
    text = json.dumps(report, sort_keys=True)
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(text)
    return 0 if report["phase10_exit_eligible"] and not report["professional_mastery_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
