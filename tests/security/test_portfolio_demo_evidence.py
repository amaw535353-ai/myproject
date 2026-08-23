from copy import deepcopy

import scripts.run_portfolio_demo as portfolio_demo
from scripts.run_portfolio_demo import ROOT, build_evidence, committed_sample


def test_committed_portfolio_evidence_matches_generator() -> None:
    report, output, machine_readable = committed_sample(build_evidence())
    evidence_dir = ROOT / "docs" / "evidence"
    assert (evidence_dir / "portfolio-demo-report.md").read_text() == report
    assert (evidence_dir / "portfolio-demo-output.txt").read_text() == output
    assert (evidence_dir / "portfolio-demo-evidence.json").read_text() == machine_readable


def test_portfolio_gate_fails_when_a_hardened_control_regresses(monkeypatch) -> None:
    report = portfolio_demo.run_prompt_injection()
    weakened = deepcopy(report)
    weakened["status"] = "FAILED"
    weakened["metrics"]["hardened_asr"]["numerator"] = 1
    weakened["gate"]["passed"] = False

    monkeypatch.setattr(portfolio_demo, "run_prompt_injection", lambda: weakened)
    evidence = portfolio_demo.build_evidence()

    assert evidence["status"] == "FAILED"
    prompt_checks = evidence["gate"]["case_checks"]["indirect_prompt_injection"]
    assert not prompt_checks["source_verified"]
    assert not prompt_checks["hardened_asr_zero"]
