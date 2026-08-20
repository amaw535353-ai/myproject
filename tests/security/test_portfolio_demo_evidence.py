from scripts.run_portfolio_demo import ROOT, build_evidence, committed_sample


def test_committed_portfolio_evidence_matches_generator() -> None:
    report, output = committed_sample(build_evidence())
    evidence_dir = ROOT / "docs" / "evidence"
    assert (evidence_dir / "portfolio-demo-report.md").read_text() == report
    assert (evidence_dir / "portfolio-demo-output.txt").read_text() == output
