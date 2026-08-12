from evals.p2a_tenant_boundary import build_report


def test_p2a_matched_asr_is_deterministic() -> None:
    report = build_report()

    vulnerable = report["variants"]["vulnerable"]["metrics"]
    hardened = report["variants"]["hardened"]["metrics"]

    assert vulnerable["successful_policy_violations"] == 2
    assert vulnerable["valid_adversarial_attempts"] == 2
    assert vulnerable["asr_percent"] == 100.0

    assert hardened["successful_policy_violations"] == 0
    assert hardened["valid_adversarial_attempts"] == 2
    assert hardened["asr_percent"] == 0.0
