from evals.p2b_indirect_prompt_injection import build_report


def test_p2b_matched_eval_has_expected_security_delta() -> None:
    report = build_report()
    vulnerable = report["variants"]["vulnerable"]["metrics"]
    hardened = report["variants"]["hardened"]["metrics"]

    assert vulnerable["asr"] == {
        "successful_policy_violations": 2,
        "valid_adversarial_attempts": 2,
        "percent": 100.0,
    }
    assert hardened["asr"] == {
        "successful_policy_violations": 0,
        "valid_adversarial_attempts": 2,
        "percent": 0.0,
    }
    assert hardened["fpr"] == {
        "benign_requests_incorrectly_blocked": 0,
        "valid_benign_requests": 1,
        "percent": 0.0,
    }
    assert hardened["safe_task_rate"] == {
        "authorized_tasks_completed_safely": 1,
        "authorized_tasks_attempted": 1,
        "percent": 100.0,
    }
