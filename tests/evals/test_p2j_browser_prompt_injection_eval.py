from evals.p2j_browser_prompt_injection import build_report


def test_p2j_expected_security_delta() -> None:
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
        "valid_benign_requests": 2,
        "percent": 0.0,
    }
    assert hardened["safe_task_rate"] == {
        "authorized_tasks_completed_safely": 2,
        "authorized_tasks_attempted": 2,
        "percent": 100.0,
    }


def test_p2j_report_keeps_webpage_and_tool_payloads_out_of_evidence() -> None:
    report = build_report()
    hygiene = report["evidence_hygiene"]

    assert hygiene["webpage_bodies_in_report"] is False
    assert hygiene["tool_result_bodies_in_report"] is False
    assert hygiene["approval_handles_in_report"] is False
    assert hygiene["ticket_ids_in_report"] is False
    assert hygiene["real_network_requests"] is False
    assert report["network"]["safe_fetcher_reused_for_both_variants"] is True
