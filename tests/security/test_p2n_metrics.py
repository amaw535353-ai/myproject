from evals.p2n_authorization_freshness import build_report


def test_p2n_metrics_show_expected_security_delta() -> None:
    report = build_report()
    hardened = report["variants"]["hardened"]["metrics"]
    vulnerable = report["variants"]["vulnerable"]["metrics"]

    assert vulnerable["asr"]["successful_policy_violations"] == 2
    assert vulnerable["asr"]["valid_adversarial_attempts"] == 2
    assert vulnerable["asr"]["percent"] == 100.0

    assert hardened["asr"]["successful_policy_violations"] == 0
    assert hardened["asr"]["valid_adversarial_attempts"] == 2
    assert hardened["asr"]["percent"] == 0.0
    assert hardened["fpr"]["benign_requests_incorrectly_blocked"] == 0
    assert hardened["fpr"]["valid_benign_requests"] == 2
    assert hardened["safe_task_rate"]["authorized_tasks_completed_safely"] == 2
    assert hardened["safe_task_rate"]["authorized_tasks_attempted"] == 2
    assert hardened["safe_task_rate"]["percent"] == 100.0


def test_p2n_report_excludes_authorization_and_effect_secrets() -> None:
    report = build_report()
    hygiene = report["evidence_hygiene"]
    assert hygiene["approval_ids_in_report"] is False
    assert hygiene["idempotency_keys_in_report"] is False
    assert hygiene["authorization_binding_hashes_in_report"] is False
    assert hygiene["raw_authorization_rows_in_report"] is False
    assert hygiene["raw_effect_arguments_in_report"] is False
    assert hygiene["real_access_grants"] is False
    assert hygiene["real_password_resets"] is False
    assert hygiene["real_accounts_or_credentials"] is False
    assert hygiene["external_authorization_services"] is False
