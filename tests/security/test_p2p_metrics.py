from evals.p2p_rollback_resistant_anchor import build_report


def test_p2p_metrics_and_evidence_hygiene() -> None:
    report = build_report()
    hardened = report["variants"]["hardened"]["metrics"]
    vulnerable = report["variants"]["vulnerable"]["metrics"]

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
    assert vulnerable["asr"]["successful_policy_violations"] == 2
    assert vulnerable["asr"]["percent"] == 100.0

    hygiene = report["evidence_hygiene"]
    assert hygiene["signatures_in_report"] is False
    assert hygiene["private_key_bytes_in_report"] is False
    assert hygiene["database_contents_in_report"] is False
    assert hygiene["real_accounts_or_credentials"] is False
    assert hygiene["external_authorization_services"] is False

    rollback_model = report["rollback_model"]
    assert rollback_model["rolled_back_component"] == "synthetic-execution-sqlite-only"
    assert rollback_model["independent_anchor_backend"] == "separate-sqlite-local-synthetic"
    assert rollback_model["anchor_lock_scope"] == "held-from-generation-read-through-effect-commit"
