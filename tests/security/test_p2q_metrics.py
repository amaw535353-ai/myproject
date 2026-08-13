from evals.p2q_control_plane_recovery import build_report


def test_p2q_metrics_and_protocol() -> None:
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
    assert vulnerable["fpr"]["percent"] == 0.0
    assert vulnerable["safe_task_rate"]["percent"] == 100.0

    protocol = report["recovery_protocol"]
    assert protocol["state_machine"] == ["prepared", "applied", "active"]
    assert protocol["security_mutation_and_applied_generation_same_transaction"] is True
    assert protocol["activation_requires_matching_execution_generation_and_change_hash"] is True
    assert protocol["authorization_requires_no_pending_change_and_generation_equality"] is True

    hygiene = report["evidence_hygiene"]
    assert all(value is False for value in hygiene.values())
