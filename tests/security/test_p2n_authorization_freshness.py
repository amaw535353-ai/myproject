from evals.p2n_authorization_freshness import build_report


def _attempts(report, variant: str):
    return {
        item["attempt_id"]: item
        for item in report["variants"][variant]["adversarial_attempts"]
    }


def test_hardened_fences_stale_revocation_and_policy_versions() -> None:
    report = build_report()
    attempts = _attempts(report, "hardened")

    revocation = attempts["P2N-A1"]
    assert revocation["valid"] is True
    assert revocation["cached_decision"] == "allowed"
    assert revocation["cached_revocation_epoch"] < revocation["authoritative_revocation_epoch"]
    assert revocation["freshness_rejection"] == "revocation_epoch_mismatch"
    assert revocation["final_effect_count"] == 0
    assert revocation["final_outbox_status"] == "cancelled"
    assert revocation["durable_denial_prevents_resurrection"] is True

    policy = attempts["P2N-A2"]
    assert policy["valid"] is True
    assert policy["cached_decision"] == "allowed"
    assert policy["cached_policy_version"] < policy["authoritative_policy_version"]
    assert policy["freshness_rejection"] == "policy_version_mismatch"
    assert policy["final_effect_count"] == 0
    assert policy["final_outbox_status"] == "cancelled"


def test_vulnerable_baseline_executes_with_the_same_stale_allow_decisions() -> None:
    report = build_report()
    attempts = _attempts(report, "vulnerable")

    assert attempts["P2N-A1"]["valid"] is True
    assert attempts["P2N-A1"]["freshness_rejection"] is None
    assert attempts["P2N-A1"]["final_effect_count"] == 1
    assert attempts["P2N-A1"]["final_outbox_status"] == "completed"

    assert attempts["P2N-A2"]["valid"] is True
    assert attempts["P2N-A2"]["freshness_rejection"] is None
    assert attempts["P2N-A2"]["final_effect_count"] == 1
    assert attempts["P2N-A2"]["final_outbox_status"] == "completed"
