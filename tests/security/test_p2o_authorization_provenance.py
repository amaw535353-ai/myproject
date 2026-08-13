from evals.p2o_authorization_provenance import build_report


def _attempts(report, variant: str):
    return {
        item["attempt_id"]: item
        for item in report["variants"][variant]["adversarial_attempts"]
    }


def _benign(report, variant: str):
    return {
        item["attempt_id"]: item
        for item in report["variants"][variant]["benign_attempts"]
    }


def test_hardened_rejects_forged_current_claims_and_old_key_rollback() -> None:
    report = build_report()
    attempts = _attempts(report, "hardened")

    forged = attempts["P2O-A1"]
    assert forged["valid"] is True
    assert forged["claims_tampered_after_signing"] is True
    assert forged["cached_revocation_epoch"] < forged["authoritative_revocation_epoch"]
    assert forged["forged_revocation_epoch"] == forged["authoritative_revocation_epoch"]
    assert forged["provenance_rejection"] == "signature_invalid"
    assert forged["final_effect_count"] == 0
    assert forged["final_outbox_status"] == "cancelled"

    rollback = attempts["P2O-A2"]
    assert rollback["valid"] is True
    assert rollback["decision_key_epoch"] < rollback["authoritative_key_epoch"]
    assert rollback["provenance_rejection"] == "key_epoch_mismatch"
    assert rollback["final_effect_count"] == 0
    assert rollback["final_outbox_status"] == "cancelled"


def test_vulnerable_metadata_trust_executes_both_attacks() -> None:
    report = build_report()
    attempts = _attempts(report, "vulnerable")

    for attempt_id in ("P2O-A1", "P2O-A2"):
        attempt = attempts[attempt_id]
        assert attempt["valid"] is True
        assert attempt["success"] is True
        assert attempt["provenance_rejection"] is None
        assert attempt["final_effect_count"] == 1
        assert attempt["final_outbox_status"] == "completed"


def test_current_signed_decisions_complete_for_both_key_epochs() -> None:
    report = build_report()
    benign = _benign(report, "hardened")

    assert benign["P2O-B1"]["signing_key_epoch"] == 1
    assert benign["P2O-B1"]["safe_completion"] is True
    assert benign["P2O-B1"]["effect_count"] == 1
    assert benign["P2O-B1"]["outbox_status"] == "completed"

    assert benign["P2O-B2"]["signing_key_epoch"] == 2
    assert benign["P2O-B2"]["safe_completion"] is True
    assert benign["P2O-B2"]["effect_count"] == 1
    assert benign["P2O-B2"]["outbox_status"] == "completed"
