from pathlib import Path

import pytest

from aegis.approvals.models import ApprovalAction
from aegis.effects.revalidation import RevalidatingEffectOutboxStore
from aegis.effects.rollback_anchor import (
    AnchoredAuthorizationPayload,
    AnchoredAuthorizationSigner,
    ControlPlaneGenerationStore,
    RollbackAnchorError,
    RollbackAnchorReason,
    RollbackResistantSyntheticEffectService,
)
from aegis.effects.signed_authorization import TrustedAuthorizationKeyStore
from evals.p2n_authorization_freshness import _create_case
from evals.p2o_authorization_provenance import _clock, _key_fixture, _signer, _trust_initial
from evals.p2p_rollback_resistant_anchor import _anchor_fixture, build_report


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


def test_hardened_rejects_revocation_and_key_state_database_rollbacks() -> None:
    attempts = _attempts(build_report(), "hardened")

    for attempt_id in ("P2P-A1", "P2P-A2"):
        attempt = attempts[attempt_id]
        assert attempt["valid"] is True
        assert attempt["decision_generation"] < attempt["anchor_generation"]
        assert attempt["anchor_rejection"] == "control_plane_generation_mismatch"
        assert attempt["final_effect_count"] == 0
        assert attempt["final_outbox_status"] == "cancelled"
        assert attempt["success"] is False


def test_rollback_blind_p2o_baseline_executes_both_database_rollbacks() -> None:
    attempts = _attempts(build_report(), "vulnerable")

    for attempt_id in ("P2P-A1", "P2P-A2"):
        attempt = attempts[attempt_id]
        assert attempt["valid"] is True
        assert attempt["anchor_rejection"] is None
        assert attempt["final_effect_count"] == 1
        assert attempt["final_outbox_status"] == "completed"
        assert attempt["success"] is True


def test_current_generation_envelopes_complete_before_and_after_rotation() -> None:
    benign = _benign(build_report(), "hardened")

    assert benign["P2P-B1"]["control_plane_generation"] == 1
    assert benign["P2P-B1"]["signing_key_epoch"] == 1
    assert benign["P2P-B1"]["safe_completion"] is True
    assert benign["P2P-B1"]["effect_count"] == 1

    assert benign["P2P-B2"]["control_plane_generation"] == 2
    assert benign["P2P-B2"]["signing_key_epoch"] == 2
    assert benign["P2P-B2"]["safe_completion"] is True
    assert benign["P2P-B2"]["effect_count"] == 1


def test_control_plane_generation_is_monotonic_and_compare_and_swap_bound(tmp_path: Path) -> None:
    store = ControlPlaneGenerationStore(tmp_path / "anchor.sqlite3")
    authority_id = "synthetic-authority"

    assert store.initialize(authority_id=authority_id, generation=1) == 1
    assert store.advance(authority_id=authority_id, expected_current=1) == 2
    with pytest.raises(ValueError, match="compare-and-swap"):
        store.advance(authority_id=authority_id, expected_current=1)
    with pytest.raises(ValueError, match="already initialized"):
        store.initialize(authority_id=authority_id, generation=1)


def test_signed_envelope_binds_control_plane_generation(tmp_path: Path) -> None:
    key_fixture = _key_fixture()
    anchor_fixture = _anchor_fixture()
    key1 = key_fixture["keys"][0]
    authority_id = str(anchor_fixture["authority_id"])

    case = _create_case(
        tmp_path,
        action=ApprovalAction.REQUEST_ACCESS,
        arguments={"resource": "synthetic-vpn", "justification": "Envelope tamper test"},
    )
    registry = TrustedAuthorizationKeyStore(case["effect_db"])
    _trust_initial(registry, key_fixture, key1)
    generation_store = ControlPlaneGenerationStore(tmp_path / "anchor.sqlite3")
    generation_store.initialize(authority_id=authority_id, generation=1)

    outbox = RevalidatingEffectOutboxStore(case["state_db"])
    record = outbox.get(case["approval_id"])
    signer = AnchoredAuthorizationSigner(_signer(key_fixture, key1))
    envelope = signer.issue(case["replica"].evaluate(record), control_plane_generation=1)
    generation_store.advance(authority_id=authority_id, expected_current=1)
    forged_payload = AnchoredAuthorizationPayload(
        control_plane_generation=2,
        decision=envelope.payload.decision,
    )
    forged = envelope.model_copy(update={"payload": forged_payload})

    service = RollbackResistantSyntheticEffectService(
        case["effect_db"],
        authoritative_versions=case["authoritative_versions"],
        trusted_keys=registry,
        generation_store=generation_store,
        authority_id=authority_id,
        expected_issuer_id=str(key_fixture["issuer_id"]),
        expected_audience=str(key_fixture["audience"]),
        clock=_clock,
    )
    with pytest.raises(RollbackAnchorError) as exc_info:
        service.execute_with_anchored_decision(record, forged)
    assert exc_info.value.reason is RollbackAnchorReason.ENVELOPE_SIGNATURE_INVALID
    assert service.count_effects(case["approval_id"]) == 0
