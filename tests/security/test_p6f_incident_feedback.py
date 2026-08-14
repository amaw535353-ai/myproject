from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.assurance.corpus_evolution import change_manifest_digest
from aegis.assurance.incident_feedback import (
    IncidentFeedbackRejectReason,
    IncidentFeedbackRejected,
    IncidentToAssuranceFeedbackGate,
    incident_feedback_digest,
)
from evals.p6f_incident_feedback import adversarial_variants, build_fixture, run_hardened


def test_p6f_happy_path_returns_inert_verified_feedback():
    fixture = build_fixture()
    verified = run_hardened(fixture)
    assert verified.incident_integrity_verified
    assert verified.exact_incident_binding_verified
    assert verified.exact_evolution_binding_verified
    assert verified.append_only_obligation_ledger_verified
    assert verified.exact_case_links_verified
    assert verified.threat_signal_coverage_verified
    assert verified.historical_incident_coverage_verified
    assert verified.p6c_future_removal_governance_required
    assert not verified.semantic_equivalence_proven
    assert not verified.automatic_test_generation
    assert not verified.production_incident_management
    assert not verified.rollback_resistant_ledger
    assert verified.network_operations == 0


@pytest.mark.parametrize("name,fixture", adversarial_variants(), ids=lambda item: item if isinstance(item, str) else None)
def test_p6f_adversarial_variants_fail_closed(name, fixture):
    with pytest.raises(IncidentFeedbackRejected):
        run_hardened(fixture)


@pytest.mark.parametrize("suffix", ["A", "B", "C"])
def test_p6f_benign_feedback_variants_pass(suffix):
    fixture = build_fixture()
    fixture["feedback"] = replace(
        fixture["feedback"],
        feedback_id=f"{fixture['feedback'].feedback_id}-{suffix}",
    )
    expected_reason = (
        f"incident-feedback:{fixture['feedback'].feedback_id}:"
        f"{fixture['incident'].incident_id}:{fixture['incident'].batch_sha256}"
    )
    change = replace(fixture["manifest"].changes[0], reason=expected_reason)
    fixture["manifest"] = replace(fixture["manifest"], changes=(change,))
    manifest_sha = change_manifest_digest(fixture["manifest"])
    fixture["evolution"] = replace(fixture["evolution"], change_manifest_sha256=manifest_sha)
    fixture["feedback"] = replace(fixture["feedback"], change_manifest_sha256=manifest_sha)
    fixture["request"] = replace(
        fixture["request"],
        feedback_id=fixture["feedback"].feedback_id,
        feedback_sha256=incident_feedback_digest(fixture["feedback"]),
    )
    verified = run_hardened(fixture)
    assert verified.feedback_id.endswith(suffix)


def test_p6f_feedback_id_replay_is_rejected():
    fixture = build_fixture()
    gate = IncidentToAssuranceFeedbackGate(fixture["policy"])
    args = (
        fixture["request"], fixture["feedback"], fixture["incident"],
        fixture["baseline"], fixture["candidate"], fixture["manifest"],
        fixture["evolution"], fixture["previous_ledger"], fixture["candidate_ledger"],
    )
    gate.evaluate(*args)
    with pytest.raises(IncidentFeedbackRejected) as exc_info:
        gate.evaluate(*args)
    assert exc_info.value.reason == IncidentFeedbackRejectReason.FEEDBACK_DUPLICATE
