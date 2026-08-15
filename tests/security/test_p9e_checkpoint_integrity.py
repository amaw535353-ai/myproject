from dataclasses import replace

import pytest

from aegis.training.checkpoint_integrity_security import TrainingCheckpointIntegrityAnalyzer
from aegis.training.checkpoint_integrity_types import *
from aegis.training.training_execution_types import TrainingExecutionDecision
from evals.p9e_checkpoint_integrity import adversarial_cases
from evals.p9e_fixture import build_fixture, rebind


def test_clean_resume_is_allowed():
    f = build_fixture()
    assessment = TrainingCheckpointIntegrityAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9d"])
    assert assessment.decision == CheckpointDecision.ALLOW
    assert assessment.upstream_p9d_bound
    assert assessment.checkpoint_lineage_verified
    assert assessment.checkpoint_state_integrity_verified
    assert assessment.operation_authorization_verified
    assert assessment.rollback_safe
    assert not assessment.caller_declared_safety_trusted
    assert not assessment.production_checkpoint_store_integrated
    assert not assessment.cryptographic_checkpoint_signature_verified
    assert not assessment.proof_of_resume_execution


def test_all_adversarial_cases_fail_closed():
    for name, f in adversarial_cases():
        analyzer = TrainingCheckpointIntegrityAnalyzer(f["policy"])
        try:
            assessment = analyzer.evaluate(f["request"], f["manifest"], f["p9d"])
        except CheckpointSecurityRejected:
            continue
        assert assessment.decision == CheckpointDecision.DENY, name


def test_authorized_rollback_to_allowlisted_parent_is_allowed():
    f = build_fixture()
    m = f["manifest"]
    auth = replace(
        m.authorization,
        action=CheckpointAction.ROLLBACK,
        source_checkpoint_id=m.checkpoints[2].checkpoint_id,
        target_checkpoint_id=m.checkpoints[1].checkpoint_id,
        reason_code="approved-rollback:incident-001",
    )
    rollback = replace(
        m,
        action=CheckpointAction.ROLLBACK,
        source_checkpoint_id=m.checkpoints[2].checkpoint_id,
        target_checkpoint_id=m.checkpoints[1].checkpoint_id,
        next_step=401,
        authorization=auth,
    )
    f = rebind(f, manifest=rollback)
    assessment = TrainingCheckpointIntegrityAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9d"])
    assert assessment.decision == CheckpointDecision.ALLOW
    assert assessment.rollback_safe


def test_rollback_to_unapproved_root_is_denied():
    f = build_fixture()
    m = f["manifest"]
    auth = replace(
        m.authorization,
        action=CheckpointAction.ROLLBACK,
        source_checkpoint_id=m.checkpoints[2].checkpoint_id,
        target_checkpoint_id=m.checkpoints[0].checkpoint_id,
        reason_code="approved-rollback:incident-001",
    )
    rollback = replace(
        m,
        action=CheckpointAction.ROLLBACK,
        source_checkpoint_id=m.checkpoints[2].checkpoint_id,
        target_checkpoint_id=m.checkpoints[0].checkpoint_id,
        next_step=1,
        authorization=auth,
    )
    f = rebind(f, manifest=rollback)
    with pytest.raises(CheckpointSecurityRejected):
        TrainingCheckpointIntegrityAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9d"])


def test_swapped_optimizer_state_is_denied():
    f = build_fixture()
    m = f["manifest"]
    items = list(m.checkpoints)
    items[2] = replace(items[2], optimizer_state_sha256=items[1].optimizer_state_sha256)
    f = rebind(f, manifest=replace(m, checkpoints=tuple(items)))
    with pytest.raises(CheckpointSecurityRejected):
        TrainingCheckpointIntegrityAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9d"])


def test_swapped_rng_state_is_denied():
    f = build_fixture()
    m = f["manifest"]
    items = list(m.checkpoints)
    items[2] = replace(items[2], rng_state_sha256=items[1].rng_state_sha256)
    f = rebind(f, manifest=replace(m, checkpoints=tuple(items)))
    with pytest.raises(CheckpointSecurityRejected):
        TrainingCheckpointIntegrityAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9d"])


def test_non_monotonic_step_is_denied():
    f = build_fixture()
    m = f["manifest"]
    items = list(m.checkpoints)
    items[2] = replace(items[2], step=400)
    f = rebind(f, manifest=replace(m, checkpoints=tuple(items)))
    with pytest.raises(CheckpointSecurityRejected):
        TrainingCheckpointIntegrityAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9d"])


def test_cross_job_checkpoint_is_denied():
    f = build_fixture()
    m = f["manifest"]
    items = list(m.checkpoints)
    items[1] = replace(items[1], job_id="other-job")
    f = rebind(f, manifest=replace(m, checkpoints=tuple(items)))
    with pytest.raises(CheckpointSecurityRejected):
        TrainingCheckpointIntegrityAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9d"])


def test_external_checkpoint_reference_is_denied():
    f = build_fixture()
    m = f["manifest"]
    items = list(m.checkpoints)
    items[2] = replace(items[2], external_reference=True)
    f = rebind(f, manifest=replace(m, checkpoints=tuple(items)))
    with pytest.raises(CheckpointSecurityRejected):
        TrainingCheckpointIntegrityAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9d"])


def test_custom_deserializer_is_denied():
    f = build_fixture()
    m = f["manifest"]
    items = list(m.checkpoints)
    items[2] = replace(items[2], custom_deserializer=True)
    f = rebind(f, manifest=replace(m, checkpoints=tuple(items)))
    with pytest.raises(CheckpointSecurityRejected):
        TrainingCheckpointIntegrityAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9d"])


def test_expired_operation_authorization_is_denied():
    f = build_fixture()
    m = f["manifest"]
    expired = replace(m.authorization, expires_at_epoch=m.created_at_epoch - 1)
    f = rebind(f, manifest=replace(m, authorization=expired))
    with pytest.raises(CheckpointSecurityRejected):
        TrainingCheckpointIntegrityAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9d"])


def test_upstream_production_claim_is_not_accepted():
    f = build_fixture()
    f = rebind(f, p9d=replace(f["p9d"], production_scheduler_integrated=True))
    with pytest.raises(CheckpointSecurityRejected):
        TrainingCheckpointIntegrityAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9d"])


def test_upstream_execution_proof_claim_is_not_accepted():
    f = build_fixture()
    f = rebind(f, p9d=replace(f["p9d"], proof_of_training_execution=True))
    with pytest.raises(CheckpointSecurityRejected):
        TrainingCheckpointIntegrityAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9d"])


def test_request_replay_is_rejected():
    f = build_fixture()
    f["request"] = replace(f["request"], evaluated_at_epoch=f["manifest"].created_at_epoch + 301)
    with pytest.raises(CheckpointSecurityRejected) as exc:
        TrainingCheckpointIntegrityAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9d"])
    assert exc.value.reason == CheckpointRejectReason.REQUEST_INVALID


def test_caller_cannot_override_denial():
    f = build_fixture()
    p9d = replace(f["p9d"], decision=TrainingExecutionDecision.DENY)
    f = rebind(f, p9d=p9d)
    with pytest.raises(CheckpointSecurityRejected):
        TrainingCheckpointIntegrityAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"], f["p9d"])


def test_policy_rejects_missing_checkpoint_pin():
    f = build_fixture()
    bad = replace(f["policy"], expected_checkpoint_step_by_id={f["manifest"].checkpoints[0].checkpoint_id: 0})
    with pytest.raises(CheckpointSecurityRejected) as exc:
        TrainingCheckpointIntegrityAnalyzer(bad)
    assert exc.value.reason == CheckpointRejectReason.POLICY_INVALID
