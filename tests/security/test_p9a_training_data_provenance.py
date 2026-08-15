from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.training import (
    P9A_ASSESSMENT_MODE,
    P9A_ASSESSMENT_SCHEMA_VERSION,
    P9A_DATASET_POLICY_VERSION,
    P9A_DATASET_SCHEMA_VERSION,
    DatasetSplit,
    TrainingDataDecision,
    TrainingDataRisk,
    TrainingDataSecurityRejected,
    TrainingDatasetProvenanceAnalyzer,
    training_dataset_manifest_digest,
)
from aegis.vulnerable.training_data_provenance import VulnerableCallerDeclaredTrainingDataTrust
from evals.p9a_fixture import NOW, RECORD_IDS, SOURCE_IDS, build_fixture
from evals.p9a_training_data_provenance import CASES, EXPECTED_ADVERSARIAL_CASES, run


def _attack(name: str):
    return dict(CASES)[name](build_fixture())


def _derived_risks(name: str):
    f = _attack(name)
    return TrainingDatasetProvenanceAnalyzer(f["policy"]).derive(f["manifest"], f["request"].evaluated_at_epoch)


def test_clean_fixture_allows_exact_training_dataset_lineage():
    f = build_fixture()
    assessment = TrainingDatasetProvenanceAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"])
    assert assessment.decision == TrainingDataDecision.ALLOW
    assert assessment.source_count == 3
    assert assessment.record_count == 12
    assert assessment.split_counts == {
        DatasetSplit.TRAIN: 6,
        DatasetSplit.VALIDATION: 3,
        DatasetSplit.TEST: 3,
    }
    assert assessment.transform_count == 3


def test_policy_schema_and_mode_versions_are_pinned():
    assert P9A_DATASET_POLICY_VERSION == "training-dataset-provenance-lineage-v1"
    assert P9A_DATASET_SCHEMA_VERSION == "aegis-training-dataset-manifest-v1"
    assert P9A_ASSESSMENT_SCHEMA_VERSION == "aegis-training-dataset-assessment-v1"
    assert P9A_ASSESSMENT_MODE == "deterministic-evidence-bound-training-data-provenance-v1"


def test_manifest_digest_is_exact_and_content_sensitive():
    f = build_fixture()
    original = training_dataset_manifest_digest(f["manifest"])
    changed = replace(f["manifest"], created_at_epoch=f["manifest"].created_at_epoch - 1)
    assert original == f["policy"].expected_manifest_sha256
    assert training_dataset_manifest_digest(changed) != original


def test_assessment_exposes_only_supported_local_claims():
    f = build_fixture()
    assessment = TrainingDatasetProvenanceAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"])
    assert assessment.exact_manifest_binding_verified
    assert assessment.trusted_source_snapshots_verified
    assert assessment.record_hash_coverage_verified
    assert assessment.split_isolation_verified
    assert assessment.transform_lineage_verified
    assert not assessment.caller_declared_training_data_safety_trusted
    assert not assessment.production_data_lake_integration
    assert not assessment.production_training_pipeline_attestation
    assert not assessment.cryptographic_source_authentication
    assert assessment.network_operations == 0


def test_vulnerable_baseline_trusts_caller_training_data_assertions():
    vulnerable = VulnerableCallerDeclaredTrainingDataTrust()
    assert vulnerable.accepts(declared_training_data_safe=True, declared_provenance_complete=True)


def test_untrusted_source_owner_is_denied():
    assert TrainingDataRisk.SOURCE_OWNER_UNTRUSTED in _derived_risks("source-owner-src-helpdesk")


def test_mutable_or_wrong_source_revision_is_denied():
    assert TrainingDataRisk.SOURCE_REVISION_MISMATCH in _derived_risks("source-revision-src-security")


def test_source_snapshot_digest_substitution_is_denied():
    assert TrainingDataRisk.SOURCE_DIGEST_MISMATCH in _derived_risks("source-digest-src-synthetic")


def test_record_payload_substitution_is_denied():
    assert TrainingDataRisk.RECORD_DIGEST_MISMATCH in _derived_risks("record-digest-record-01")


def test_record_source_laundering_is_denied():
    assert TrainingDataRisk.RECORD_SOURCE_MISMATCH in _derived_risks("record-source-record-05")


def test_record_parent_injection_is_denied():
    assert TrainingDataRisk.RECORD_PARENT_MISMATCH in _derived_risks("record-parent-record-04")


def test_split_reassignment_is_denied():
    assert TrainingDataRisk.SPLIT_ASSIGNMENT_MISMATCH in _derived_risks("split-move-record-02")


def test_holdout_overlap_into_training_is_denied():
    risks = _derived_risks("holdout-overlap-train-record-10")
    assert TrainingDataRisk.SPLIT_OVERLAP in risks
    assert TrainingDataRisk.HOLDOUT_LEAKAGE in risks


def test_transform_owner_and_config_are_policy_bound():
    assert TrainingDataRisk.TRANSFORM_OWNER_MISMATCH in _derived_risks("transform-owner-transform-dedupe")
    assert TrainingDataRisk.TRANSFORM_CONFIG_MISMATCH in _derived_risks("transform-config-transform-canonicalize")


def test_transform_chain_substitution_is_denied():
    assert TrainingDataRisk.TRANSFORM_CHAIN_BROKEN in _derived_risks("transform-input-transform-normalize")
    assert TrainingDataRisk.TRANSFORM_CHAIN_BROKEN in _derived_risks("transform-predecessor-transform-dedupe")


def test_preprocessing_network_side_effect_is_not_silently_accepted():
    assert TrainingDataRisk.NETWORK_SIDE_EFFECT_REPORTED in _derived_risks("transform-network-transform-canonicalize")


def test_caller_declared_summary_cannot_override_evidence():
    f = _attack("request-record-count")
    with pytest.raises(TrainingDataSecurityRejected):
        TrainingDatasetProvenanceAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"])


def test_outer_manifest_seal_rejects_unpinned_substitution():
    f = _attack("manifest-outer-digest-substitution")
    with pytest.raises(TrainingDataSecurityRejected):
        TrainingDatasetProvenanceAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"])


def test_source_freshness_is_checked():
    assert TrainingDataRisk.SOURCE_TIME_INVALID in _derived_risks("source-too-old-src-helpdesk")
    assert TrainingDataRisk.SOURCE_TIME_INVALID in _derived_risks("source-future-src-security")


def test_safe_evaluation_time_variants_remain_allowed():
    for offset in (0, 1, 2, 3):
        f = build_fixture()
        f["request"] = replace(f["request"], evaluated_at_epoch=NOW + offset)
        assessment = TrainingDatasetProvenanceAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"])
        assert assessment.decision == TrainingDataDecision.ALLOW


def test_evaluator_metrics_are_deterministic():
    result = run()
    assert EXPECTED_ADVERSARIAL_CASES == 157
    assert result["adversarial_cases"] == 157
    assert result["vulnerable_asr"] == "157/157"
    assert result["hardened_asr"] == "0/157"
    assert result["hardened_fpr"] == "0/4"
    assert result["safe_task_rate"] == "4/4"
    assert result["blocked_case_count"] == 157
