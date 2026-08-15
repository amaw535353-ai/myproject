from __future__ import annotations

from dataclasses import replace
import hashlib

from aegis.training.checkpoint_integrity_types import P9E_ASSESSMENT_MODE, P9E_ASSESSMENT_SCHEMA_VERSION
from aegis.training.data_poisoning_types import P9B_ASSESSMENT_MODE, P9B_ASSESSMENT_SCHEMA_VERSION
from aegis.training.data_provenance_types import P9A_ASSESSMENT_MODE, P9A_ASSESSMENT_SCHEMA_VERSION
from aegis.training.evaluation_governance_types import P9F_ASSESSMENT_MODE, P9F_ASSESSMENT_SCHEMA_VERSION
from aegis.training.fine_tuning_types import P9C_ASSESSMENT_MODE, P9C_ASSESSMENT_SCHEMA_VERSION
from aegis.training.model_promotion_types import P9H_ASSESSMENT_MODE, P9H_ASSESSMENT_SCHEMA_VERSION
from aegis.training.sensitive_data_types import P9G_ASSESSMENT_MODE, P9G_ASSESSMENT_SCHEMA_VERSION
from aegis.training.training_execution_types import P9D_ASSESSMENT_MODE, P9D_ASSESSMENT_SCHEMA_VERSION
from aegis.training.phase9_exit_types import (
    MILESTONE_DOMAINS, MILESTONE_ORDER, P9I_EXIT_POLICY_VERSION, P9I_EXIT_SCHEMA_VERSION,
    REQUIRED_SYNTHETIC_ASSUMPTIONS, SCENARIO_ORDER, ZERO_SHA256,
    CompromiseExerciseEvidence, Phase9ClaimProfile, Phase9ExitDecision, Phase9ExitManifest,
    Phase9ExitPolicy, Phase9ExitRequest, Phase9MilestoneEvidence, Phase9VerificationRecord,
    Phase9VerificationStatus, phase9_exit_manifest_digest,
)

NOW = 1_800_060_000
LINEAGE_ID = "phase9-integrated-training-compromise-lineage-001"
MANIFEST_ID = "phase9-exit-evidence-001"
REMOTE_BLOCK_REASON = "github-hosted-runner-account-billing-or-spending-limit"

MILESTONE_MANIFEST_SHA256 = {
    "P9-A": "5583a2a7bcebb464e1b305db178d57c7b6f74c706977701c8a1971fa62604eb6",
    "P9-B": "11277f13642c4302973f479b2ebf9c8e228058e88e638f8e33d131ce9532eabb",
    "P9-C": "19b893dac6ed7f3003df7ad5b35fe2c3b8a20d4823f678a9b19f1ed342254254",
    "P9-D": "c05279a1d945b5261b5c39f696bd7be15d6d7ef14d70cb56537410e2c2056bbe",
    "P9-E": "f959da93204ce6f682e6313e701f73ecdd77395a24151fb50de2dfab3811d744",
    "P9-F": "3a2e67ac73b68fbcfda37779429735cd4d9acdc72056e02eea79efa908c20231",
    "P9-G": "4dfb72a686f3fc12980d03317b251be9c712fa6cff0a194d9ad7e0728203d85c",
    "P9-H": "8166e90e7e7c04028628c02f10b3cf6c702686bf6c986bee31583b51501fa914",
}

MILESTONE_ASSESSMENT_SHA256 = {
    "P9-A": "b47663cd718ebe3493d2a0985301403a8925628b8d49a384b9d098f1822632c9",
    "P9-B": "084afbd8c147ba60a414fee1bf0c32bf0c9cfcb6f4178ab237fb3a4b3483b193",
    "P9-C": "0c2091bc9f2e50842f2d4642c3aca39ff4e444cc15a41d639579d7b98ec77729",
    "P9-D": "094b678ef6c3cff7a6751c6b2ec0765bef78e2546bd31fd7155476222080af3e",
    "P9-E": "e3464594fc8631d5a6a22fc68b5200e4f823778a0e09bfe4e3f1eb3717cc4c27",
    "P9-F": "53247ee9ca6297451a63910cbb9fdca19588d6fa76d1bd8b50b3ccabcab0ac03",
    "P9-G": "5f6fef4642e0f9d390ba7a7745f74290176608e4f0e24eafff7cb3de28cc5849",
    "P9-H": "8daa403475acdf99254740ac7ba1c6384696acd4eb3fb1b57b09d98232946888",
}

MILESTONE_VERIFICATION_SHA256 = {
    "P9-A": "1fd9de08c533e8569c3d8265c261bab3a2f9a1a9c72f0ca1b4f264b5f58269ec",
    "P9-B": "6f1141de704927d761c4d39ff019d719d5615a68555d2adda1e3c56c38f7d7b9",
    "P9-C": "c77ca7e352b0412553a6f9650e1524656772bd56cd3e3b2da428bcb74fbd5224",
    "P9-D": "b13c3bfb7aedab2cda9dc293f3f0ad7037080e7be2839ac39edebfdc40b272b6",
    "P9-E": "1107ce8477cba094b23dfd4b1f058c2518f9d6e120e7e075248abea9d2271fe6",
    "P9-F": "73c2a0276bbdc6884f19245927233afb394e42ccead1d428f52cc54c48a900ad",
    "P9-G": "aca0df27c879a37d2b8dc926ff9fe9ccabb366047e955e1582285371c0632b01",
    "P9-H": "fb0804d3f8c320657955815e08e66e4c49b87f27cb4c5a3b09a8e8217a1b7e3a",
}

ASSESSMENT_SCHEMA_BY_MILESTONE = {
    "P9-A": P9A_ASSESSMENT_SCHEMA_VERSION, "P9-B": P9B_ASSESSMENT_SCHEMA_VERSION,
    "P9-C": P9C_ASSESSMENT_SCHEMA_VERSION, "P9-D": P9D_ASSESSMENT_SCHEMA_VERSION,
    "P9-E": P9E_ASSESSMENT_SCHEMA_VERSION, "P9-F": P9F_ASSESSMENT_SCHEMA_VERSION,
    "P9-G": P9G_ASSESSMENT_SCHEMA_VERSION, "P9-H": P9H_ASSESSMENT_SCHEMA_VERSION,
}
ASSESSMENT_MODE_BY_MILESTONE = {
    "P9-A": P9A_ASSESSMENT_MODE, "P9-B": P9B_ASSESSMENT_MODE, "P9-C": P9C_ASSESSMENT_MODE,
    "P9-D": P9D_ASSESSMENT_MODE, "P9-E": P9E_ASSESSMENT_MODE, "P9-F": P9F_ASSESSMENT_MODE,
    "P9-G": P9G_ASSESSMENT_MODE, "P9-H": P9H_ASSESSMENT_MODE,
}

SCENARIO_SPECS = {
    "dataset-poisoning-to-promotion": ("training-data-poisoning", "P9-A", MILESTONE_ORDER, "P9-B"),
    "unauthorized-adapter-base-swap": ("fine-tuning-authorization-confusion", "P9-C", ("P9-C", "P9-D", "P9-E", "P9-F", "P9-G", "P9-H"), "P9-C"),
    "execution-secret-capability-escalation": ("training-job-privilege-escalation", "P9-D", ("P9-D", "P9-E", "P9-F", "P9-G", "P9-H"), "P9-D"),
    "checkpoint-rollback-substitution": ("checkpoint-rollback-and-state-substitution", "P9-E", ("P9-E", "P9-F", "P9-G", "P9-H"), "P9-E"),
    "benchmark-contamination-score-inflation": ("evaluation-contamination-and-score-inflation", "P9-F", ("P9-F", "P9-G", "P9-H"), "P9-F"),
    "sensitive-data-canary-reproduction": ("sensitive-data-and-canary-reproduction", "P9-G", ("P9-G", "P9-H"), "P9-G"),
    "registry-artifact-reference-substitution": ("model-registry-artifact-and-reference-substitution", "P9-H", ("P9-H",), "P9-H"),
    "upstream-assessment-replay-at-promotion": ("transitive-upstream-assessment-replay", "P9-A", MILESTONE_ORDER, "P9-H"),
}


def h(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _milestones() -> tuple[Phase9MilestoneEvidence, ...]:
    result = []
    previous_assessment = ZERO_SHA256
    previous_state = ZERO_SHA256
    for index, milestone_id in enumerate(MILESTONE_ORDER, start=1):
        assessment_sha = MILESTONE_ASSESSMENT_SHA256[milestone_id]
        output_state = h(f"{LINEAGE_ID}:{milestone_id}:{assessment_sha}:{previous_state}:output-state")
        result.append(Phase9MilestoneEvidence(milestone_id=milestone_id, control_domain=MILESTONE_DOMAINS[milestone_id], step_index=index, training_lineage_id=LINEAGE_ID, manifest_sha256=MILESTONE_MANIFEST_SHA256[milestone_id], assessment_sha256=assessment_sha, predecessor_assessment_sha256=previous_assessment, input_state_sha256=previous_state, output_state_sha256=output_state, assessment_schema_version=ASSESSMENT_SCHEMA_BY_MILESTONE[milestone_id], assessment_mode=ASSESSMENT_MODE_BY_MILESTONE[milestone_id], safe=True, caller_declared_safety_trusted=False, network_operations=0))
        previous_assessment, previous_state = assessment_sha, output_state
    return tuple(result)


def _compromise_exercises() -> tuple[CompromiseExerciseEvidence, ...]:
    result = []
    for scenario_id in SCENARIO_ORDER:
        attack_class, entry, path, detection = SCENARIO_SPECS[scenario_id]
        result.append(CompromiseExerciseEvidence(scenario_id=scenario_id, attack_class=attack_class, entry_milestone_id=entry, propagation_path=tuple(path), attack_input_sha256=h(f"{LINEAGE_ID}:{scenario_id}:attack-input"), detection_milestone_id=detection, detected=True, promotion_blocked=True, recovery_state_sha256=h(f"{LINEAGE_ID}:{scenario_id}:recovery-state"), network_operations=0))
    return tuple(result)


def _verification_records(remote_status: Phase9VerificationStatus = Phase9VerificationStatus.REMOTE_CI_BLOCKED) -> tuple[Phase9VerificationRecord, ...]:
    records = [Phase9VerificationRecord(verification_id=f"local-{milestone_id.lower()}", scope=milestone_id, status=Phase9VerificationStatus.LOCAL_FOCUSED_PASS, evidence_sha256=MILESTONE_VERIFICATION_SHA256[milestone_id], runner_started=True, steps_executed=1) for milestone_id in MILESTONE_ORDER]
    if remote_status == Phase9VerificationStatus.REMOTE_CI_BLOCKED:
        records.append(Phase9VerificationRecord("remote-phase9-ci", "Phase9", remote_status, h("remote-phase9-ci:blocked:billing-or-spending-limit"), False, 0, REMOTE_BLOCK_REASON))
    elif remote_status == Phase9VerificationStatus.REMOTE_CI_PASS:
        records.append(Phase9VerificationRecord("remote-phase9-ci", "Phase9", remote_status, h("remote-phase9-ci:pass"), True, 12, ""))
    else:
        records.append(Phase9VerificationRecord("remote-phase9-ci", "Phase9", remote_status, h("remote-phase9-ci:executed-failure"), True, 5, "tests-failed"))
    return tuple(records)


def build_fixture(remote_status: Phase9VerificationStatus = Phase9VerificationStatus.REMOTE_CI_BLOCKED) -> dict[str, object]:
    milestones = _milestones(); exercises = _compromise_exercises()
    manifest = Phase9ExitManifest(MANIFEST_ID, P9I_EXIT_SCHEMA_VERSION, NOW, LINEAGE_ID, milestones, exercises, _verification_records(remote_status), REQUIRED_SYNTHETIC_ASSUMPTIONS, Phase9ClaimProfile())
    policy = Phase9ExitPolicy(policy_version=P9I_EXIT_POLICY_VERSION, expected_manifest_id=MANIFEST_ID, expected_manifest_sha256=phase9_exit_manifest_digest(manifest), expected_training_lineage_id=LINEAGE_ID, expected_assessment_sha256_by_milestone={i.milestone_id:i.assessment_sha256 for i in milestones}, expected_manifest_sha256_by_milestone={i.milestone_id:i.manifest_sha256 for i in milestones}, expected_output_state_sha256_by_milestone={i.milestone_id:i.output_state_sha256 for i in milestones}, expected_assessment_schema_by_milestone={i.milestone_id:i.assessment_schema_version for i in milestones}, expected_assessment_mode_by_milestone={i.milestone_id:i.assessment_mode for i in milestones}, expected_scenario_order=SCENARIO_ORDER, expected_attack_class_by_scenario={i.scenario_id:i.attack_class for i in exercises}, expected_entry_milestone_by_scenario={i.scenario_id:i.entry_milestone_id for i in exercises}, expected_propagation_path_by_scenario={i.scenario_id:i.propagation_path for i in exercises}, expected_attack_input_sha256_by_scenario={i.scenario_id:i.attack_input_sha256 for i in exercises}, expected_detection_milestone_by_scenario={i.scenario_id:i.detection_milestone_id for i in exercises}, expected_recovery_state_sha256_by_scenario={i.scenario_id:i.recovery_state_sha256 for i in exercises}, required_local_verification_scopes=MILESTONE_ORDER, allowed_external_ci_block_reasons=(REMOTE_BLOCK_REASON,), max_manifest_age_seconds=3600, max_future_skew_seconds=30)
    decision = Phase9ExitDecision.PASS_WITH_EXTERNAL_CI_LIMITATION if remote_status == Phase9VerificationStatus.REMOTE_CI_BLOCKED else Phase9ExitDecision.PASS if remote_status == Phase9VerificationStatus.REMOTE_CI_PASS else Phase9ExitDecision.FAIL
    request = Phase9ExitRequest(MANIFEST_ID, phase9_exit_manifest_digest(manifest), P9I_EXIT_POLICY_VERSION, NOW+10, decision, {i.milestone_id:i.assessment_sha256 for i in milestones}, {i.scenario_id:i.detected for i in exercises}, {i.scenario_id:i.promotion_blocked for i in exercises}, {i.verification_id:i.status.value for i in manifest.verification_records})
    return {"manifest":manifest,"policy":policy,"request":request}


def rebind(fixture: dict[str, object], manifest: Phase9ExitManifest, *, keep_policy_pins: bool = True) -> dict[str, object]:
    policy: Phase9ExitPolicy = fixture["policy"]  # type: ignore[assignment]
    if not keep_policy_pins:
        policy = replace(policy, expected_manifest_sha256=phase9_exit_manifest_digest(manifest))
    request: Phase9ExitRequest = fixture["request"]  # type: ignore[assignment]
    request = replace(request, manifest_sha256=phase9_exit_manifest_digest(manifest), declared_assessment_sha256_by_milestone={i.milestone_id:i.assessment_sha256 for i in manifest.milestone_evidence}, declared_scenario_detection_by_id={i.scenario_id:i.detected for i in manifest.compromise_exercises}, declared_scenario_promotion_blocked_by_id={i.scenario_id:i.promotion_blocked for i in manifest.compromise_exercises}, declared_verification_status_by_id={i.verification_id:i.status.value for i in manifest.verification_records})
    return {"manifest":manifest,"policy":policy,"request":request}
