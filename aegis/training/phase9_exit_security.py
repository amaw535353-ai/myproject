from __future__ import annotations

import re

from .phase9_exit_types import (
    MILESTONE_DOMAINS,
    MILESTONE_ORDER,
    P9I_ASSESSMENT_MODE,
    P9I_ASSESSMENT_SCHEMA_VERSION,
    P9I_EXIT_POLICY_VERSION,
    P9I_EXIT_SCHEMA_VERSION,
    PRODUCTION_CLAIM_FIELDS,
    REQUIRED_SYNTHETIC_ASSUMPTIONS,
    SCENARIO_ORDER,
    ZERO_SHA256,
    Phase9ExitAssessment,
    Phase9ExitDecision,
    Phase9ExitManifest,
    Phase9ExitPolicy,
    Phase9ExitRejectReason,
    Phase9ExitRequest,
    Phase9ExitRisk,
    Phase9VerificationStatus,
    _digest_json,
    phase9_exit_manifest_digest,
    reject,
)

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class Phase9IntegratedExitGate:
    def __init__(self, policy: Phase9ExitPolicy):
        self.policy = policy
        self._validate_policy()

    @staticmethod
    def _sha(value: str) -> bool:
        return bool(_SHA256_RE.fullmatch(str(value)))

    @staticmethod
    def _ordered_path(path: tuple[str, ...]) -> bool:
        if not path or len(path) != len(set(path)):
            return False
        try:
            indices = tuple(MILESTONE_ORDER.index(item) for item in path)
        except ValueError:
            return False
        return indices == tuple(sorted(indices))

    def _validate_policy(self) -> None:
        p = self.policy
        if p.policy_version != P9I_EXIT_POLICY_VERSION:
            reject(Phase9ExitRejectReason.POLICY_INVALID, "unexpected policy version")
        if not p.expected_manifest_id or not p.expected_training_lineage_id:
            reject(Phase9ExitRejectReason.POLICY_INVALID, "manifest and training-lineage identities are required")
        if not self._sha(p.expected_manifest_sha256):
            reject(Phase9ExitRejectReason.POLICY_INVALID, "expected exit manifest digest must be SHA-256")
        expected = set(MILESTONE_ORDER)
        milestone_maps = (p.expected_assessment_sha256_by_milestone, p.expected_manifest_sha256_by_milestone, p.expected_output_state_sha256_by_milestone, p.expected_assessment_schema_by_milestone, p.expected_assessment_mode_by_milestone)
        if any(set(mapping) != expected for mapping in milestone_maps):
            reject(Phase9ExitRejectReason.POLICY_INVALID, "milestone policy pins must exactly cover P9-A through P9-H")
        for mapping in (p.expected_assessment_sha256_by_milestone, p.expected_manifest_sha256_by_milestone, p.expected_output_state_sha256_by_milestone):
            if any(not self._sha(value) for value in mapping.values()):
                reject(Phase9ExitRejectReason.POLICY_INVALID, "milestone digest pins must be SHA-256")
        if p.expected_scenario_order != SCENARIO_ORDER:
            reject(Phase9ExitRejectReason.POLICY_INVALID, "scenario order must match the Phase 9 compromise profile")
        scenario_ids = set(SCENARIO_ORDER)
        scenario_maps = (p.expected_attack_class_by_scenario, p.expected_entry_milestone_by_scenario, p.expected_propagation_path_by_scenario, p.expected_attack_input_sha256_by_scenario, p.expected_detection_milestone_by_scenario, p.expected_recovery_state_sha256_by_scenario)
        if any(set(mapping) != scenario_ids for mapping in scenario_maps):
            reject(Phase9ExitRejectReason.POLICY_INVALID, "scenario policy pins must exactly cover the compromise profile")
        for scenario_id in SCENARIO_ORDER:
            entry = p.expected_entry_milestone_by_scenario[scenario_id]
            path = tuple(p.expected_propagation_path_by_scenario[scenario_id])
            detection = p.expected_detection_milestone_by_scenario[scenario_id]
            if (entry not in MILESTONE_ORDER or detection not in MILESTONE_ORDER or not self._ordered_path(path) or path[0] != entry or detection not in path or not p.expected_attack_class_by_scenario[scenario_id] or not self._sha(p.expected_attack_input_sha256_by_scenario[scenario_id]) or not self._sha(p.expected_recovery_state_sha256_by_scenario[scenario_id])):
                reject(Phase9ExitRejectReason.POLICY_INVALID, "compromise scenario policy pin is invalid")
        if len(set(p.required_local_verification_scopes)) != len(p.required_local_verification_scopes) or set(p.required_local_verification_scopes) != expected:
            reject(Phase9ExitRejectReason.POLICY_INVALID, "local verification scopes must exactly cover P9-A through P9-H")
        if p.max_manifest_age_seconds < 0 or p.max_future_skew_seconds < 0:
            reject(Phase9ExitRejectReason.POLICY_INVALID, "freshness limits must be non-negative")

    def _validate_manifest_shape(self, manifest: Phase9ExitManifest) -> None:
        if manifest.schema_version != P9I_EXIT_SCHEMA_VERSION:
            reject(Phase9ExitRejectReason.MANIFEST_INVALID, "unexpected exit manifest schema")
        if manifest.manifest_id != self.policy.expected_manifest_id or manifest.training_lineage_id != self.policy.expected_training_lineage_id:
            reject(Phase9ExitRejectReason.MANIFEST_INVALID, "exit manifest identity mismatch")
        if len({item.milestone_id for item in manifest.milestone_evidence}) != len(manifest.milestone_evidence):
            reject(Phase9ExitRejectReason.MANIFEST_INVALID, "duplicate milestone identity")
        if len({item.scenario_id for item in manifest.compromise_exercises}) != len(manifest.compromise_exercises):
            reject(Phase9ExitRejectReason.MANIFEST_INVALID, "duplicate compromise scenario identity")
        if len({item.verification_id for item in manifest.verification_records}) != len(manifest.verification_records):
            reject(Phase9ExitRejectReason.MANIFEST_INVALID, "duplicate verification identity")
        for item in manifest.milestone_evidence:
            if not all(self._sha(value) for value in (item.manifest_sha256, item.assessment_sha256, item.predecessor_assessment_sha256, item.input_state_sha256, item.output_state_sha256)) or item.network_operations < 0:
                reject(Phase9ExitRejectReason.MANIFEST_INVALID, "milestone evidence is malformed")
        for scenario in manifest.compromise_exercises:
            if (not scenario.scenario_id or not scenario.attack_class or scenario.entry_milestone_id not in MILESTONE_ORDER or scenario.detection_milestone_id not in MILESTONE_ORDER or not self._ordered_path(scenario.propagation_path) or not self._sha(scenario.attack_input_sha256) or not self._sha(scenario.recovery_state_sha256) or scenario.network_operations < 0):
                reject(Phase9ExitRejectReason.MANIFEST_INVALID, "compromise exercise evidence is malformed")
        for verification in manifest.verification_records:
            if not self._sha(verification.evidence_sha256) or verification.steps_executed < 0:
                reject(Phase9ExitRejectReason.MANIFEST_INVALID, "verification evidence is malformed")

    def derive(self, manifest: Phase9ExitManifest, now: int) -> tuple[tuple[Phase9ExitRisk, ...], Phase9ExitDecision, dict[str, object]]:
        self._validate_manifest_shape(manifest)
        p = self.policy
        risks: set[Phase9ExitRisk] = set()
        milestone_ids = tuple(item.milestone_id for item in manifest.milestone_evidence)
        if set(milestone_ids) != set(MILESTONE_ORDER) or len(milestone_ids) != len(MILESTONE_ORDER):
            risks.add(Phase9ExitRisk.MILESTONE_COVERAGE_INVALID)
        if milestone_ids != MILESTONE_ORDER:
            risks.add(Phase9ExitRisk.MILESTONE_ORDER_INVALID)
        previous_assessment = ZERO_SHA256
        previous_state = ZERO_SHA256
        milestone_by_id = {item.milestone_id: item for item in manifest.milestone_evidence}
        for index, milestone_id in enumerate(MILESTONE_ORDER, start=1):
            item = milestone_by_id.get(milestone_id)
            if item is None:
                continue
            if item.control_domain != MILESTONE_DOMAINS[milestone_id]:
                risks.add(Phase9ExitRisk.DOMAIN_BINDING_MISMATCH)
            if item.step_index != index or item.training_lineage_id != manifest.training_lineage_id:
                risks.add(Phase9ExitRisk.LINEAGE_MISMATCH)
            if item.predecessor_assessment_sha256.casefold() != previous_assessment.casefold():
                risks.add(Phase9ExitRisk.EVIDENCE_CHAIN_BROKEN)
            if item.input_state_sha256.casefold() != previous_state.casefold() or item.output_state_sha256.casefold() != p.expected_output_state_sha256_by_milestone[milestone_id].casefold():
                risks.add(Phase9ExitRisk.LINEAGE_MISMATCH)
            if (item.assessment_schema_version != p.expected_assessment_schema_by_milestone[milestone_id] or item.assessment_mode != p.expected_assessment_mode_by_milestone[milestone_id] or item.assessment_sha256.casefold() != p.expected_assessment_sha256_by_milestone[milestone_id].casefold() or item.manifest_sha256.casefold() != p.expected_manifest_sha256_by_milestone[milestone_id].casefold()):
                risks.add(Phase9ExitRisk.EVIDENCE_DIGEST_MISMATCH)
            if not item.safe:
                risks.add(Phase9ExitRisk.UPSTREAM_SAFETY_FAILED)
            if item.caller_declared_safety_trusted:
                risks.add(Phase9ExitRisk.CALLER_DECLARED_SAFETY_TRUSTED)
            if item.network_operations != 0:
                risks.add(Phase9ExitRisk.NETWORK_SIDE_EFFECT_REPORTED)
            previous_assessment = item.assessment_sha256
            previous_state = item.output_state_sha256
        scenario_ids = tuple(item.scenario_id for item in manifest.compromise_exercises)
        if set(scenario_ids) != set(p.expected_scenario_order) or len(scenario_ids) != len(p.expected_scenario_order):
            risks.add(Phase9ExitRisk.COMPROMISE_SCENARIO_COVERAGE_INVALID)
        if scenario_ids != p.expected_scenario_order:
            risks.add(Phase9ExitRisk.COMPROMISE_SCENARIO_ORDER_INVALID)
        scenario_by_id = {item.scenario_id: item for item in manifest.compromise_exercises}
        for scenario_id in p.expected_scenario_order:
            scenario = scenario_by_id.get(scenario_id)
            if scenario is None:
                continue
            if (scenario.attack_class != p.expected_attack_class_by_scenario[scenario_id] or scenario.entry_milestone_id != p.expected_entry_milestone_by_scenario[scenario_id] or tuple(scenario.propagation_path) != tuple(p.expected_propagation_path_by_scenario[scenario_id]) or scenario.attack_input_sha256.casefold() != p.expected_attack_input_sha256_by_scenario[scenario_id].casefold() or scenario.detection_milestone_id != p.expected_detection_milestone_by_scenario[scenario_id] or scenario.recovery_state_sha256.casefold() != p.expected_recovery_state_sha256_by_scenario[scenario_id].casefold() or scenario.propagation_path[0] != scenario.entry_milestone_id or scenario.detection_milestone_id not in scenario.propagation_path):
                risks.add(Phase9ExitRisk.COMPROMISE_SCENARIO_BINDING_MISMATCH)
            if not scenario.detected:
                risks.add(Phase9ExitRisk.COMPROMISE_NOT_DETECTED)
            if not scenario.promotion_blocked:
                risks.add(Phase9ExitRisk.PROMOTION_FAIL_OPEN)
            if scenario.network_operations != 0:
                risks.add(Phase9ExitRisk.NETWORK_SIDE_EFFECT_REPORTED)
        assumptions_ok = set(manifest.synthetic_assumptions) == set(REQUIRED_SYNTHETIC_ASSUMPTIONS) and len(manifest.synthetic_assumptions) == len(REQUIRED_SYNTHETIC_ASSUMPTIONS)
        if not assumptions_ok:
            risks.add(Phase9ExitRisk.SYNTHETIC_ASSUMPTION_MISSING)
        unsupported_claims = any(bool(getattr(manifest.claim_profile, field)) for field in PRODUCTION_CLAIM_FIELDS)
        if unsupported_claims:
            risks.add(Phase9ExitRisk.UNSUPPORTED_PRODUCTION_CLAIM)
        local_records = {item.scope: item for item in manifest.verification_records if item.status in {Phase9VerificationStatus.LOCAL_FOCUSED_PASS, Phase9VerificationStatus.LOCAL_FULL_PASS}}
        local_ok = True
        for scope in p.required_local_verification_scopes:
            record = local_records.get(scope)
            if record is None or not record.runner_started or record.steps_executed <= 0:
                local_ok = False
                risks.add(Phase9ExitRisk.LOCAL_VERIFICATION_INCOMPLETE)
        remote_records = [item for item in manifest.verification_records if item.status in {Phase9VerificationStatus.REMOTE_CI_PASS, Phase9VerificationStatus.REMOTE_CI_BLOCKED, Phase9VerificationStatus.REMOTE_CI_FAIL}]
        remote_status = Phase9VerificationStatus.NOT_RUN.value
        remote_verified = False
        remote_external_limitation = False
        if len(remote_records) != 1:
            risks.add(Phase9ExitRisk.REMOTE_CI_INVALID)
        else:
            remote = remote_records[0]
            remote_status = remote.status.value
            if remote.status == Phase9VerificationStatus.REMOTE_CI_PASS:
                if not remote.runner_started or remote.steps_executed <= 0 or remote.reason_code:
                    risks.add(Phase9ExitRisk.REMOTE_CI_INVALID)
                else:
                    remote_verified = True
            elif remote.status == Phase9VerificationStatus.REMOTE_CI_BLOCKED:
                if remote.runner_started or remote.steps_executed != 0 or remote.reason_code not in p.allowed_external_ci_block_reasons:
                    risks.add(Phase9ExitRisk.REMOTE_CI_INVALID)
                else:
                    remote_external_limitation = True
            else:
                if not remote.runner_started or remote.steps_executed <= 0:
                    risks.add(Phase9ExitRisk.REMOTE_CI_INVALID)
                risks.add(Phase9ExitRisk.REMOTE_CI_EXECUTION_FAILED)
        decision = Phase9ExitDecision.FAIL if risks else Phase9ExitDecision.PASS if remote_verified else Phase9ExitDecision.PASS_WITH_EXTERNAL_CI_LIMITATION if remote_external_limitation else Phase9ExitDecision.FAIL
        scenario_risks = {Phase9ExitRisk.COMPROMISE_SCENARIO_COVERAGE_INVALID, Phase9ExitRisk.COMPROMISE_SCENARIO_ORDER_INVALID, Phase9ExitRisk.COMPROMISE_SCENARIO_BINDING_MISMATCH, Phase9ExitRisk.COMPROMISE_NOT_DETECTED, Phase9ExitRisk.PROMOTION_FAIL_OPEN}
        metadata = {"local_ok": local_ok, "remote_status": remote_status, "remote_verified": remote_verified, "remote_external_limitation": remote_external_limitation, "assumptions_ok": assumptions_ok, "unsupported_claims": unsupported_claims, "scenario_passed": not bool(set(risks).intersection(scenario_risks)), "promotion_fail_closed": Phase9ExitRisk.PROMOTION_FAIL_OPEN not in risks}
        return tuple(sorted(risks, key=lambda item: item.value)), decision, metadata

    def evaluate(self, request: Phase9ExitRequest, manifest: Phase9ExitManifest) -> Phase9ExitAssessment:
        self._validate_manifest_shape(manifest)
        actual_manifest_sha = phase9_exit_manifest_digest(manifest)
        if actual_manifest_sha.casefold() != self.policy.expected_manifest_sha256.casefold():
            reject(Phase9ExitRejectReason.MANIFEST_DIGEST_MISMATCH, "exit manifest differs from policy-pinned evidence")
        if request.manifest_id != manifest.manifest_id or request.manifest_sha256.casefold() != actual_manifest_sha.casefold() or request.policy_version != self.policy.policy_version:
            reject(Phase9ExitRejectReason.REQUEST_INVALID, "request exit-manifest binding mismatch")
        if request.evaluated_at_epoch < manifest.created_at_epoch - self.policy.max_future_skew_seconds or request.evaluated_at_epoch > manifest.created_at_epoch + self.policy.max_manifest_age_seconds:
            reject(Phase9ExitRejectReason.REQUEST_INVALID, "exit manifest freshness invalid")
        risks, decision, metadata = self.derive(manifest, request.evaluated_at_epoch)
        expected_assessments = {item.milestone_id: item.assessment_sha256.casefold() for item in manifest.milestone_evidence}
        declared_assessments = {key: str(value).casefold() for key, value in request.declared_assessment_sha256_by_milestone.items()}
        if declared_assessments != expected_assessments:
            reject(Phase9ExitRejectReason.DECLARED_EVIDENCE_MISMATCH, "declared milestone assessment evidence differs from manifest")
        expected_detection = {item.scenario_id: item.detected for item in manifest.compromise_exercises}
        expected_blocked = {item.scenario_id: item.promotion_blocked for item in manifest.compromise_exercises}
        if dict(request.declared_scenario_detection_by_id) != expected_detection or dict(request.declared_scenario_promotion_blocked_by_id) != expected_blocked:
            reject(Phase9ExitRejectReason.DECLARED_SCENARIO_MISMATCH, "declared compromise-exercise outcome differs from evidence")
        expected_verification = {item.verification_id: item.status.value for item in manifest.verification_records}
        if dict(request.declared_verification_status_by_id) != expected_verification:
            reject(Phase9ExitRejectReason.DECLARED_VERIFICATION_MISMATCH, "declared verification state differs from evidence")
        if request.declared_exit_decision != decision:
            reject(Phase9ExitRejectReason.DECLARED_DECISION_MISMATCH, "caller-declared Phase 9 exit decision differs from derived decision")
        assessment_sha = _digest_json({"manifest_id": manifest.manifest_id, "training_lineage_id": manifest.training_lineage_id, "milestones": manifest.milestone_evidence, "compromise_exercises": manifest.compromise_exercises, "verification": manifest.verification_records, "assumptions": manifest.synthetic_assumptions, "claims": manifest.claim_profile, "risks": risks, "decision": decision, "schema": P9I_ASSESSMENT_SCHEMA_VERSION, "mode": P9I_ASSESSMENT_MODE})
        local_count = sum(item.status in {Phase9VerificationStatus.LOCAL_FOCUSED_PASS, Phase9VerificationStatus.LOCAL_FULL_PASS} for item in manifest.verification_records)
        binding_risks = {Phase9ExitRisk.MILESTONE_COVERAGE_INVALID, Phase9ExitRisk.MILESTONE_ORDER_INVALID, Phase9ExitRisk.DOMAIN_BINDING_MISMATCH, Phase9ExitRisk.LINEAGE_MISMATCH, Phase9ExitRisk.EVIDENCE_CHAIN_BROKEN, Phase9ExitRisk.EVIDENCE_DIGEST_MISMATCH}
        return Phase9ExitAssessment(manifest_id=manifest.manifest_id, training_lineage_id=manifest.training_lineage_id, milestone_count=len(manifest.milestone_evidence), compromise_scenario_count=len(manifest.compromise_exercises), local_verification_count=local_count, remote_ci_status=str(metadata["remote_status"]), risks=risks, decision=decision, all_milestones_evidence_bound=not bool(set(risks).intersection(binding_risks)), compromise_exercises_passed=bool(metadata["scenario_passed"]), promotion_fail_closed_verified=bool(metadata["promotion_fail_closed"]), upstream_safety_derived=Phase9ExitRisk.UPSTREAM_SAFETY_FAILED not in risks, caller_declared_safety_trusted=Phase9ExitRisk.CALLER_DECLARED_SAFETY_TRUSTED in risks, local_security_validation_passed=bool(metadata["local_ok"]), remote_ci_execution_verified=bool(metadata["remote_verified"]), remote_ci_external_limitation=bool(metadata["remote_external_limitation"]), synthetic_assumptions_explicit=bool(metadata["assumptions_ok"]), unsupported_production_claims_present=bool(metadata["unsupported_claims"]), production_data_platform_integrated=False, production_training_runtime_validated=False, production_scheduler_iam_kms_integrated=False, production_checkpoint_store_integrated=False, production_hidden_benchmark_service_integrated=False, production_privacy_compliance_verified=False, production_model_registry_integrated=False, cryptographic_attestation_verified=False, network_operations=sum(item.network_operations for item in manifest.milestone_evidence) + sum(item.network_operations for item in manifest.compromise_exercises), assessment_schema_version=P9I_ASSESSMENT_SCHEMA_VERSION, assessment_mode=P9I_ASSESSMENT_MODE, assessment_evidence_sha256=assessment_sha)


def machine_readable_phase9_exit(assessment: Phase9ExitAssessment) -> dict[str, object]:
    return {"phase": "P9", "manifest_id": assessment.manifest_id, "training_lineage_id": assessment.training_lineage_id, "implementation_status": "PASS" if assessment.decision != Phase9ExitDecision.FAIL else "FAIL", "local_security_validation": "PASS" if assessment.local_security_validation_passed else "FAIL", "compromise_exercises": {"scenario_count": assessment.compromise_scenario_count, "passed": assessment.compromise_exercises_passed, "promotion_fail_closed_verified": assessment.promotion_fail_closed_verified}, "remote_ci": {"status": assessment.remote_ci_status, "execution_verified": assessment.remote_ci_execution_verified, "external_limitation": assessment.remote_ci_external_limitation}, "production_claims": False, "exit_decision": assessment.decision.value, "assessment_evidence_sha256": assessment.assessment_evidence_sha256}
