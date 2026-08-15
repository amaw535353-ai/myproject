from __future__ import annotations

import re

from .phase8_exit_types import (
    MILESTONE_DOMAINS,
    MILESTONE_ORDER,
    P8L_ASSESSMENT_MODE,
    P8L_ASSESSMENT_SCHEMA_VERSION,
    P8L_EXIT_POLICY_VERSION,
    P8L_EXIT_SCHEMA_VERSION,
    PRODUCTION_CLAIM_FIELDS,
    REQUIRED_SYNTHETIC_ASSUMPTIONS,
    ZERO_SHA256,
    ExitRejectReason,
    ExitRisk,
    Phase8ExitAssessment,
    Phase8ExitDecision,
    Phase8ExitManifest,
    Phase8ExitPolicy,
    Phase8ExitRequest,
    VerificationStatus,
    _digest_json,
    phase8_exit_manifest_digest,
    reject,
)

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class Phase8IntegratedExitGate:
    def __init__(self, policy: Phase8ExitPolicy):
        self.policy = policy
        self._validate_policy()

    @staticmethod
    def _sha(value: str) -> bool:
        return bool(_SHA256_RE.fullmatch(str(value)))

    def _validate_policy(self) -> None:
        p = self.policy
        if p.policy_version != P8L_EXIT_POLICY_VERSION:
            reject(ExitRejectReason.POLICY_INVALID, "unexpected policy version")
        if not p.expected_manifest_id or not p.expected_execution_lineage_id:
            reject(ExitRejectReason.POLICY_INVALID, "manifest and lineage identities are required")
        if not self._sha(p.expected_manifest_sha256):
            reject(ExitRejectReason.POLICY_INVALID, "expected manifest digest must be sha256")
        if tuple(sorted(p.expected_assessment_sha256_by_milestone)) != tuple(sorted(MILESTONE_ORDER)):
            reject(ExitRejectReason.POLICY_INVALID, "assessment digest pins must cover P8-A through P8-K")
        if tuple(sorted(p.expected_manifest_sha256_by_milestone)) != tuple(sorted(MILESTONE_ORDER)):
            reject(ExitRejectReason.POLICY_INVALID, "manifest digest pins must cover P8-A through P8-K")
        if tuple(sorted(p.expected_output_state_sha256_by_milestone)) != tuple(sorted(MILESTONE_ORDER)):
            reject(ExitRejectReason.POLICY_INVALID, "output state pins must cover P8-A through P8-K")
        if tuple(sorted(p.expected_assessment_schema_by_milestone)) != tuple(sorted(MILESTONE_ORDER)):
            reject(ExitRejectReason.POLICY_INVALID, "assessment schema pins must cover P8-A through P8-K")
        if tuple(sorted(p.expected_assessment_mode_by_milestone)) != tuple(sorted(MILESTONE_ORDER)):
            reject(ExitRejectReason.POLICY_INVALID, "assessment mode pins must cover P8-A through P8-K")
        all_digests = (
            tuple(p.expected_assessment_sha256_by_milestone.values())
            + tuple(p.expected_manifest_sha256_by_milestone.values())
            + tuple(p.expected_output_state_sha256_by_milestone.values())
        )
        for digest in all_digests:
            if not self._sha(digest):
                reject(ExitRejectReason.POLICY_INVALID, "milestone pins must be sha256")
        if len(set(p.required_local_verification_scopes)) != len(p.required_local_verification_scopes):
            reject(ExitRejectReason.POLICY_INVALID, "duplicate local verification scopes")
        if p.max_manifest_age_seconds < 0 or p.max_future_skew_seconds < 0:
            reject(ExitRejectReason.POLICY_INVALID, "freshness limits must be non-negative")

    def _validate_manifest_shape(self, manifest: Phase8ExitManifest) -> None:
        if manifest.schema_version != P8L_EXIT_SCHEMA_VERSION:
            reject(ExitRejectReason.MANIFEST_INVALID, "unexpected manifest schema")
        if manifest.manifest_id != self.policy.expected_manifest_id:
            reject(ExitRejectReason.MANIFEST_INVALID, "manifest identity mismatch")
        if manifest.execution_lineage_id != self.policy.expected_execution_lineage_id:
            reject(ExitRejectReason.MANIFEST_INVALID, "execution lineage identity mismatch")
        if len({m.milestone_id for m in manifest.milestone_evidence}) != len(manifest.milestone_evidence):
            reject(ExitRejectReason.MANIFEST_INVALID, "duplicate milestone identity")
        if len({v.verification_id for v in manifest.verification_records}) != len(manifest.verification_records):
            reject(ExitRejectReason.MANIFEST_INVALID, "duplicate verification identity")
        for m in manifest.milestone_evidence:
            if (
                not self._sha(m.manifest_sha256)
                or not self._sha(m.assessment_sha256)
                or not self._sha(m.predecessor_assessment_sha256)
                or not self._sha(m.input_state_sha256)
                or not self._sha(m.output_state_sha256)
            ):
                reject(ExitRejectReason.MANIFEST_INVALID, "milestone evidence digest is not sha256")
            if m.network_operations < 0:
                reject(ExitRejectReason.MANIFEST_INVALID, "network operation count cannot be negative")
        for v in manifest.verification_records:
            if not self._sha(v.evidence_sha256):
                reject(ExitRejectReason.MANIFEST_INVALID, "verification evidence digest is not sha256")
            if v.steps_executed < 0:
                reject(ExitRejectReason.MANIFEST_INVALID, "verification step count cannot be negative")

    def derive(self, manifest: Phase8ExitManifest, now: int) -> tuple[tuple[ExitRisk, ...], Phase8ExitDecision, dict[str, object]]:
        self._validate_manifest_shape(manifest)
        risks: set[ExitRisk] = set()

        milestone_ids = tuple(m.milestone_id for m in manifest.milestone_evidence)
        if set(milestone_ids) != set(MILESTONE_ORDER) or len(milestone_ids) != len(MILESTONE_ORDER):
            risks.add(ExitRisk.MILESTONE_COVERAGE_INVALID)
        if milestone_ids != MILESTONE_ORDER:
            risks.add(ExitRisk.MILESTONE_ORDER_INVALID)

        previous = ZERO_SHA256
        previous_state = ZERO_SHA256
        milestone_by_id = {m.milestone_id: m for m in manifest.milestone_evidence}
        for index, milestone_id in enumerate(MILESTONE_ORDER, start=1):
            m = milestone_by_id.get(milestone_id)
            if m is None:
                continue
            if m.control_domain != MILESTONE_DOMAINS[milestone_id]:
                risks.add(ExitRisk.DOMAIN_BINDING_MISMATCH)
            if m.step_index != index or m.execution_lineage_id != manifest.execution_lineage_id:
                risks.add(ExitRisk.LINEAGE_MISMATCH)
            if m.predecessor_assessment_sha256.casefold() != previous.casefold():
                risks.add(ExitRisk.EVIDENCE_CHAIN_BROKEN)
            if m.input_state_sha256.casefold() != previous_state.casefold():
                risks.add(ExitRisk.LINEAGE_MISMATCH)
            if m.output_state_sha256.casefold() != self.policy.expected_output_state_sha256_by_milestone[milestone_id].casefold():
                risks.add(ExitRisk.LINEAGE_MISMATCH)
            if m.assessment_schema_version != self.policy.expected_assessment_schema_by_milestone[milestone_id]:
                risks.add(ExitRisk.EVIDENCE_DIGEST_MISMATCH)
            if m.assessment_mode != self.policy.expected_assessment_mode_by_milestone[milestone_id]:
                risks.add(ExitRisk.EVIDENCE_DIGEST_MISMATCH)
            if m.assessment_sha256.casefold() != self.policy.expected_assessment_sha256_by_milestone[milestone_id].casefold():
                risks.add(ExitRisk.EVIDENCE_DIGEST_MISMATCH)
            if m.manifest_sha256.casefold() != self.policy.expected_manifest_sha256_by_milestone[milestone_id].casefold():
                risks.add(ExitRisk.EVIDENCE_DIGEST_MISMATCH)
            if not m.safe:
                risks.add(ExitRisk.UPSTREAM_SAFETY_FAILED)
            if m.caller_declared_safety_trusted:
                risks.add(ExitRisk.CALLER_DECLARED_SAFETY_TRUSTED)
            if m.network_operations != 0:
                risks.add(ExitRisk.NETWORK_SIDE_EFFECT_REPORTED)
            previous = m.assessment_sha256
            previous_state = m.output_state_sha256

        assumptions = tuple(manifest.synthetic_assumptions)
        if set(assumptions) != set(REQUIRED_SYNTHETIC_ASSUMPTIONS) or len(assumptions) != len(REQUIRED_SYNTHETIC_ASSUMPTIONS):
            risks.add(ExitRisk.SYNTHETIC_ASSUMPTION_MISSING)

        unsupported = any(bool(getattr(manifest.claim_profile, field)) for field in PRODUCTION_CLAIM_FIELDS)
        if unsupported:
            risks.add(ExitRisk.UNSUPPORTED_PRODUCTION_CLAIM)

        local_records = {
            v.scope: v
            for v in manifest.verification_records
            if v.status in {VerificationStatus.LOCAL_FOCUSED_PASS, VerificationStatus.LOCAL_FULL_PASS}
        }
        local_ok = True
        for scope in self.policy.required_local_verification_scopes:
            v = local_records.get(scope)
            if v is None or not v.runner_started or v.steps_executed <= 0:
                local_ok = False
                risks.add(ExitRisk.LOCAL_VERIFICATION_INCOMPLETE)

        remote_records = [
            v
            for v in manifest.verification_records
            if v.status in {
                VerificationStatus.REMOTE_CI_PASS,
                VerificationStatus.REMOTE_CI_BLOCKED,
                VerificationStatus.REMOTE_CI_FAIL,
            }
        ]
        remote_status = VerificationStatus.NOT_RUN.value
        remote_verified = False
        remote_external_limitation = False
        if len(remote_records) != 1:
            risks.add(ExitRisk.REMOTE_CI_INVALID)
        else:
            remote = remote_records[0]
            remote_status = remote.status.value
            if remote.status == VerificationStatus.REMOTE_CI_PASS:
                if not remote.runner_started or remote.steps_executed <= 0 or remote.reason_code:
                    risks.add(ExitRisk.REMOTE_CI_INVALID)
                else:
                    remote_verified = True
            elif remote.status == VerificationStatus.REMOTE_CI_BLOCKED:
                if remote.runner_started or remote.steps_executed != 0:
                    risks.add(ExitRisk.REMOTE_CI_INVALID)
                elif remote.reason_code not in self.policy.allowed_external_ci_block_reasons:
                    risks.add(ExitRisk.REMOTE_CI_INVALID)
                else:
                    remote_external_limitation = True
            elif remote.status == VerificationStatus.REMOTE_CI_FAIL:
                if not remote.runner_started or remote.steps_executed <= 0:
                    risks.add(ExitRisk.REMOTE_CI_INVALID)
                risks.add(ExitRisk.REMOTE_CI_EXECUTION_FAILED)

        if risks:
            decision = Phase8ExitDecision.FAIL
        elif remote_verified:
            decision = Phase8ExitDecision.PASS
        elif remote_external_limitation:
            decision = Phase8ExitDecision.PASS_WITH_EXTERNAL_CI_LIMITATION
        else:
            decision = Phase8ExitDecision.FAIL

        metadata = {
            "local_ok": local_ok,
            "remote_status": remote_status,
            "remote_verified": remote_verified,
            "remote_external_limitation": remote_external_limitation,
            "unsupported": unsupported,
            "assumptions_ok": ExitRisk.SYNTHETIC_ASSUMPTION_MISSING not in risks,
        }
        return tuple(sorted(risks, key=lambda r: r.value)), decision, metadata

    def evaluate(self, request: Phase8ExitRequest, manifest: Phase8ExitManifest) -> Phase8ExitAssessment:
        self._validate_manifest_shape(manifest)
        actual_manifest_sha = phase8_exit_manifest_digest(manifest)
        if actual_manifest_sha.casefold() != self.policy.expected_manifest_sha256.casefold():
            reject(ExitRejectReason.MANIFEST_DIGEST_MISMATCH, "manifest differs from policy-pinned evidence")
        if request.manifest_id != manifest.manifest_id:
            reject(ExitRejectReason.REQUEST_INVALID, "request manifest identity mismatch")
        if request.manifest_sha256.casefold() != actual_manifest_sha:
            reject(ExitRejectReason.REQUEST_INVALID, "request manifest digest mismatch")
        if request.policy_version != self.policy.policy_version:
            reject(ExitRejectReason.REQUEST_INVALID, "request policy version mismatch")
        if request.evaluated_at_epoch < manifest.created_at_epoch - self.policy.max_future_skew_seconds:
            reject(ExitRejectReason.REQUEST_INVALID, "evaluation predates manifest beyond allowed skew")
        if request.evaluated_at_epoch > manifest.created_at_epoch + self.policy.max_manifest_age_seconds:
            reject(ExitRejectReason.REQUEST_INVALID, "manifest is stale")

        risks, decision, metadata = self.derive(manifest, request.evaluated_at_epoch)
        expected_assessments = {m.milestone_id: m.assessment_sha256.casefold() for m in manifest.milestone_evidence}
        declared_assessments = {k: str(v).casefold() for k, v in request.declared_assessment_sha256_by_milestone.items()}
        if declared_assessments != expected_assessments:
            reject(ExitRejectReason.DECLARED_EVIDENCE_MISMATCH, "declared milestone evidence differs from manifest")
        expected_verification = {v.verification_id: v.status.value for v in manifest.verification_records}
        if dict(request.declared_verification_status_by_id) != expected_verification:
            reject(ExitRejectReason.DECLARED_VERIFICATION_MISMATCH, "declared verification state differs from evidence")
        if request.declared_exit_decision != decision:
            reject(ExitRejectReason.DECLARED_DECISION_MISMATCH, "caller-declared exit decision differs from derived decision")

        assessment_payload = {
            "manifest_id": manifest.manifest_id,
            "lineage": manifest.execution_lineage_id,
            "milestones": manifest.milestone_evidence,
            "verification": manifest.verification_records,
            "assumptions": manifest.synthetic_assumptions,
            "claims": manifest.claim_profile,
            "risks": risks,
            "decision": decision,
            "schema": P8L_ASSESSMENT_SCHEMA_VERSION,
            "mode": P8L_ASSESSMENT_MODE,
        }
        assessment_sha = _digest_json(assessment_payload)
        local_count = sum(
            v.status in {VerificationStatus.LOCAL_FOCUSED_PASS, VerificationStatus.LOCAL_FULL_PASS}
            for v in manifest.verification_records
        )
        return Phase8ExitAssessment(
            manifest_id=manifest.manifest_id,
            execution_lineage_id=manifest.execution_lineage_id,
            milestone_count=len(manifest.milestone_evidence),
            local_verification_count=local_count,
            remote_ci_status=str(metadata["remote_status"]),
            risks=risks,
            decision=decision,
            all_milestones_evidence_bound=not bool(
                set(risks).intersection(
                    {
                        ExitRisk.MILESTONE_COVERAGE_INVALID,
                        ExitRisk.MILESTONE_ORDER_INVALID,
                        ExitRisk.DOMAIN_BINDING_MISMATCH,
                        ExitRisk.LINEAGE_MISMATCH,
                        ExitRisk.EVIDENCE_CHAIN_BROKEN,
                        ExitRisk.EVIDENCE_DIGEST_MISMATCH,
                    }
                )
            ),
            upstream_safety_derived=ExitRisk.UPSTREAM_SAFETY_FAILED not in risks,
            caller_declared_safety_trusted=ExitRisk.CALLER_DECLARED_SAFETY_TRUSTED in risks,
            local_security_validation_passed=bool(metadata["local_ok"]),
            remote_ci_execution_verified=bool(metadata["remote_verified"]),
            remote_ci_external_limitation=bool(metadata["remote_external_limitation"]),
            synthetic_assumptions_explicit=bool(metadata["assumptions_ok"]),
            unsupported_production_claims_present=bool(metadata["unsupported"]),
            production_runtime_validated=False,
            production_distributed_system_validated=False,
            production_siem_edr_integrated=False,
            cryptographic_attestation_verified=False,
            network_operations=sum(m.network_operations for m in manifest.milestone_evidence),
            assessment_schema_version=P8L_ASSESSMENT_SCHEMA_VERSION,
            assessment_mode=P8L_ASSESSMENT_MODE,
            assessment_evidence_sha256=assessment_sha,
        )


def machine_readable_phase8_exit(assessment: Phase8ExitAssessment) -> dict[str, object]:
    return {
        "phase": "P8",
        "manifest_id": assessment.manifest_id,
        "execution_lineage_id": assessment.execution_lineage_id,
        "implementation_status": "PASS" if assessment.decision != Phase8ExitDecision.FAIL else "FAIL",
        "local_security_validation": "PASS" if assessment.local_security_validation_passed else "FAIL",
        "remote_ci": {
            "status": assessment.remote_ci_status,
            "execution_verified": assessment.remote_ci_execution_verified,
            "external_limitation": assessment.remote_ci_external_limitation,
        },
        "production_claims": False,
        "exit_decision": assessment.decision.value,
        "assessment_evidence_sha256": assessment.assessment_evidence_sha256,
    }
