from __future__ import annotations

from dataclasses import replace
import hashlib

from aegis.agentic.phase8_exit_types import (
    MILESTONE_DOMAINS,
    MILESTONE_ORDER,
    P8L_EXIT_POLICY_VERSION,
    P8L_EXIT_SCHEMA_VERSION,
    REQUIRED_SYNTHETIC_ASSUMPTIONS,
    ZERO_SHA256,
    MilestoneEvidence,
    Phase8ClaimProfile,
    Phase8ExitDecision,
    Phase8ExitManifest,
    Phase8ExitPolicy,
    Phase8ExitRequest,
    VerificationRecord,
    VerificationStatus,
    phase8_exit_manifest_digest,
)

NOW = 1_800_000_000
LINEAGE_ID = "phase8-integrated-compromise-lineage-001"
MANIFEST_ID = "phase8-exit-evidence-001"
REMOTE_BLOCK_REASON = "github-hosted-runner-account-billing-or-spending-limit"


def h(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _milestones() -> tuple[MilestoneEvidence, ...]:
    result = []
    prev_assessment = ZERO_SHA256
    prev_state = ZERO_SHA256
    for index, milestone_id in enumerate(MILESTONE_ORDER, start=1):
        manifest_sha = h(f"{LINEAGE_ID}:{milestone_id}:manifest")
        assessment_sha = h(f"{LINEAGE_ID}:{milestone_id}:assessment")
        output_state = h(f"{LINEAGE_ID}:{milestone_id}:output-state")
        result.append(
            MilestoneEvidence(
                milestone_id=milestone_id,
                control_domain=MILESTONE_DOMAINS[milestone_id],
                step_index=index,
                execution_lineage_id=LINEAGE_ID,
                manifest_sha256=manifest_sha,
                assessment_sha256=assessment_sha,
                predecessor_assessment_sha256=prev_assessment,
                input_state_sha256=prev_state,
                output_state_sha256=output_state,
                assessment_schema_version=f"{milestone_id.lower()}-assessment-v1",
                assessment_mode="deterministic-synthetic-security-evidence",
                safe=True,
                caller_declared_safety_trusted=False,
                network_operations=0,
            )
        )
        prev_assessment = assessment_sha
        prev_state = output_state
    return tuple(result)


def _verification_records(
    remote_status: VerificationStatus = VerificationStatus.REMOTE_CI_BLOCKED,
) -> tuple[VerificationRecord, ...]:
    records = []
    for milestone_id in MILESTONE_ORDER:
        records.append(
            VerificationRecord(
                verification_id=f"local-{milestone_id.lower()}",
                scope=milestone_id,
                status=VerificationStatus.LOCAL_FOCUSED_PASS,
                evidence_sha256=h(f"verification:{milestone_id}:focused-pass"),
                runner_started=True,
                steps_executed=1,
            )
        )
    if remote_status == VerificationStatus.REMOTE_CI_BLOCKED:
        records.append(
            VerificationRecord(
                verification_id="remote-phase8-ci",
                scope="Phase8",
                status=remote_status,
                evidence_sha256=h("remote-phase8-ci:blocked:billing"),
                runner_started=False,
                steps_executed=0,
                reason_code=REMOTE_BLOCK_REASON,
            )
        )
    elif remote_status == VerificationStatus.REMOTE_CI_PASS:
        records.append(
            VerificationRecord(
                verification_id="remote-phase8-ci",
                scope="Phase8",
                status=remote_status,
                evidence_sha256=h("remote-phase8-ci:pass"),
                runner_started=True,
                steps_executed=14,
                reason_code="",
            )
        )
    else:
        records.append(
            VerificationRecord(
                verification_id="remote-phase8-ci",
                scope="Phase8",
                status=remote_status,
                evidence_sha256=h("remote-phase8-ci:fail"),
                runner_started=True,
                steps_executed=5,
                reason_code="tests-failed",
            )
        )
    return tuple(records)


def build_fixture(
    remote_status: VerificationStatus = VerificationStatus.REMOTE_CI_BLOCKED,
) -> dict[str, object]:
    milestones = _milestones()
    manifest = Phase8ExitManifest(
        manifest_id=MANIFEST_ID,
        schema_version=P8L_EXIT_SCHEMA_VERSION,
        created_at_epoch=NOW,
        execution_lineage_id=LINEAGE_ID,
        milestone_evidence=milestones,
        verification_records=_verification_records(remote_status),
        synthetic_assumptions=REQUIRED_SYNTHETIC_ASSUMPTIONS,
        claim_profile=Phase8ClaimProfile(),
    )
    policy = Phase8ExitPolicy(
        policy_version=P8L_EXIT_POLICY_VERSION,
        expected_manifest_id=MANIFEST_ID,
        expected_manifest_sha256=phase8_exit_manifest_digest(manifest),
        expected_execution_lineage_id=LINEAGE_ID,
        expected_assessment_sha256_by_milestone={m.milestone_id: m.assessment_sha256 for m in milestones},
        expected_manifest_sha256_by_milestone={m.milestone_id: m.manifest_sha256 for m in milestones},
        expected_output_state_sha256_by_milestone={m.milestone_id: m.output_state_sha256 for m in milestones},
        expected_assessment_schema_by_milestone={m.milestone_id: m.assessment_schema_version for m in milestones},
        expected_assessment_mode_by_milestone={m.milestone_id: m.assessment_mode for m in milestones},
        required_local_verification_scopes=MILESTONE_ORDER,
        allowed_external_ci_block_reasons=(REMOTE_BLOCK_REASON,),
        max_manifest_age_seconds=3600,
        max_future_skew_seconds=30,
    )
    expected_decision = (
        Phase8ExitDecision.PASS_WITH_EXTERNAL_CI_LIMITATION
        if remote_status == VerificationStatus.REMOTE_CI_BLOCKED
        else Phase8ExitDecision.PASS
        if remote_status == VerificationStatus.REMOTE_CI_PASS
        else Phase8ExitDecision.FAIL
    )
    request = Phase8ExitRequest(
        manifest_id=MANIFEST_ID,
        manifest_sha256=phase8_exit_manifest_digest(manifest),
        policy_version=P8L_EXIT_POLICY_VERSION,
        evaluated_at_epoch=NOW + 10,
        declared_exit_decision=expected_decision,
        declared_assessment_sha256_by_milestone={m.milestone_id: m.assessment_sha256 for m in milestones},
        declared_verification_status_by_id={v.verification_id: v.status.value for v in manifest.verification_records},
    )
    return {"manifest": manifest, "policy": policy, "request": request}


def rebind(
    fixture: dict[str, object],
    manifest: Phase8ExitManifest,
    *,
    keep_policy_pins: bool = True,
) -> dict[str, object]:
    """Rebuild request; optionally repin only the outer manifest digest for shape attacks."""
    policy: Phase8ExitPolicy = fixture["policy"]  # type: ignore[assignment]
    if not keep_policy_pins:
        policy = replace(policy, expected_manifest_sha256=phase8_exit_manifest_digest(manifest))
    request: Phase8ExitRequest = fixture["request"]  # type: ignore[assignment]
    request = replace(
        request,
        manifest_sha256=phase8_exit_manifest_digest(manifest),
        declared_assessment_sha256_by_milestone={
            m.milestone_id: m.assessment_sha256 for m in manifest.milestone_evidence
        },
        declared_verification_status_by_id={
            v.verification_id: v.status.value for v in manifest.verification_records
        },
    )
    return {"manifest": manifest, "policy": policy, "request": request}
