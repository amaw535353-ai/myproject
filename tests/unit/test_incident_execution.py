import sqlite3
from dataclasses import FrozenInstanceError, replace

import pytest

from aegis.incidents.execution import (
    IncidentExecutionBoundary,
    execution_request_digest,
)
from aegis.incidents.governance import (
    IncidentGovernanceBoundary,
    IncidentGovernanceDecision,
)
from aegis.incidents.lifecycle import (
    ZERO_SHA256,
    IncidentLifecycleBoundary,
    IncidentLifecycleState,
)
from aegis.incidents.types import IncidentIntakeRecord


def _intake(incident_id: str = "incident-001") -> IncidentIntakeRecord:
    suffix = incident_id.rsplit("-", 1)[-1]
    return IncidentIntakeRecord(
        incident_id=incident_id,
        tenant_ref=f"ref:tenant-{suffix}",
        workload_ref=f"ref:workload-{suffix}",
        contributing_event_ids=(f"event-{suffix}",),
        evidence_references=(
            ("tenant_ref", f"ref:tenant-{suffix}"),
            ("workload_ref", f"ref:workload-{suffix}"),
        ),
        severities=("high",),
        highest_severity="high",
        categories=("application_agent",),
    )


def _governance(
    incident_id: str = "incident-001",
    decision: IncidentGovernanceDecision = IncidentGovernanceDecision.APPROVED,
    lifecycle_state: IncidentLifecycleState = IncidentLifecycleState.OPEN,
):
    lifecycle_boundary = IncidentLifecycleBoundary()
    lifecycle = lifecycle_boundary.open(_intake(incident_id))
    if lifecycle_state is IncidentLifecycleState.ACKNOWLEDGED:
        lifecycle = lifecycle_boundary.transition(lifecycle, lifecycle_state)
    return IncidentGovernanceBoundary().evaluate(
        lifecycle,
        tenant_ref=lifecycle.intake.tenant_ref,
        workload_ref=lifecycle.intake.workload_ref,
        requested_action="isolate-workload",
        policy_decision=decision,
    )


def _request(boundary: IncidentExecutionBoundary, incident_id: str = "incident-001"):
    return boundary.create_request(_governance(incident_id))


def test_original_digest_api_and_request_contract_are_preserved() -> None:
    governance = _governance(lifecycle_state=IncidentLifecycleState.ACKNOWLEDGED)
    request = IncidentExecutionBoundary().create_request(governance)
    lifecycle_head = governance.lifecycle.transitions[-1].transition_sha256

    assert request.request_sha256 == execution_request_digest(
        incident_id=governance.incident_id,
        governance_decision=governance.decision,
        governance_decision_sha256=governance.decision_sha256.upper(),
        lifecycle_state=governance.lifecycle.state,
        lifecycle_head_sha256=lifecycle_head.upper(),
        intake_root_sha256=governance.lifecycle.intake_root_sha256.upper(),
        tenant_ref=governance.tenant_ref,
        workload_ref=governance.workload_ref,
        requested_action=governance.requested_action,
        evidence_references=governance.lifecycle.intake.evidence_references,
    )
    assert request.governance_decision is IncidentGovernanceDecision.APPROVED
    assert request.lifecycle_state is IncidentLifecycleState.ACKNOWLEDGED
    assert request.provenance_references == (
        governance.lifecycle.intake_root_sha256,
        lifecycle_head,
    )


@pytest.mark.parametrize(
    ("decision", "error"),
    (
        (IncidentGovernanceDecision.DENIED, "DENIED_GOVERNANCE_EXECUTION_REJECTED"),
        (
            IncidentGovernanceDecision.REQUIRES_APPROVAL,
            "INCIDENT_EXECUTION_APPROVAL_REQUIRED",
        ),
    ),
)
def test_governance_approval_required(decision, error) -> None:
    with pytest.raises(ValueError, match=error):
        IncidentExecutionBoundary().create_request(_governance(decision=decision))


def test_policy_references_are_governance_owned() -> None:
    governance = _governance()
    boundary = IncidentExecutionBoundary()
    request = boundary.create_request(governance)

    assert request.policy_references == (governance.decision_sha256,)
    with pytest.raises(TypeError):
        boundary.create_request(governance, policy_references=("attacker-policy",))


def test_validation_precedes_replay_lookup() -> None:
    boundary = IncidentExecutionBoundary()
    request = _request(boundary)
    boundary.execute(request)

    with pytest.raises(ValueError, match="INCIDENT_EXECUTION_REQUEST_INVALID"):
        boundary.execute(replace(request, schema_version="invalid"))


def test_sqlite_replay_survives_boundary_restart(tmp_path) -> None:
    ledger = tmp_path / "execution.sqlite3"
    request = _request(IncidentExecutionBoundary(ledger))
    first = IncidentExecutionBoundary(ledger).execute(request)
    second = IncidentExecutionBoundary(ledger).execute(request)

    assert first == second


def test_conflicting_reuse_after_restart_is_rejected(tmp_path) -> None:
    ledger = tmp_path / "execution.sqlite3"
    request = _request(IncidentExecutionBoundary(ledger))
    IncidentExecutionBoundary(ledger).execute(request)

    with sqlite3.connect(ledger) as connection:
        connection.execute(
            "UPDATE incident_execution_ledger SET request_fingerprint = ?",
            ("0" * 64,),
        )

    with pytest.raises(ValueError, match="INCIDENT_EXECUTION_REPLAY_CONFLICT"):
        IncidentExecutionBoundary(ledger).execute(request)


def test_identity_canonicalization_contract() -> None:
    first = _request(IncidentExecutionBoundary(), "Incident-ABC")
    duplicate_evidence = replace(
        first,
        evidence_references=first.evidence_references + first.evidence_references,
    )

    assert first.execution_identity == duplicate_evidence.execution_identity
    assert (
        first.execution_identity
        != replace(first, incident_id="incident-abc").execution_identity
    )
    assert (
        first.execution_identity
        != replace(
            first, policy_references=(first.policy_references[0].upper(),)
        ).execution_identity
    )


def test_duplicate_request_is_idempotent_in_one_boundary() -> None:
    boundary = IncidentExecutionBoundary()
    request = _request(boundary)

    assert boundary.execute(request) is boundary.execute(request)


def test_cross_incident_isolation() -> None:
    boundary = IncidentExecutionBoundary()
    first = _request(boundary, "incident-001")
    second = _request(boundary, "incident-002")

    assert first.execution_identity != second.execution_identity
    assert boundary.execute(first).incident_id == "incident-001"
    assert boundary.execute(second).incident_id == "incident-002"


def test_request_and_result_are_deeply_immutable() -> None:
    request = _request(IncidentExecutionBoundary())
    result = IncidentExecutionBoundary().execute(request)

    with pytest.raises(FrozenInstanceError):
        request.requested_action = "disable-credential"
    with pytest.raises(FrozenInstanceError):
        request.governance.requested_action = "disable-credential"
    with pytest.raises(FrozenInstanceError):
        result.status = "executed"
    assert isinstance(request.evidence_references, tuple)
    assert all(isinstance(item, tuple) for item in request.evidence_references)


def test_missing_incident_and_tampered_governance_are_rejected() -> None:
    governance = _governance()
    missing = replace(
        governance,
        lifecycle=replace(
            governance.lifecycle,
            intake=replace(governance.lifecycle.intake, incident_id=""),
        ),
    )
    with pytest.raises(ValueError, match="INCIDENT_EXECUTION_INCIDENT_ID_REQUIRED"):
        IncidentExecutionBoundary().create_request(missing)
    with pytest.raises(ValueError, match="INCIDENT_GOVERNANCE_RECORD_INVALID"):
        IncidentExecutionBoundary().create_request(
            replace(governance, decision_sha256="0" * 64)
        )


def test_digest_preserves_opaque_case_and_action() -> None:
    governance = _governance()
    arguments = {
        "incident_id": governance.incident_id,
        "governance_decision": governance.decision,
        "governance_decision_sha256": governance.decision_sha256,
        "lifecycle_state": governance.lifecycle.state,
        "lifecycle_head_sha256": ZERO_SHA256,
        "intake_root_sha256": governance.lifecycle.intake_root_sha256,
        "tenant_ref": governance.tenant_ref,
        "workload_ref": governance.workload_ref,
        "requested_action": governance.requested_action,
        "evidence_references": governance.lifecycle.intake.evidence_references,
    }
    baseline = execution_request_digest(**arguments)

    assert baseline != execution_request_digest(
        **{**arguments, "incident_id": "Incident-001"}
    )
    assert baseline != execution_request_digest(
        **{**arguments, "requested_action": "disable-credential"}
    )
