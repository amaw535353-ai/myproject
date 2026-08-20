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


def _intake() -> IncidentIntakeRecord:
    return IncidentIntakeRecord(
        incident_id="incident-001",
        tenant_ref="ref:tenant-a",
        workload_ref="ref:workload-a",
        contributing_event_ids=("event-001",),
        evidence_references=(
            ("tenant_ref", "ref:tenant-a"),
            ("workload_ref", "ref:workload-a"),
        ),
        severities=("high",),
        highest_severity="high",
        categories=("application_agent",),
    )


def _governance(
    decision: IncidentGovernanceDecision = IncidentGovernanceDecision.APPROVED,
    lifecycle_state: IncidentLifecycleState = IncidentLifecycleState.OPEN,
):
    lifecycle_boundary = IncidentLifecycleBoundary()
    lifecycle = lifecycle_boundary.open(_intake())
    if lifecycle_state is IncidentLifecycleState.ACKNOWLEDGED:
        lifecycle = lifecycle_boundary.transition(
            lifecycle, IncidentLifecycleState.ACKNOWLEDGED
        )
    return IncidentGovernanceBoundary().evaluate(
        lifecycle,
        tenant_ref="ref:tenant-a",
        workload_ref="ref:workload-a",
        requested_action="isolate-workload",
        policy_decision=decision,
    )


def test_approved_governance_creates_execution_request() -> None:
    governance = _governance()

    request = IncidentExecutionBoundary().create_request(governance)

    assert request.governance is governance
    assert request.incident_id == governance.incident_id
    assert request.governance_decision is IncidentGovernanceDecision.APPROVED
    assert request.requested_action == "isolate-workload"


def test_denied_governance_is_rejected() -> None:
    with pytest.raises(ValueError, match="DENIED_GOVERNANCE_EXECUTION_REJECTED"):
        IncidentExecutionBoundary().create_request(
            _governance(IncidentGovernanceDecision.DENIED)
        )


def test_lifecycle_state_and_provenance_are_preserved() -> None:
    governance = _governance(
        lifecycle_state=IncidentLifecycleState.ACKNOWLEDGED
    )

    request = IncidentExecutionBoundary().create_request(governance)

    assert request.lifecycle_state is IncidentLifecycleState.ACKNOWLEDGED
    assert request.policy_references == (governance.decision_sha256,)
    assert request.provenance_references == (
        governance.lifecycle.intake_root_sha256,
        governance.lifecycle.transitions[-1].transition_sha256,
    )


def test_evidence_references_are_preserved() -> None:
    governance = _governance()

    request = IncidentExecutionBoundary().create_request(governance)

    assert request.evidence_references == governance.lifecycle.intake.evidence_references


def test_execution_request_digest_is_deterministic() -> None:
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

    assert execution_request_digest(**arguments) == execution_request_digest(
        **arguments
    )
    assert execution_request_digest(**arguments) != execution_request_digest(
        **{**arguments, "requested_action": "disable-credential"}
    )


def test_duplicate_execution_requests_are_identical() -> None:
    governance = _governance()
    boundary = IncidentExecutionBoundary()

    first = boundary.create_request(governance)
    second = boundary.create_request(governance)

    assert first == second
    assert first.request_sha256 == second.request_sha256


def test_execution_request_is_immutable() -> None:
    request = IncidentExecutionBoundary().create_request(_governance())

    with pytest.raises(FrozenInstanceError):
        request.requested_action = "disable-credential"


def test_invalid_input_is_rejected() -> None:
    with pytest.raises(TypeError, match="INCIDENT_GOVERNANCE_RECORD_REQUIRED"):
        IncidentExecutionBoundary().create_request(object())


def test_tampered_governance_is_rejected() -> None:
    governance = _governance()

    with pytest.raises(ValueError, match="INCIDENT_GOVERNANCE_RECORD_INVALID"):
        IncidentExecutionBoundary().create_request(
            replace(governance, decision_sha256="0" * 64)
        )
