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
from aegis.incidents.handoff import (
    IncidentResponseHandoffBoundary,
    handoff_request_digest,
)
from aegis.incidents.lifecycle import IncidentLifecycleBoundary, IncidentLifecycleState
from aegis.incidents.types import IncidentIntakeRecord


def _execution():
    intake = IncidentIntakeRecord(
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
    lifecycle_boundary = IncidentLifecycleBoundary()
    lifecycle = lifecycle_boundary.transition(
        lifecycle_boundary.open(intake), IncidentLifecycleState.ACKNOWLEDGED
    )
    governance = IncidentGovernanceBoundary().evaluate(
        lifecycle,
        tenant_ref=intake.tenant_ref,
        workload_ref=intake.workload_ref,
        requested_action="isolate-workload",
        policy_decision=IncidentGovernanceDecision.APPROVED,
    )
    return IncidentExecutionBoundary().create_request(governance)


def test_approved_execution_creates_handoff() -> None:
    execution = _execution()

    handoff = IncidentResponseHandoffBoundary().create_handoff(execution)

    assert handoff.execution is execution
    assert handoff.incident_id == execution.incident_id
    assert handoff.execution_request_sha256 == execution.request_sha256
    assert handoff.governance_decision is IncidentGovernanceDecision.APPROVED
    assert handoff.lifecycle_state is IncidentLifecycleState.ACKNOWLEDGED


def test_rejected_execution_cannot_create_handoff() -> None:
    execution = _execution()
    governance = IncidentGovernanceBoundary().evaluate(
        execution.governance.lifecycle,
        tenant_ref=execution.governance.tenant_ref,
        workload_ref=execution.governance.workload_ref,
        requested_action=execution.requested_action,
        policy_decision=IncidentGovernanceDecision.DENIED,
    )
    lifecycle_head = governance.lifecycle.transitions[-1].transition_sha256
    denied = replace(
        execution,
        governance=governance,
        governance_decision=governance.decision,
        policy_references=(governance.decision_sha256,),
        request_sha256=execution_request_digest(
            incident_id=governance.incident_id,
            governance_decision=governance.decision,
            governance_decision_sha256=governance.decision_sha256,
            lifecycle_state=governance.lifecycle.state,
            lifecycle_head_sha256=lifecycle_head,
            intake_root_sha256=governance.lifecycle.intake_root_sha256,
            tenant_ref=governance.tenant_ref,
            workload_ref=governance.workload_ref,
            requested_action=governance.requested_action,
            evidence_references=governance.lifecycle.intake.evidence_references,
        ),
    )

    with pytest.raises(
        ValueError, match="INCIDENT_HANDOFF_APPROVED_EXECUTION_REQUIRED"
    ):
        IncidentResponseHandoffBoundary().create_handoff(denied)


def test_evidence_references_are_preserved() -> None:
    execution = _execution()

    handoff = IncidentResponseHandoffBoundary().create_handoff(execution)

    assert handoff.evidence_references == execution.evidence_references


def test_policy_and_provenance_references_are_preserved() -> None:
    execution = _execution()

    handoff = IncidentResponseHandoffBoundary().create_handoff(execution)

    assert handoff.policy_references == execution.policy_references
    assert handoff.provenance_references == execution.provenance_references


def test_handoff_identity_is_deterministic() -> None:
    execution = _execution()
    arguments = {
        "incident_id": execution.incident_id,
        "execution_request_sha256": execution.request_sha256,
        "governance_decision": execution.governance_decision,
        "lifecycle_state": execution.lifecycle_state,
        "evidence_references": execution.evidence_references,
        "policy_references": execution.policy_references,
        "provenance_references": execution.provenance_references,
        "requested_action": execution.requested_action,
    }

    assert handoff_request_digest(**arguments) == handoff_request_digest(**arguments)
    assert handoff_request_digest(**arguments) != handoff_request_digest(
        **{**arguments, "requested_action": "disable-credential"}
    )


def test_duplicate_handoff_requests_are_identical() -> None:
    execution = _execution()
    boundary = IncidentResponseHandoffBoundary()

    first = boundary.create_handoff(execution)
    second = boundary.create_handoff(execution)

    assert first == second
    assert first.handoff_id == second.handoff_id


def test_handoff_output_is_immutable() -> None:
    handoff = IncidentResponseHandoffBoundary().create_handoff(_execution())

    with pytest.raises(FrozenInstanceError):
        handoff.handoff_id = "handoff-tampered"


def test_tampered_execution_request_is_rejected() -> None:
    execution = _execution()

    with pytest.raises(ValueError, match="INCIDENT_EXECUTION_REQUEST_INVALID"):
        IncidentResponseHandoffBoundary().create_handoff(
            replace(execution, request_sha256="0" * 64)
        )


def test_invalid_execution_input_is_rejected() -> None:
    with pytest.raises(TypeError, match="INCIDENT_EXECUTION_REQUEST_REQUIRED"):
        IncidentResponseHandoffBoundary().create_handoff(object())
