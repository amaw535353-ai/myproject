from dataclasses import FrozenInstanceError, replace

import pytest

from aegis.incidents.governance import (
    IncidentGovernanceBoundary,
    IncidentGovernanceDecision,
    governance_decision_digest,
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


def _lifecycle(state: IncidentLifecycleState = IncidentLifecycleState.OPEN):
    boundary = IncidentLifecycleBoundary()
    record = boundary.open(_intake())
    path = (
        IncidentLifecycleState.ACKNOWLEDGED,
        IncidentLifecycleState.INVESTIGATING,
        IncidentLifecycleState.RESOLVED,
        IncidentLifecycleState.CLOSED,
    )
    for target in path:
        if record.state is state:
            break
        record = boundary.transition(record, target)
    return record


def _evaluate(decision: IncidentGovernanceDecision):
    return IncidentGovernanceBoundary().evaluate(
        _lifecycle(),
        tenant_ref="ref:tenant-a",
        workload_ref="ref:workload-a",
        requested_action="isolate-workload",
        policy_decision=decision,
    )


@pytest.mark.parametrize(
    "decision",
    (
        IncidentGovernanceDecision.APPROVED,
        IncidentGovernanceDecision.DENIED,
        IncidentGovernanceDecision.REQUIRES_APPROVAL,
    ),
)
def test_governance_policy_decisions_are_recorded(decision) -> None:
    record = _evaluate(decision)

    assert record.decision is decision
    assert record.incident_id == "incident-001"
    assert record.requested_action == "isolate-workload"


def test_closed_incident_is_rejected() -> None:
    with pytest.raises(ValueError, match="CLOSED_INCIDENT_ACTION_REJECTED"):
        IncidentGovernanceBoundary().evaluate(
            _lifecycle(IncidentLifecycleState.CLOSED),
            tenant_ref="ref:tenant-a",
            workload_ref="ref:workload-a",
            requested_action="isolate-workload",
            policy_decision=IncidentGovernanceDecision.APPROVED,
        )


def test_tenant_mismatch_is_rejected() -> None:
    with pytest.raises(ValueError, match="INCIDENT_GOVERNANCE_TENANT_MISMATCH"):
        IncidentGovernanceBoundary().evaluate(
            _lifecycle(),
            tenant_ref="ref:tenant-b",
            workload_ref="ref:workload-a",
            requested_action="isolate-workload",
            policy_decision=IncidentGovernanceDecision.APPROVED,
        )


def test_workload_mismatch_is_rejected() -> None:
    with pytest.raises(ValueError, match="INCIDENT_GOVERNANCE_WORKLOAD_MISMATCH"):
        IncidentGovernanceBoundary().evaluate(
            _lifecycle(),
            tenant_ref="ref:tenant-a",
            workload_ref="ref:workload-b",
            requested_action="isolate-workload",
            policy_decision=IncidentGovernanceDecision.APPROVED,
        )


def test_missing_policy_decision_is_rejected() -> None:
    with pytest.raises(
        ValueError, match="INCIDENT_GOVERNANCE_POLICY_DECISION_REQUIRED"
    ):
        IncidentGovernanceBoundary().evaluate(
            _lifecycle(),
            tenant_ref="ref:tenant-a",
            workload_ref="ref:workload-a",
            requested_action="isolate-workload",
            policy_decision=None,
        )


def test_governance_decision_digest_is_deterministic() -> None:
    lifecycle = _lifecycle()
    arguments = {
        "incident_id": lifecycle.incident_id,
        "intake_root_sha256": lifecycle.intake_root_sha256,
        "lifecycle_state": lifecycle.state,
        "lifecycle_head_sha256": ZERO_SHA256,
        "tenant_ref": lifecycle.intake.tenant_ref,
        "workload_ref": lifecycle.intake.workload_ref,
        "requested_action": "isolate-workload",
        "decision": IncidentGovernanceDecision.APPROVED,
    }

    assert governance_decision_digest(**arguments) == governance_decision_digest(
        **arguments
    )
    assert governance_decision_digest(**arguments) != governance_decision_digest(
        **{**arguments, "decision": IncidentGovernanceDecision.DENIED}
    )


def test_governance_output_is_immutable() -> None:
    record = _evaluate(IncidentGovernanceDecision.APPROVED)

    with pytest.raises(FrozenInstanceError):
        record.decision = IncidentGovernanceDecision.DENIED


def test_invalid_lifecycle_is_rejected() -> None:
    lifecycle = _lifecycle()

    with pytest.raises(ValueError, match="INCIDENT_LIFECYCLE_INTAKE_ROOT_INVALID"):
        IncidentGovernanceBoundary().evaluate(
            replace(lifecycle, intake_root_sha256="0" * 64),
            tenant_ref="ref:tenant-a",
            workload_ref="ref:workload-a",
            requested_action="isolate-workload",
            policy_decision=IncidentGovernanceDecision.APPROVED,
        )
