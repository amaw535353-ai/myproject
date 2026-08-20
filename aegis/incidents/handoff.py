from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from aegis.incidents.execution import (
    P17_EXECUTION_SCHEMA_VERSION,
    IncidentExecutionRequest,
    _validate_governance,
    execution_request_digest,
)
from aegis.incidents.governance import IncidentGovernanceDecision
from aegis.incidents.lifecycle import IncidentLifecycleState


P18_HANDOFF_SCHEMA_VERSION = "aegis-response-handoff-request-v1"
P18_HANDOFF_REQUEST_DOMAIN = "aegis-p18-response-handoff-request-v1"


@dataclass(frozen=True)
class IncidentResponseHandoffRequest:
    execution: IncidentExecutionRequest
    handoff_id: str
    incident_id: str
    execution_request_sha256: str
    governance_decision: IncidentGovernanceDecision
    lifecycle_state: IncidentLifecycleState
    evidence_references: tuple[tuple[str, str], ...]
    policy_references: tuple[str, ...]
    provenance_references: tuple[str, ...]
    requested_action: str
    schema_version: str = P18_HANDOFF_SCHEMA_VERSION


def handoff_request_digest(
    *,
    incident_id: str,
    execution_request_sha256: str,
    governance_decision: IncidentGovernanceDecision,
    lifecycle_state: IncidentLifecycleState,
    evidence_references: tuple[tuple[str, str], ...],
    policy_references: tuple[str, ...],
    provenance_references: tuple[str, ...],
    requested_action: str,
) -> str:
    material = {
        "domain": P18_HANDOFF_REQUEST_DOMAIN,
        "evidence_references": [list(item) for item in evidence_references],
        "execution_request_sha256": execution_request_sha256.casefold(),
        "governance_decision": governance_decision.value,
        "incident_id": incident_id,
        "lifecycle_state": lifecycle_state.value,
        "policy_references": list(policy_references),
        "provenance_references": list(provenance_references),
        "requested_action": requested_action,
    }
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_execution_request(request: IncidentExecutionRequest) -> None:
    if not isinstance(request, IncidentExecutionRequest):
        raise TypeError("INCIDENT_EXECUTION_REQUEST_REQUIRED")
    lifecycle_head = _validate_governance(request.governance)
    lifecycle = request.governance.lifecycle
    intake = lifecycle.intake
    expected_policy = (request.governance.decision_sha256.casefold(),)
    expected_provenance = (
        lifecycle.intake_root_sha256.casefold(),
        lifecycle_head,
    )
    if (
        request.schema_version != P17_EXECUTION_SCHEMA_VERSION
        or request.incident_id != request.governance.incident_id
        or request.governance_decision is not request.governance.decision
        or request.lifecycle_state is not lifecycle.state
        or request.requested_action != request.governance.requested_action
        or request.evidence_references != intake.evidence_references
        or request.policy_references != expected_policy
        or request.provenance_references != expected_provenance
    ):
        raise ValueError("INCIDENT_EXECUTION_REQUEST_INVALID")
    expected_digest = execution_request_digest(
        incident_id=request.incident_id,
        governance_decision=request.governance_decision,
        governance_decision_sha256=request.governance.decision_sha256,
        lifecycle_state=request.lifecycle_state,
        lifecycle_head_sha256=lifecycle_head,
        intake_root_sha256=lifecycle.intake_root_sha256,
        tenant_ref=request.governance.tenant_ref,
        workload_ref=request.governance.workload_ref,
        requested_action=request.requested_action,
        evidence_references=request.evidence_references,
    )
    if request.request_sha256.casefold() != expected_digest:
        raise ValueError("INCIDENT_EXECUTION_REQUEST_INVALID")


class IncidentResponseHandoffBoundary:
    """Create inert handoff records without contacting a response system."""

    def create_handoff(
        self, execution: IncidentExecutionRequest
    ) -> IncidentResponseHandoffRequest:
        _validate_execution_request(execution)
        if execution.governance_decision is not IncidentGovernanceDecision.APPROVED:
            raise ValueError("INCIDENT_HANDOFF_APPROVED_EXECUTION_REQUIRED")
        if execution.lifecycle_state is IncidentLifecycleState.CLOSED:
            raise ValueError("CLOSED_INCIDENT_HANDOFF_REJECTED")

        digest = handoff_request_digest(
            incident_id=execution.incident_id,
            execution_request_sha256=execution.request_sha256,
            governance_decision=execution.governance_decision,
            lifecycle_state=execution.lifecycle_state,
            evidence_references=execution.evidence_references,
            policy_references=execution.policy_references,
            provenance_references=execution.provenance_references,
            requested_action=execution.requested_action,
        )
        return IncidentResponseHandoffRequest(
            execution=execution,
            handoff_id="handoff-" + digest,
            incident_id=execution.incident_id,
            execution_request_sha256=execution.request_sha256.casefold(),
            governance_decision=execution.governance_decision,
            lifecycle_state=execution.lifecycle_state,
            evidence_references=execution.evidence_references,
            policy_references=execution.policy_references,
            provenance_references=execution.provenance_references,
            requested_action=execution.requested_action,
        )
