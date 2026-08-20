from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from aegis.incidents.governance import (
    P16_GOVERNANCE_SCHEMA_VERSION,
    IncidentGovernanceDecision,
    IncidentGovernanceRecord,
    governance_decision_digest,
)
from aegis.incidents.lifecycle import (
    ZERO_SHA256,
    IncidentLifecycleState,
    _validate_record,
)


P17_EXECUTION_SCHEMA_VERSION = "aegis-incident-execution-request-v1"
P17_EXECUTION_REQUEST_DOMAIN = "aegis-p17-incident-execution-request-v1"


@dataclass(frozen=True)
class IncidentExecutionRequest:
    governance: IncidentGovernanceRecord
    incident_id: str
    governance_decision: IncidentGovernanceDecision
    lifecycle_state: IncidentLifecycleState
    requested_action: str
    evidence_references: tuple[tuple[str, str], ...]
    policy_references: tuple[str, ...]
    provenance_references: tuple[str, ...]
    request_sha256: str
    schema_version: str = P17_EXECUTION_SCHEMA_VERSION


def execution_request_digest(
    *,
    incident_id: str,
    governance_decision: IncidentGovernanceDecision,
    governance_decision_sha256: str,
    lifecycle_state: IncidentLifecycleState,
    lifecycle_head_sha256: str,
    intake_root_sha256: str,
    tenant_ref: str,
    workload_ref: str,
    requested_action: str,
    evidence_references: tuple[tuple[str, str], ...],
) -> str:
    material = {
        "domain": P17_EXECUTION_REQUEST_DOMAIN,
        "evidence_references": [list(item) for item in evidence_references],
        "governance_decision": governance_decision.value,
        "governance_decision_sha256": governance_decision_sha256.casefold(),
        "incident_id": incident_id,
        "intake_root_sha256": intake_root_sha256.casefold(),
        "lifecycle_head_sha256": lifecycle_head_sha256.casefold(),
        "lifecycle_state": lifecycle_state.value,
        "requested_action": requested_action,
        "tenant_ref": tenant_ref,
        "workload_ref": workload_ref,
    }
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_governance(record: IncidentGovernanceRecord) -> str:
    if not isinstance(record, IncidentGovernanceRecord):
        raise TypeError("INCIDENT_GOVERNANCE_RECORD_REQUIRED")
    _validate_record(record.lifecycle)
    if record.schema_version != P16_GOVERNANCE_SCHEMA_VERSION:
        raise ValueError("INCIDENT_GOVERNANCE_SCHEMA_INVALID")
    if record.tenant_ref != record.lifecycle.intake.tenant_ref:
        raise ValueError("INCIDENT_GOVERNANCE_TENANT_MISMATCH")
    if record.workload_ref != record.lifecycle.intake.workload_ref:
        raise ValueError("INCIDENT_GOVERNANCE_WORKLOAD_MISMATCH")
    if not record.requested_action:
        raise ValueError("INCIDENT_GOVERNANCE_ACTION_REQUIRED")
    if not isinstance(record.decision, IncidentGovernanceDecision):
        raise ValueError("INCIDENT_GOVERNANCE_POLICY_DECISION_INVALID")

    lifecycle_head = (
        record.lifecycle.transitions[-1].transition_sha256
        if record.lifecycle.transitions
        else ZERO_SHA256
    )
    expected_digest = governance_decision_digest(
        incident_id=record.incident_id,
        intake_root_sha256=record.lifecycle.intake_root_sha256,
        lifecycle_state=record.lifecycle.state,
        lifecycle_head_sha256=lifecycle_head,
        tenant_ref=record.tenant_ref,
        workload_ref=record.workload_ref,
        requested_action=record.requested_action,
        decision=record.decision,
    )
    if record.decision_sha256.casefold() != expected_digest:
        raise ValueError("INCIDENT_GOVERNANCE_RECORD_INVALID")
    return lifecycle_head.casefold()


class IncidentExecutionBoundary:
    """Create inert execution requests without performing response actions."""

    def create_request(
        self, governance: IncidentGovernanceRecord
    ) -> IncidentExecutionRequest:
        lifecycle_head = _validate_governance(governance)
        if governance.lifecycle.state is IncidentLifecycleState.CLOSED:
            raise ValueError("CLOSED_INCIDENT_EXECUTION_REJECTED")
        if governance.decision is IncidentGovernanceDecision.DENIED:
            raise ValueError("DENIED_GOVERNANCE_EXECUTION_REJECTED")
        if governance.decision is not IncidentGovernanceDecision.APPROVED:
            raise ValueError("INCIDENT_EXECUTION_APPROVAL_REQUIRED")

        intake = governance.lifecycle.intake
        request_digest = execution_request_digest(
            incident_id=governance.incident_id,
            governance_decision=governance.decision,
            governance_decision_sha256=governance.decision_sha256,
            lifecycle_state=governance.lifecycle.state,
            lifecycle_head_sha256=lifecycle_head,
            intake_root_sha256=governance.lifecycle.intake_root_sha256,
            tenant_ref=governance.tenant_ref,
            workload_ref=governance.workload_ref,
            requested_action=governance.requested_action,
            evidence_references=intake.evidence_references,
        )
        return IncidentExecutionRequest(
            governance=governance,
            incident_id=governance.incident_id,
            governance_decision=governance.decision,
            lifecycle_state=governance.lifecycle.state,
            requested_action=governance.requested_action,
            evidence_references=intake.evidence_references,
            policy_references=(governance.decision_sha256.casefold(),),
            provenance_references=(
                governance.lifecycle.intake_root_sha256.casefold(),
                lifecycle_head,
            ),
            request_sha256=request_digest,
        )
