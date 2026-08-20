from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

from aegis.incidents.lifecycle import (
    ZERO_SHA256,
    IncidentLifecycleRecord,
    IncidentLifecycleState,
    _validate_record,
)


P16_GOVERNANCE_SCHEMA_VERSION = "aegis-incident-governance-v1"
P16_GOVERNANCE_DECISION_DOMAIN = "aegis-p16-incident-governance-decision-v1"


class IncidentGovernanceDecision(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"
    REQUIRES_APPROVAL = "requires_approval"


@dataclass(frozen=True)
class IncidentGovernanceRecord:
    lifecycle: IncidentLifecycleRecord
    tenant_ref: str
    workload_ref: str
    requested_action: str
    decision: IncidentGovernanceDecision
    decision_sha256: str
    schema_version: str = P16_GOVERNANCE_SCHEMA_VERSION

    @property
    def incident_id(self) -> str:
        return self.lifecycle.incident_id


def governance_decision_digest(
    *,
    incident_id: str,
    intake_root_sha256: str,
    lifecycle_state: IncidentLifecycleState,
    lifecycle_head_sha256: str,
    tenant_ref: str,
    workload_ref: str,
    requested_action: str,
    decision: IncidentGovernanceDecision,
) -> str:
    material = {
        "decision": decision.value,
        "domain": P16_GOVERNANCE_DECISION_DOMAIN,
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


class IncidentGovernanceBoundary:
    """Record policy decisions without executing the requested response action."""

    def evaluate(
        self,
        lifecycle: IncidentLifecycleRecord,
        *,
        tenant_ref: str,
        workload_ref: str,
        requested_action: str,
        policy_decision: IncidentGovernanceDecision,
    ) -> IncidentGovernanceRecord:
        _validate_record(lifecycle)
        if lifecycle.state is IncidentLifecycleState.CLOSED:
            raise ValueError("CLOSED_INCIDENT_ACTION_REJECTED")
        if tenant_ref != lifecycle.intake.tenant_ref:
            raise ValueError("INCIDENT_GOVERNANCE_TENANT_MISMATCH")
        if workload_ref != lifecycle.intake.workload_ref:
            raise ValueError("INCIDENT_GOVERNANCE_WORKLOAD_MISMATCH")
        if not requested_action:
            raise ValueError("INCIDENT_GOVERNANCE_ACTION_REQUIRED")
        if policy_decision is None or policy_decision == "":
            raise ValueError("INCIDENT_GOVERNANCE_POLICY_DECISION_REQUIRED")
        if not isinstance(policy_decision, IncidentGovernanceDecision):
            raise TypeError("INCIDENT_GOVERNANCE_POLICY_DECISION_INVALID")

        lifecycle_head = (
            lifecycle.transitions[-1].transition_sha256
            if lifecycle.transitions
            else ZERO_SHA256
        )
        digest = governance_decision_digest(
            incident_id=lifecycle.incident_id,
            intake_root_sha256=lifecycle.intake_root_sha256,
            lifecycle_state=lifecycle.state,
            lifecycle_head_sha256=lifecycle_head,
            tenant_ref=tenant_ref,
            workload_ref=workload_ref,
            requested_action=requested_action,
            decision=policy_decision,
        )
        return IncidentGovernanceRecord(
            lifecycle=lifecycle,
            tenant_ref=tenant_ref,
            workload_ref=workload_ref,
            requested_action=requested_action,
            decision=policy_decision,
            decision_sha256=digest,
        )
