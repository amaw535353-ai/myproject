from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path

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
P17_EXECUTION_ID_DOMAIN = "aegis-p17-incident-execution-identity-v1"
P17_EXECUTION_STATUS = "projected"


@dataclass(frozen=True)
class IncidentExecutionRequest:
    """Frozen, inert projection of an approved incident response action."""

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

    @property
    def governance_decision_reference(self) -> str:
        return self.governance.decision_sha256.casefold()

    @property
    def execution_identity(self) -> str:
        return execution_identity(
            incident_id=self.incident_id,
            governance_decision_reference=self.governance_decision_reference,
            requested_action=self.requested_action,
            policy_references=self.policy_references,
            evidence_references=self.evidence_references,
        )


@dataclass(frozen=True)
class IncidentExecutionResult:
    """Frozen record that an execution was projected, never performed."""

    incident_id: str
    governance_decision_reference: str
    requested_action: str
    policy_references: tuple[str, ...]
    evidence_references: tuple[tuple[str, str], ...]
    execution_identity: str
    status: str = P17_EXECUTION_STATUS
    schema_version: str = P17_EXECUTION_SCHEMA_VERSION


def _canonical_strings(values: tuple[str, ...], *, error: str) -> tuple[str, ...]:
    if not values or any(not isinstance(value, str) or not value for value in values):
        raise ValueError(error)
    return tuple(sorted(set(values)))


def _canonical_evidence(
    values: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    if not values or any(
        not isinstance(item, tuple)
        or len(item) != 2
        or not all(isinstance(value, str) and value for value in item)
        for item in values
    ):
        raise ValueError("INCIDENT_EXECUTION_EVIDENCE_REQUIRED")
    return tuple(sorted(set(values)))


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
    """Compatibility wrapper with the exact original P17 call signature.

    Opaque identifiers and references are case-sensitive. Only hexadecimal digest
    fields are normalized to lowercase.
    """

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


def execution_identity(
    *,
    incident_id: str,
    governance_decision_reference: str,
    requested_action: str,
    policy_references: tuple[str, ...],
    evidence_references: tuple[tuple[str, str], ...],
) -> str:
    """Canonical identity with ordering/duplicate independence for collections."""

    if not incident_id:
        raise ValueError("INCIDENT_EXECUTION_INCIDENT_ID_REQUIRED")
    material = {
        "domain": P17_EXECUTION_ID_DOMAIN,
        "evidence_references": [
            list(item) for item in _canonical_evidence(evidence_references)
        ],
        "governance_decision_reference": governance_decision_reference.casefold(),
        "incident_id": incident_id,
        "policy_references": list(
            _canonical_strings(
                policy_references, error="INCIDENT_EXECUTION_POLICY_REQUIRED"
            )
        ),
        "requested_action": requested_action,
    }
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return "execution-" + hashlib.sha256(encoded).hexdigest()


def _validate_governance(record: IncidentGovernanceRecord) -> str:
    if not isinstance(record, IncidentGovernanceRecord):
        raise TypeError("INCIDENT_GOVERNANCE_RECORD_REQUIRED")
    if not record.incident_id:
        raise ValueError("INCIDENT_EXECUTION_INCIDENT_ID_REQUIRED")
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
    if (
        not record.decision_sha256
        or record.decision_sha256.casefold() != expected_digest
    ):
        raise ValueError("INCIDENT_GOVERNANCE_RECORD_INVALID")
    return lifecycle_head.casefold()


def _validate_request(request: IncidentExecutionRequest) -> None:
    if not isinstance(request, IncidentExecutionRequest):
        raise TypeError("INCIDENT_EXECUTION_REQUEST_REQUIRED")
    lifecycle_head = _validate_governance(request.governance)
    governance = request.governance
    if (
        request.schema_version != P17_EXECUTION_SCHEMA_VERSION
        or request.incident_id != governance.incident_id
        or request.governance_decision is not governance.decision
        or request.lifecycle_state is not governance.lifecycle.state
        or request.requested_action != governance.requested_action
        or request.evidence_references
        != governance.lifecycle.intake.evidence_references
        or request.policy_references != (governance.decision_sha256.casefold(),)
        or request.provenance_references
        != (governance.lifecycle.intake_root_sha256.casefold(), lifecycle_head)
    ):
        raise ValueError("INCIDENT_EXECUTION_REQUEST_INVALID")
    expected_digest = execution_request_digest(
        incident_id=request.incident_id,
        governance_decision=request.governance_decision,
        governance_decision_sha256=governance.decision_sha256,
        lifecycle_state=request.lifecycle_state,
        lifecycle_head_sha256=lifecycle_head,
        intake_root_sha256=governance.lifecycle.intake_root_sha256,
        tenant_ref=governance.tenant_ref,
        workload_ref=governance.workload_ref,
        requested_action=request.requested_action,
        evidence_references=request.evidence_references,
    )
    if request.request_sha256.casefold() != expected_digest:
        raise ValueError("INCIDENT_EXECUTION_REQUEST_INVALID")


def _request_fingerprint(request: IncidentExecutionRequest) -> str:
    material = {
        "execution_identity": request.execution_identity,
        "request_sha256": request.request_sha256.casefold(),
        "schema_version": request.schema_version,
    }
    return hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


class IncidentExecutionBoundary:
    """Project inert results; SQLite is required for cross-process replay protection."""

    def __init__(self, ledger_path: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(str(ledger_path))
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_execution_ledger (
                execution_identity TEXT PRIMARY KEY,
                request_sha256 TEXT NOT NULL UNIQUE,
                request_fingerprint TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
            """
        )
        self._connection.commit()
        self._results: dict[str, IncidentExecutionResult] = {}

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

    def execute(self, request: IncidentExecutionRequest) -> IncidentExecutionResult:
        """Persist an inert projection after validation; perform no response action."""

        _validate_request(request)
        identity = request.execution_identity
        fingerprint = _request_fingerprint(request)
        result = IncidentExecutionResult(
            incident_id=request.incident_id,
            governance_decision_reference=request.governance_decision_reference,
            requested_action=request.requested_action,
            policy_references=request.policy_references,
            evidence_references=request.evidence_references,
            execution_identity=identity,
        )
        result_json = json.dumps(
            {
                "evidence_references": [
                    list(item) for item in result.evidence_references
                ],
                "execution_identity": result.execution_identity,
                "governance_decision_reference": result.governance_decision_reference,
                "incident_id": result.incident_id,
                "policy_references": list(result.policy_references),
                "requested_action": result.requested_action,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        with self._connection:
            prior = self._connection.execute(
                """SELECT request_sha256, request_fingerprint, result_json
                   FROM incident_execution_ledger WHERE execution_identity = ?""",
                (identity,),
            ).fetchone()
            expected = (request.request_sha256.casefold(), fingerprint, result_json)
            if prior is not None:
                if prior != expected:
                    raise ValueError("INCIDENT_EXECUTION_REPLAY_CONFLICT")
                cached = self._results.get(identity)
                if cached is not None:
                    return cached
                self._results[identity] = result
                return result
            try:
                self._connection.execute(
                    """INSERT INTO incident_execution_ledger
                       (execution_identity, request_sha256, request_fingerprint, result_json)
                       VALUES (?, ?, ?, ?)""",
                    (identity, *expected),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("INCIDENT_EXECUTION_REPLAY_CONFLICT") from exc
        self._results[identity] = result
        return result
