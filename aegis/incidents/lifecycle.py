from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

from aegis.incidents.types import IncidentIntakeRecord


P15_LIFECYCLE_SCHEMA_VERSION = "aegis-incident-lifecycle-v1"
P15_INTAKE_ROOT_DOMAIN = "aegis-p15-incident-intake-root-v1"
P15_TRANSITION_DOMAIN = "aegis-p15-incident-lifecycle-transition-v1"
ZERO_SHA256 = "0" * 64


class IncidentLifecycleState(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


_ALLOWED_TRANSITIONS = {
    IncidentLifecycleState.OPEN: frozenset({IncidentLifecycleState.ACKNOWLEDGED}),
    IncidentLifecycleState.ACKNOWLEDGED: frozenset({IncidentLifecycleState.INVESTIGATING}),
    IncidentLifecycleState.INVESTIGATING: frozenset({
        IncidentLifecycleState.CONTAINED,
        IncidentLifecycleState.RESOLVED,
    }),
    IncidentLifecycleState.CONTAINED: frozenset({IncidentLifecycleState.RESOLVED}),
    IncidentLifecycleState.RESOLVED: frozenset({IncidentLifecycleState.CLOSED}),
    IncidentLifecycleState.CLOSED: frozenset(),
}


@dataclass(frozen=True)
class IncidentLifecycleTransition:
    incident_id: str
    intake_root_sha256: str
    sequence: int
    from_state: IncidentLifecycleState
    to_state: IncidentLifecycleState
    previous_transition_sha256: str
    transition_sha256: str


@dataclass(frozen=True)
class IncidentLifecycleRecord:
    intake: IncidentIntakeRecord
    intake_root_sha256: str
    state: IncidentLifecycleState
    transitions: tuple[IncidentLifecycleTransition, ...] = ()
    schema_version: str = P15_LIFECYCLE_SCHEMA_VERSION

    @property
    def incident_id(self) -> str:
        return self.intake.incident_id


def intake_root_digest(intake: IncidentIntakeRecord) -> str:
    _validate_intake(intake)
    material = {
        "contributing_event_ids": list(intake.contributing_event_ids),
        "domain": P15_INTAKE_ROOT_DOMAIN,
        "evidence_references": [list(item) for item in intake.evidence_references],
        "incident_id": intake.incident_id,
        "tenant_ref": intake.tenant_ref,
        "workload_ref": intake.workload_ref,
    }
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def transition_digest(
    *,
    incident_id: str,
    intake_root_sha256: str,
    sequence: int,
    from_state: IncidentLifecycleState,
    to_state: IncidentLifecycleState,
    previous_transition_sha256: str,
) -> str:
    material = {
        "domain": P15_TRANSITION_DOMAIN,
        "from_state": from_state.value,
        "incident_id": incident_id,
        "intake_root_sha256": intake_root_sha256.casefold(),
        "previous_transition_sha256": previous_transition_sha256.casefold(),
        "sequence": sequence,
        "to_state": to_state.value,
    }
    encoded = json.dumps(
        material, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_intake(intake: IncidentIntakeRecord) -> None:
    if not isinstance(intake, IncidentIntakeRecord):
        raise TypeError("INCIDENT_INTAKE_RECORD_REQUIRED")
    if (
        not intake.incident_id
        or not intake.tenant_ref
        or not intake.workload_ref
        or not intake.contributing_event_ids
        or not intake.evidence_references
    ):
        raise ValueError("INCIDENT_INTAKE_RECORD_INVALID")


def _validate_record(record: IncidentLifecycleRecord) -> None:
    if not isinstance(record, IncidentLifecycleRecord):
        raise TypeError("INCIDENT_LIFECYCLE_RECORD_REQUIRED")
    _validate_intake(record.intake)
    if record.schema_version != P15_LIFECYCLE_SCHEMA_VERSION:
        raise ValueError("INCIDENT_LIFECYCLE_SCHEMA_INVALID")
    if record.intake_root_sha256.casefold() != intake_root_digest(record.intake):
        raise ValueError("INCIDENT_LIFECYCLE_INTAKE_ROOT_INVALID")

    expected_state = IncidentLifecycleState.OPEN
    previous = ZERO_SHA256
    for sequence, item in enumerate(record.transitions, 1):
        if (
            not isinstance(item, IncidentLifecycleTransition)
            or item.incident_id != record.incident_id
            or item.intake_root_sha256.casefold()
            != record.intake_root_sha256.casefold()
            or item.sequence != sequence
            or item.from_state != expected_state
            or item.to_state not in _ALLOWED_TRANSITIONS[expected_state]
            or item.previous_transition_sha256.casefold() != previous
            or item.transition_sha256.casefold() != transition_digest(
                incident_id=item.incident_id,
                intake_root_sha256=item.intake_root_sha256,
                sequence=item.sequence,
                from_state=item.from_state,
                to_state=item.to_state,
                previous_transition_sha256=item.previous_transition_sha256,
            )
        ):
            raise ValueError("INCIDENT_LIFECYCLE_CHAIN_INVALID")
        expected_state = item.to_state
        previous = item.transition_sha256.casefold()
    if record.state != expected_state:
        raise ValueError("INCIDENT_LIFECYCLE_STATE_INVALID")


class IncidentLifecycleBoundary:
    """Track incident state without executing containment or response actions."""

    def __init__(self) -> None:
        self._canonical_transitions: dict[str, dict[int, str]] = {}

    def _bind_chain(self, record: IncidentLifecycleRecord) -> None:
        root = record.intake_root_sha256.casefold()
        canonical = self._canonical_transitions.setdefault(root, {})
        for item in record.transitions:
            digest = item.transition_sha256.casefold()
            if item.sequence in canonical and canonical[item.sequence] != digest:
                raise ValueError("INCIDENT_LIFECYCLE_FORK_INVALID")
            canonical[item.sequence] = digest

    def open(self, intake: IncidentIntakeRecord) -> IncidentLifecycleRecord:
        _validate_intake(intake)
        record = IncidentLifecycleRecord(
            intake=intake,
            intake_root_sha256=intake_root_digest(intake),
            state=IncidentLifecycleState.OPEN,
        )
        self._bind_chain(record)
        return record

    def transition(
        self,
        record: IncidentLifecycleRecord,
        to_state: IncidentLifecycleState,
    ) -> IncidentLifecycleRecord:
        _validate_record(record)
        self._bind_chain(record)
        if not isinstance(to_state, IncidentLifecycleState):
            raise TypeError("INCIDENT_LIFECYCLE_STATE_REQUIRED")

        # Reapplying the latest completed transition is an idempotent replay.
        if record.transitions and to_state == record.state:
            return record
        if to_state not in _ALLOWED_TRANSITIONS[record.state]:
            raise ValueError("INCIDENT_LIFECYCLE_TRANSITION_INVALID")

        previous = (
            record.transitions[-1].transition_sha256
            if record.transitions
            else ZERO_SHA256
        )
        sequence = len(record.transitions) + 1
        item = IncidentLifecycleTransition(
            incident_id=record.incident_id,
            intake_root_sha256=record.intake_root_sha256,
            sequence=sequence,
            from_state=record.state,
            to_state=to_state,
            previous_transition_sha256=previous,
            transition_sha256=transition_digest(
                incident_id=record.incident_id,
                intake_root_sha256=record.intake_root_sha256,
                sequence=sequence,
                from_state=record.state,
                to_state=to_state,
                previous_transition_sha256=previous,
            ),
        )
        result = IncidentLifecycleRecord(
            intake=record.intake,
            intake_root_sha256=record.intake_root_sha256,
            state=to_state,
            transitions=record.transitions + (item,),
        )
        self._bind_chain(result)
        return result
