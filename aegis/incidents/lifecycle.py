from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum

from aegis.incidents.types import IncidentIntakeRecord


P15_LIFECYCLE_SCHEMA_VERSION = "aegis-incident-lifecycle-v1"
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
    sequence: int
    from_state: IncidentLifecycleState
    to_state: IncidentLifecycleState
    previous_transition_sha256: str
    transition_sha256: str


@dataclass(frozen=True)
class IncidentLifecycleRecord:
    intake: IncidentIntakeRecord
    state: IncidentLifecycleState
    transitions: tuple[IncidentLifecycleTransition, ...] = ()
    schema_version: str = P15_LIFECYCLE_SCHEMA_VERSION

    @property
    def incident_id(self) -> str:
        return self.intake.incident_id


def transition_digest(
    *,
    incident_id: str,
    sequence: int,
    from_state: IncidentLifecycleState,
    to_state: IncidentLifecycleState,
    previous_transition_sha256: str,
) -> str:
    material = {
        "domain": P15_TRANSITION_DOMAIN,
        "from_state": from_state.value,
        "incident_id": incident_id,
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

    expected_state = IncidentLifecycleState.OPEN
    previous = ZERO_SHA256
    for sequence, item in enumerate(record.transitions, 1):
        if (
            not isinstance(item, IncidentLifecycleTransition)
            or item.incident_id != record.incident_id
            or item.sequence != sequence
            or item.from_state != expected_state
            or item.to_state not in _ALLOWED_TRANSITIONS[expected_state]
            or item.previous_transition_sha256.casefold() != previous
            or item.transition_sha256.casefold() != transition_digest(
                incident_id=item.incident_id,
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

    def open(self, intake: IncidentIntakeRecord) -> IncidentLifecycleRecord:
        _validate_intake(intake)
        return IncidentLifecycleRecord(
            intake=intake,
            state=IncidentLifecycleState.OPEN,
        )

    def transition(
        self,
        record: IncidentLifecycleRecord,
        to_state: IncidentLifecycleState,
    ) -> IncidentLifecycleRecord:
        _validate_record(record)
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
            sequence=sequence,
            from_state=record.state,
            to_state=to_state,
            previous_transition_sha256=previous,
            transition_sha256=transition_digest(
                incident_id=record.incident_id,
                sequence=sequence,
                from_state=record.state,
                to_state=to_state,
                previous_transition_sha256=previous,
            ),
        )
        return IncidentLifecycleRecord(
            intake=record.intake,
            state=to_state,
            transitions=record.transitions + (item,),
        )
