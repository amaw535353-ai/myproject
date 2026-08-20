from dataclasses import FrozenInstanceError, replace

import pytest

from aegis.incidents.lifecycle import (
    ZERO_SHA256,
    IncidentLifecycleBoundary,
    IncidentLifecycleState,
    intake_root_digest,
    transition_digest,
)
from aegis.incidents.types import IncidentIntakeRecord


def _intake(incident_id: str = "incident-001") -> IncidentIntakeRecord:
    return IncidentIntakeRecord(
        incident_id=incident_id,
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


def test_open_consumes_intake_and_preserves_it() -> None:
    intake = _intake()
    record = IncidentLifecycleBoundary().open(intake)

    assert record.intake is intake
    assert record.incident_id == intake.incident_id
    assert record.state is IncidentLifecycleState.OPEN
    assert record.transitions == ()
    assert record.intake_root_sha256 == intake_root_digest(intake)


def test_intake_root_digest_is_deterministic_and_bound_to_required_fields() -> None:
    intake = _intake()

    assert intake_root_digest(intake) == intake_root_digest(intake)
    for field, value in (
        ("incident_id", "incident-002"),
        ("tenant_ref", "ref:tenant-b"),
        ("workload_ref", "ref:workload-b"),
        ("contributing_event_ids", ("event-002",)),
        ("evidence_references", (("tenant_ref", "ref:tenant-b"),)),
    ):
        assert intake_root_digest(intake) != intake_root_digest(
            replace(intake, **{field: value})
        )


def test_valid_lifecycle_transition_chain() -> None:
    boundary = IncidentLifecycleBoundary()
    record = boundary.open(_intake())

    for state in (
        IncidentLifecycleState.ACKNOWLEDGED,
        IncidentLifecycleState.INVESTIGATING,
        IncidentLifecycleState.CONTAINED,
        IncidentLifecycleState.RESOLVED,
        IncidentLifecycleState.CLOSED,
    ):
        record = boundary.transition(record, state)

    assert record.state is IncidentLifecycleState.CLOSED
    assert tuple(item.sequence for item in record.transitions) == (1, 2, 3, 4, 5)
    assert record.transitions[0].previous_transition_sha256 == ZERO_SHA256
    assert all(
        current.previous_transition_sha256 == previous.transition_sha256
        for previous, current in zip(record.transitions, record.transitions[1:])
    )
    assert all(
        item.intake_root_sha256 == record.intake_root_sha256
        for item in record.transitions
    )


def test_investigation_may_resolve_without_containment() -> None:
    boundary = IncidentLifecycleBoundary()
    record = boundary.open(_intake())
    record = boundary.transition(record, IncidentLifecycleState.ACKNOWLEDGED)
    record = boundary.transition(record, IncidentLifecycleState.INVESTIGATING)

    assert boundary.transition(record, IncidentLifecycleState.RESOLVED).state is IncidentLifecycleState.RESOLVED


@pytest.mark.parametrize("target", [
    IncidentLifecycleState.INVESTIGATING,
    IncidentLifecycleState.CONTAINED,
    IncidentLifecycleState.RESOLVED,
    IncidentLifecycleState.CLOSED,
])
def test_invalid_transition_from_open_is_rejected(target) -> None:
    with pytest.raises(ValueError, match="INCIDENT_LIFECYCLE_TRANSITION_INVALID"):
        IncidentLifecycleBoundary().transition(
            IncidentLifecycleBoundary().open(_intake()), target
        )


def test_transition_replay_is_idempotent() -> None:
    boundary = IncidentLifecycleBoundary()
    acknowledged = boundary.transition(
        boundary.open(_intake()), IncidentLifecycleState.ACKNOWLEDGED
    )

    replay = boundary.transition(acknowledged, IncidentLifecycleState.ACKNOWLEDGED)

    assert replay is acknowledged
    assert len(replay.transitions) == 1


def test_transition_digest_is_deterministic_and_incident_bound() -> None:
    arguments = {
        "incident_id": "incident-001",
        "intake_root_sha256": intake_root_digest(_intake()),
        "sequence": 1,
        "from_state": IncidentLifecycleState.OPEN,
        "to_state": IncidentLifecycleState.ACKNOWLEDGED,
        "previous_transition_sha256": ZERO_SHA256,
    }

    assert transition_digest(**arguments) == transition_digest(**arguments)
    assert transition_digest(**arguments) != transition_digest(
        **{**arguments, "incident_id": "incident-002"}
    )
    assert transition_digest(**arguments) != transition_digest(
        **{**arguments, "intake_root_sha256": "f" * 64}
    )


def test_modified_intake_is_rejected() -> None:
    boundary = IncidentLifecycleBoundary()
    record = boundary.open(_intake())

    with pytest.raises(ValueError, match="INCIDENT_LIFECYCLE_INTAKE_ROOT_INVALID"):
        boundary.transition(
            replace(record, intake=replace(record.intake, tenant_ref="ref:tenant-b")),
            IncidentLifecycleState.ACKNOWLEDGED,
        )


def test_lifecycle_fork_is_rejected() -> None:
    boundary = IncidentLifecycleBoundary()
    investigating = boundary.open(_intake())
    investigating = boundary.transition(
        investigating, IncidentLifecycleState.ACKNOWLEDGED
    )
    investigating = boundary.transition(
        investigating, IncidentLifecycleState.INVESTIGATING
    )
    boundary.transition(investigating, IncidentLifecycleState.CONTAINED)

    with pytest.raises(ValueError, match="INCIDENT_LIFECYCLE_FORK_INVALID"):
        boundary.transition(investigating, IncidentLifecycleState.RESOLVED)


def test_replay_with_identical_chain_is_accepted() -> None:
    boundary = IncidentLifecycleBoundary()
    acknowledged = boundary.transition(
        boundary.open(_intake()), IncidentLifecycleState.ACKNOWLEDGED
    )
    replay_record = replace(acknowledged, transitions=tuple(acknowledged.transitions))

    assert boundary.transition(
        replay_record, IncidentLifecycleState.ACKNOWLEDGED
    ) is replay_record


def test_replay_with_altered_valid_chain_is_rejected() -> None:
    boundary = IncidentLifecycleBoundary()
    investigating = boundary.open(_intake())
    investigating = boundary.transition(
        investigating, IncidentLifecycleState.ACKNOWLEDGED
    )
    investigating = boundary.transition(
        investigating, IncidentLifecycleState.INVESTIGATING
    )
    contained = boundary.transition(
        investigating, IncidentLifecycleState.CONTAINED
    )

    alternate = IncidentLifecycleBoundary().transition(
        investigating, IncidentLifecycleState.RESOLVED
    )
    with pytest.raises(ValueError, match="INCIDENT_LIFECYCLE_FORK_INVALID"):
        boundary.transition(alternate, IncidentLifecycleState.CLOSED)

    assert contained.state is IncidentLifecycleState.CONTAINED


def test_tampered_transition_chain_is_rejected() -> None:
    boundary = IncidentLifecycleBoundary()
    record = boundary.transition(
        boundary.open(_intake()), IncidentLifecycleState.ACKNOWLEDGED
    )
    tampered_item = replace(record.transitions[0], transition_sha256="0" * 64)

    with pytest.raises(ValueError, match="INCIDENT_LIFECYCLE_CHAIN_INVALID"):
        boundary.transition(
            replace(record, transitions=(tampered_item,)),
            IncidentLifecycleState.INVESTIGATING,
        )


def test_closed_incident_cannot_transition() -> None:
    boundary = IncidentLifecycleBoundary()
    record = boundary.open(_intake())
    for state in (
        IncidentLifecycleState.ACKNOWLEDGED,
        IncidentLifecycleState.INVESTIGATING,
        IncidentLifecycleState.RESOLVED,
        IncidentLifecycleState.CLOSED,
    ):
        record = boundary.transition(record, state)

    with pytest.raises(ValueError, match="INCIDENT_LIFECYCLE_TRANSITION_INVALID"):
        boundary.transition(record, IncidentLifecycleState.OPEN)


def test_lifecycle_output_is_immutable() -> None:
    record = IncidentLifecycleBoundary().open(_intake())

    with pytest.raises(FrozenInstanceError):
        record.state = IncidentLifecycleState.CLOSED


def test_open_rejects_non_intake_record() -> None:
    with pytest.raises(TypeError, match="INCIDENT_INTAKE_RECORD_REQUIRED"):
        IncidentLifecycleBoundary().open(object())
