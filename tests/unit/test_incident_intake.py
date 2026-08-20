from dataclasses import FrozenInstanceError, replace

import pytest

from aegis.detection.incident_context import CorrelatedDetectionContext
from aegis.incidents.intake import IncidentIntakeBoundary


def _context(
    *event_ids: str,
    tenant: str = "ref:tenant-a",
    workload: str = "ref:workload-a",
    severity: str = "high",
) -> CorrelatedDetectionContext:
    return CorrelatedDetectionContext(
        tenant_ref=tenant,
        workload_ref=workload,
        contributing_event_ids=tuple(event_ids),
        evidence_references=(
            ("request_ref", "ref:request-a"),
            ("tenant_ref", tenant),
            ("workload_ref", workload),
        ),
        severities=(severity,),
        highest_severity=severity,
        categories=("application_agent",),
    )


def test_intake_preserves_events_and_evidence() -> None:
    incident = IncidentIntakeBoundary().intake((_context("event-002", "event-001"),))[0]

    assert incident.contributing_event_ids == ("event-001", "event-002")
    assert incident.evidence_references == _context("event-001").evidence_references


def test_incident_id_is_deterministic_and_input_order_independent() -> None:
    boundary = IncidentIntakeBoundary()
    first = _context("event-001")
    second = replace(first, contributing_event_ids=("event-002",))

    assert boundary.intake((first, second)) == boundary.intake((second, first))


def test_highest_severity_wins_when_scope_is_merged() -> None:
    low = _context("event-001", severity="low")
    critical = _context("event-002", severity="critical")

    incident = IncidentIntakeBoundary().intake((low, critical))[0]

    assert incident.severities == ("low", "critical")
    assert incident.highest_severity == "critical"


def test_cross_tenant_contexts_create_isolated_incidents() -> None:
    incidents = IncidentIntakeBoundary().intake((
        _context("event-001"),
        _context("event-002", tenant="ref:tenant-b"),
    ))

    assert len(incidents) == 2
    assert len({incident.incident_id for incident in incidents}) == 2
    assert {incident.tenant_ref for incident in incidents} == {
        "ref:tenant-a", "ref:tenant-b",
    }


def test_same_event_cannot_cross_tenant_boundary() -> None:
    with pytest.raises(ValueError, match="CROSS_TENANT_EVENT_CONFLICT"):
        IncidentIntakeBoundary().intake((
            _context("event-001"),
            _context("event-001", tenant="ref:tenant-b"),
        ))


def test_duplicate_context_is_idempotent() -> None:
    context = _context("event-001")

    assert IncidentIntakeBoundary().intake((context, context)) == (
        IncidentIntakeBoundary().intake((context,))[0],
    )


def test_context_scope_must_match_preserved_evidence() -> None:
    context = _context("event-001")

    with pytest.raises(ValueError, match="INCIDENT_SCOPE_MISMATCH"):
        IncidentIntakeBoundary().intake((replace(context, tenant_ref="ref:tenant-b"),))


def test_output_is_immutable() -> None:
    incident = IncidentIntakeBoundary().intake((_context("event-001"),))[0]

    with pytest.raises(FrozenInstanceError):
        incident.highest_severity = "low"


def test_only_correlated_detection_context_is_accepted() -> None:
    with pytest.raises(TypeError, match="CORRELATED_DETECTION_CONTEXT_REQUIRED"):
        IncidentIntakeBoundary().intake((object(),))
