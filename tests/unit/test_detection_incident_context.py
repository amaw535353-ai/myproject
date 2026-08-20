from dataclasses import FrozenInstanceError, replace

import pytest

from aegis.detection.incident_context import DetectionIncidentContextBuilder
from aegis.detection.intelligence_bridge import DetectionIntelligenceContext


def _context(
    event_id: str,
    *,
    tenant: str = "ref:tenant-a",
    workload: str = "ref:workload-a",
    severity: str = "high",
    category: str = "application_agent",
) -> DetectionIntelligenceContext:
    return DetectionIntelligenceContext(
        event_id=event_id,
        event_time=1_700_000_000,
        source_id="application-agent",
        source_kind="APPLICATION",
        event_type="HIGH_IMPACT_TOOL_DENIED",
        category=category,
        action="TOOL_EXECUTION",
        outcome="DENY",
        severity=severity,
        reason_code="POLICY_DENIED",
        sequence=1,
        evidence_references=(
            ("tenant_ref", tenant),
            ("workload_ref", workload),
            ("request_ref", f"ref:{event_id}"),
        ),
    )


def test_correlates_same_tenant_and_workload() -> None:
    contexts = DetectionIncidentContextBuilder().build_contexts((
        _context("event-002", category="identity_iam"),
        _context("event-001"),
    ))

    assert len(contexts) == 1
    assert contexts[0].tenant_ref == "ref:tenant-a"
    assert contexts[0].workload_ref == "ref:workload-a"
    assert contexts[0].contributing_event_ids == ("event-001", "event-002")
    assert contexts[0].categories == ("application_agent", "identity_iam")
    assert ("request_ref", "ref:event-001") in contexts[0].evidence_references
    assert ("request_ref", "ref:event-002") in contexts[0].evidence_references


def test_different_tenants_never_correlate() -> None:
    contexts = DetectionIncidentContextBuilder().build_contexts((
        _context("event-001"),
        _context("event-002", tenant="ref:tenant-b"),
    ))

    assert len(contexts) == 2
    assert {context.tenant_ref for context in contexts} == {
        "ref:tenant-a",
        "ref:tenant-b",
    }
    assert all(len(context.contributing_event_ids) == 1 for context in contexts)


def test_different_workloads_do_not_correlate() -> None:
    contexts = DetectionIncidentContextBuilder().build_contexts((
        _context("event-001"),
        _context("event-002", workload="ref:workload-b"),
    ))

    assert len(contexts) == 2
    assert {context.workload_ref for context in contexts} == {
        "ref:workload-a",
        "ref:workload-b",
    }


def test_conflicting_tenant_references_are_rejected() -> None:
    context = _context("event-001")
    ambiguous = replace(
        context,
        evidence_references=context.evidence_references + (
            ("tenant_ref", "ref:tenant-b"),
        ),
    )

    with pytest.raises(ValueError, match="CORRELATION_CONTEXT_REQUIRED"):
        DetectionIncidentContextBuilder().build_contexts((ambiguous,))


def test_conflicting_workload_references_are_rejected() -> None:
    context = _context("event-001")
    ambiguous = replace(
        context,
        evidence_references=context.evidence_references + (
            ("workload_ref", "ref:workload-b"),
        ),
    )

    with pytest.raises(ValueError, match="CORRELATION_CONTEXT_REQUIRED"):
        DetectionIncidentContextBuilder().build_contexts((ambiguous,))


@pytest.mark.parametrize("missing", ["tenant_ref", "workload_ref"])
def test_missing_correlation_references_are_rejected(missing: str) -> None:
    context = _context("event-001")
    incomplete = replace(
        context,
        evidence_references=tuple(
            reference
            for reference in context.evidence_references
            if reference[0] != missing
        ),
    )

    with pytest.raises(ValueError, match="CORRELATION_CONTEXT_REQUIRED"):
        DetectionIncidentContextBuilder().build_contexts((incomplete,))


def test_duplicate_event_ids_do_not_duplicate_output() -> None:
    context = _context("event-001")

    correlated = DetectionIncidentContextBuilder().build_contexts((context, context))

    assert correlated[0].contributing_event_ids == ("event-001",)
    assert correlated[0].evidence_references.count(
        ("request_ref", "ref:event-001")
    ) == 1


def test_conflicting_duplicate_event_ids_are_rejected() -> None:
    context = _context("event-001")

    with pytest.raises(ValueError, match="CONFLICTING_EVENT_ID"):
        DetectionIncidentContextBuilder().build_contexts((
            context,
            replace(context, severity="critical"),
        ))


def test_input_order_does_not_change_aggregation() -> None:
    first = _context("event-001")
    second = _context("event-002", severity="medium")
    builder = DetectionIncidentContextBuilder()

    assert builder.build_contexts((first, second)) == builder.build_contexts((second, first))


def test_highest_severity_wins() -> None:
    correlated = DetectionIncidentContextBuilder().build_contexts((
        _context("event-001", severity="low"),
        _context("event-002", severity="critical"),
        _context("event-003", severity="high"),
    ))

    assert correlated[0].severities == ("low", "high", "critical")
    assert correlated[0].highest_severity == "critical"


def test_output_is_deterministic() -> None:
    contexts = (
        _context("event-003", tenant="ref:tenant-b"),
        _context("event-002", severity="medium"),
        _context("event-001"),
    )
    builder = DetectionIncidentContextBuilder()

    first = builder.build_contexts(contexts)
    second = builder.build_contexts(tuple(reversed(contexts)))

    assert first == second
    assert first[0].tenant_ref == "ref:tenant-a"


def test_output_is_immutable() -> None:
    correlated = DetectionIncidentContextBuilder().build_contexts((
        _context("event-001"),
    ))

    with pytest.raises(FrozenInstanceError):
        correlated[0].highest_severity = "low"
