from dataclasses import FrozenInstanceError, replace

import pytest

from aegis.detection.intelligence_bridge import DetectionIntelligenceBridge
from aegis.detection.security_analytics import (
    EVENT_SCHEMA,
    POLICY_VERSION,
    DetectionDenied,
    SecurityEvent,
)


def _event() -> SecurityEvent:
    return SecurityEvent.from_dict({
        "schema_version": EVENT_SCHEMA,
        "event_id": "event-001",
        "event_time": 1_700_000_000,
        "source_id": "application-agent",
        "source_kind": "APPLICATION",
        "event_type": "HIGH_IMPACT_TOOL_DENIED",
        "category": "application_agent",
        "action": "TOOL_EXECUTION",
        "outcome": "DENY",
        "severity": "high",
        "reason_code": "POLICY_DENIED",
        "tenant_ref": "ref:tenant-a",
        "principal_ref": "ref:principal-a",
        "workload_ref": "ref:workload-a",
        "namespace_ref": "ref:namespace-a",
        "resource_ref": "ref:resource-a",
        "request_ref": "ref:request-a",
        "session_ref": "ref:session-a",
        "trace_ref": "ref:trace-a",
        "policy_version": POLICY_VERSION,
        "sequence": 1,
        "provenance_classification": "DETERMINISTIC_FIXTURE",
        "attributes": {},
    })


def test_build_context_from_security_event() -> None:
    context = DetectionIntelligenceBridge().build_context(_event())

    assert context.event_id == "event-001"
    assert context.event_time == 1_700_000_000
    assert context.source_id == "application-agent"
    assert context.source_kind == "APPLICATION"
    assert context.event_type == "HIGH_IMPACT_TOOL_DENIED"
    assert context.action == "TOOL_EXECUTION"
    assert context.severity == "high"
    assert context.outcome == "DENY"
    assert context.reason_code == "POLICY_DENIED"
    assert context.sequence == 1


def test_build_context_rejects_missing_required_fields() -> None:
    event = replace(_event(), event_id="")

    with pytest.raises(DetectionDenied, match="EVENT_IDENTITY_INVALID"):
        DetectionIntelligenceBridge().build_context(event)


def test_build_context_preserves_evidence_references() -> None:
    context = DetectionIntelligenceBridge().build_context(_event())

    assert dict(context.evidence_references) == {
        "tenant_ref": "ref:tenant-a",
        "principal_ref": "ref:principal-a",
        "workload_ref": "ref:workload-a",
        "namespace_ref": "ref:namespace-a",
        "resource_ref": "ref:resource-a",
        "request_ref": "ref:request-a",
        "session_ref": "ref:session-a",
        "trace_ref": "ref:trace-a",
    }


def test_build_context_is_deterministic() -> None:
    bridge = DetectionIntelligenceBridge()
    event = _event()

    assert bridge.build_context(event) == bridge.build_context(event)


def test_build_context_is_immutable() -> None:
    context = DetectionIntelligenceBridge().build_context(_event())

    with pytest.raises(FrozenInstanceError):
        context.severity = "low"
