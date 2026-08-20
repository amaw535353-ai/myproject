from __future__ import annotations

from dataclasses import dataclass

from aegis.detection.security_analytics import DetectionDenied, SecurityEvent


@dataclass(frozen=True)
class DetectionIntelligenceContext:
    event_id: str
    event_time: int
    source_id: str
    source_kind: str
    event_type: str
    category: str
    action: str
    outcome: str
    severity: str
    reason_code: str
    sequence: int
    evidence_references: tuple[tuple[str, str], ...]


class DetectionIntelligenceBridge:
    """Build an immutable intelligence projection from a validated event."""

    def build_context(self, event: SecurityEvent) -> DetectionIntelligenceContext:
        if not isinstance(event, SecurityEvent):
            raise DetectionDenied("SECURITY_EVENT_REQUIRED")
        event.validate()
        references = tuple(
            (name, getattr(event, name))
            for name in (
                "tenant_ref",
                "principal_ref",
                "workload_ref",
                "namespace_ref",
                "resource_ref",
                "request_ref",
                "session_ref",
                "trace_ref",
            )
        )
        return DetectionIntelligenceContext(
            event_id=event.event_id,
            event_time=event.event_time,
            source_id=event.source_id,
            source_kind=event.source_kind,
            event_type=event.event_type,
            category=event.category,
            action=event.action,
            outcome=event.outcome,
            severity=event.severity,
            reason_code=event.reason_code,
            sequence=event.sequence,
            evidence_references=references,
        )
