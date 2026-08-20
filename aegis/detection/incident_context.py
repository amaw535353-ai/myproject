from __future__ import annotations

from dataclasses import dataclass

from aegis.detection.intelligence_bridge import DetectionIntelligenceContext


_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class CorrelatedDetectionContext:
    tenant_ref: str
    workload_ref: str
    contributing_event_ids: tuple[str, ...]
    evidence_references: tuple[tuple[str, str], ...]
    severities: tuple[str, ...]
    highest_severity: str
    categories: tuple[str, ...]


class DetectionIncidentContextBuilder:
    """Correlate detection projections without taking response actions."""

    def build_contexts(
        self,
        contexts: tuple[DetectionIntelligenceContext, ...],
    ) -> tuple[CorrelatedDetectionContext, ...]:
        if not contexts:
            raise ValueError("DETECTION_CONTEXTS_REQUIRED")

        unique: dict[str, DetectionIntelligenceContext] = {}
        for context in contexts:
            if not isinstance(context, DetectionIntelligenceContext):
                raise TypeError("DETECTION_CONTEXT_REQUIRED")
            if not context.event_id or context.severity not in _SEVERITY_RANK:
                raise ValueError("DETECTION_CONTEXT_INVALID")
            existing = unique.get(context.event_id)
            if existing is not None and existing != context:
                raise ValueError("CONFLICTING_EVENT_ID")
            unique[context.event_id] = context

        grouped: dict[tuple[str, str], list[DetectionIntelligenceContext]] = {}
        for context in unique.values():
            tenant_refs = tuple(
                value
                for name, value in context.evidence_references
                if name == "tenant_ref"
            )
            workload_refs = tuple(
                value
                for name, value in context.evidence_references
                if name == "workload_ref"
            )
            if (
                len(tenant_refs) != 1
                or len(workload_refs) != 1
                or not tenant_refs[0]
                or not workload_refs[0]
            ):
                raise ValueError("CORRELATION_CONTEXT_REQUIRED")
            tenant_ref = tenant_refs[0]
            workload_ref = workload_refs[0]
            grouped.setdefault((tenant_ref, workload_ref), []).append(context)

        correlated = []
        for (tenant_ref, workload_ref), members in sorted(grouped.items()):
            members.sort(key=lambda context: context.event_id)
            severities = tuple(sorted(
                {context.severity for context in members},
                key=lambda severity: (_SEVERITY_RANK[severity], severity),
            ))
            correlated.append(CorrelatedDetectionContext(
                tenant_ref=tenant_ref,
                workload_ref=workload_ref,
                contributing_event_ids=tuple(context.event_id for context in members),
                evidence_references=tuple(sorted({
                    reference
                    for context in members
                    for reference in context.evidence_references
                })),
                severities=severities,
                highest_severity=severities[-1],
                categories=tuple(sorted({context.category for context in members})),
            ))
        return tuple(correlated)
