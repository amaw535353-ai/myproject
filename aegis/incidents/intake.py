from __future__ import annotations

import hashlib
import json

from aegis.detection.incident_context import CorrelatedDetectionContext

from .types import IncidentIntakeRecord


_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _incident_id(tenant_ref: str, workload_ref: str) -> str:
    material = json.dumps(
        {"tenant_ref": tenant_ref, "workload_ref": workload_ref},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "incident-" + hashlib.sha256(material).hexdigest()[:32]


def _validate(context: CorrelatedDetectionContext) -> None:
    if not isinstance(context, CorrelatedDetectionContext):
        raise TypeError("CORRELATED_DETECTION_CONTEXT_REQUIRED")
    if (
        not context.tenant_ref
        or not context.workload_ref
        or not context.contributing_event_ids
        or not context.evidence_references
        or not context.severities
        or not context.categories
        or context.highest_severity not in _SEVERITY_RANK
        or any(severity not in _SEVERITY_RANK for severity in context.severities)
    ):
        raise ValueError("CORRELATED_DETECTION_CONTEXT_INVALID")
    if (
        len(context.contributing_event_ids) != len(set(context.contributing_event_ids))
        or len(context.evidence_references) != len(set(context.evidence_references))
        or len(context.severities) != len(set(context.severities))
        or len(context.categories) != len(set(context.categories))
    ):
        raise ValueError("CORRELATED_DETECTION_CONTEXT_DUPLICATE")

    tenant_refs = tuple(
        value for name, value in context.evidence_references if name == "tenant_ref"
    )
    workload_refs = tuple(
        value for name, value in context.evidence_references if name == "workload_ref"
    )
    if tenant_refs != (context.tenant_ref,) or workload_refs != (context.workload_ref,):
        raise ValueError("INCIDENT_SCOPE_MISMATCH")
    expected_highest = max(context.severities, key=_SEVERITY_RANK.__getitem__)
    if context.highest_severity != expected_highest:
        raise ValueError("INCIDENT_SEVERITY_MISMATCH")


class IncidentIntakeBoundary:
    """Create incident intake records without taking response actions."""

    def intake(
        self,
        contexts: tuple[CorrelatedDetectionContext, ...],
    ) -> tuple[IncidentIntakeRecord, ...]:
        if not contexts:
            raise ValueError("CORRELATED_DETECTION_CONTEXTS_REQUIRED")

        grouped: dict[tuple[str, str], list[CorrelatedDetectionContext]] = {}
        event_scope: dict[str, tuple[str, str]] = {}
        for context in contexts:
            _validate(context)
            scope = (context.tenant_ref, context.workload_ref)
            for event_id in context.contributing_event_ids:
                prior_scope = event_scope.get(event_id)
                if prior_scope is not None and prior_scope != scope:
                    raise ValueError("CROSS_TENANT_EVENT_CONFLICT")
                event_scope[event_id] = scope
            if context not in grouped.setdefault(scope, []):
                grouped[scope].append(context)

        incidents = []
        for (tenant_ref, workload_ref), members in sorted(grouped.items()):
            severities = tuple(sorted(
                {severity for member in members for severity in member.severities},
                key=lambda severity: (_SEVERITY_RANK[severity], severity),
            ))
            incidents.append(IncidentIntakeRecord(
                incident_id=_incident_id(tenant_ref, workload_ref),
                tenant_ref=tenant_ref,
                workload_ref=workload_ref,
                contributing_event_ids=tuple(sorted({
                    event_id
                    for member in members
                    for event_id in member.contributing_event_ids
                })),
                evidence_references=tuple(sorted({
                    reference
                    for member in members
                    for reference in member.evidence_references
                })),
                severities=severities,
                highest_severity=severities[-1],
                categories=tuple(sorted({
                    category for member in members for category in member.categories
                })),
            ))
        return tuple(incidents)

    def create_incidents(
        self,
        contexts: tuple[CorrelatedDetectionContext, ...],
    ) -> tuple[IncidentIntakeRecord, ...]:
        """Compatibility name for callers expressing intake as creation."""
        return self.intake(contexts)
