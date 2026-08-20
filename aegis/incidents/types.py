from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IncidentIntakeRecord:
    """Immutable incident identity and the detection evidence that opened it."""

    incident_id: str
    tenant_ref: str
    workload_ref: str
    contributing_event_ids: tuple[str, ...]
    evidence_references: tuple[tuple[str, str], ...]
    severities: tuple[str, ...]
    highest_severity: str
    categories: tuple[str, ...]
