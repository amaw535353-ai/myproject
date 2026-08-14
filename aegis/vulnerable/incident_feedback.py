from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class VulnerableIncidentFeedbackResult:
    feedback_id: str
    accepted: bool
    incident_closed_loop: bool
    regression_coverage_added: bool
    caller_declared_status: str


class VulnerableIncidentFeedbackGate:
    """Deliberately unsafe baseline that trusts caller-declared feedback status."""

    def evaluate(
        self,
        *,
        feedback_id: str,
        caller_declared_status: str,
        incident_closed_loop: bool,
        regression_coverage_added: bool,
    ) -> VulnerableIncidentFeedbackResult:
        accepted = (
            bool(feedback_id)
            and caller_declared_status == "complete"
            and incident_closed_loop
            and regression_coverage_added
        )
        return VulnerableIncidentFeedbackResult(
            feedback_id=feedback_id,
            accepted=accepted,
            incident_closed_loop=incident_closed_loop,
            regression_coverage_added=regression_coverage_added,
            caller_declared_status=caller_declared_status,
        )
