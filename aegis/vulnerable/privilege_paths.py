from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True)
class VulnerablePrivilegePathReport:
    identity_graph_id: str
    accepted: bool
    identity_complete: bool
    declared_exposed_path_count: int
    declared_max_risk_score: int

class VulnerablePrivilegePathReporter:
    """Deliberately unsafe baseline that trusts caller-supplied identity/risk summaries."""
    def evaluate(self, *, identity_graph_id: str, identity_complete: bool, declared_exposed_path_count: int, declared_max_risk_score: int) -> VulnerablePrivilegePathReport:
        accepted = bool(identity_graph_id) and identity_complete and declared_exposed_path_count >= 0 and declared_max_risk_score >= 0
        return VulnerablePrivilegePathReport(identity_graph_id, accepted, identity_complete, declared_exposed_path_count, declared_max_risk_score)
