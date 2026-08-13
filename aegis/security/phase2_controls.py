from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class DeploymentStatus(StrEnum):
    DEFAULT_API = "default_api"
    PARTIAL_DEFAULT_API = "partial_default_api"
    LAB_ONLY = "lab_only"


@dataclass(frozen=True)
class Phase2Control:
    milestone: str
    threat_model: str
    eval_module: str
    deployment_status: DeploymentStatus
    runtime_evidence: tuple[str, ...] = ()
    phase3_gaps: tuple[str, ...] = ()

    @property
    def eval_command(self) -> str:
        return f"python -m {self.eval_module}"


PHASE3_GAPS = {
    "P3-G04": "Use the P2-D credential broker for any future downstream asset adapter.",
    "P3-G05": "If durable memory is added to the API, preserve the P2-F data-not-authority rule.",
    "P3-G06": "Replace local checkpoint, witness, and signing-key abstractions before production trust claims.",
}


_P3A_RUNTIME = ("aegis/effects/default_high_impact.py", "apps/api/dependencies.py")
_P3C_NON_DEFAULT_RUNTIME = (
    "aegis/security/default_surfaces.py",
    "apps/api/dependencies.py",
    "apps/api/main.py",
)


PHASE2_CONTROLS: tuple[Phase2Control, ...] = (
    Phase2Control("P2-A", "docs/threat-model/p2a-tenant-boundary.md", "evals.p2a_tenant_boundary", DeploymentStatus.DEFAULT_API, ("apps/api/main.py", "aegis/rag/store.py")),
    Phase2Control("P2-B", "docs/threat-model/p2b-indirect-prompt-injection.md", "evals.p2b_indirect_prompt_injection", DeploymentStatus.DEFAULT_API, ("aegis/rag/answering.py", "aegis/policy/tool_capabilities.py")),
    Phase2Control("P2-C", "docs/threat-model/p2c-mcp-tool-poisoning.md", "evals.p2c_mcp_tool_poisoning", DeploymentStatus.DEFAULT_API, ("aegis/mcp_gateway/gateway.py", "aegis/mcp_gateway/server.py")),
    Phase2Control("P2-D", "docs/threat-model/p2d-token-passthrough.md", "evals.p2d_token_passthrough", DeploymentStatus.LAB_ONLY, phase3_gaps=("P3-G04",)),
    Phase2Control("P2-E", "docs/threat-model/p2e-ssrf-redirects.md", "evals.p2e_ssrf_redirects", DeploymentStatus.LAB_ONLY, _P3C_NON_DEFAULT_RUNTIME),
    Phase2Control("P2-F", "docs/threat-model/p2f-durable-memory-poisoning.md", "evals.p2f_durable_memory_poisoning", DeploymentStatus.LAB_ONLY, phase3_gaps=("P3-G05",)),
    Phase2Control("P2-G", "docs/threat-model/p2g-resource-exhaustion.md", "evals.p2g_resource_exhaustion", DeploymentStatus.DEFAULT_API, ("aegis/agent/default_budgeted_runner.py", "apps/api/dependencies.py", "apps/api/main.py")),
    Phase2Control("P2-H", "docs/threat-model/p2h-telemetry-redaction.md", "evals.p2h_telemetry_leakage", DeploymentStatus.DEFAULT_API, ("aegis/observability/security_events.py", "apps/api/dependencies.py")),
    Phase2Control("P2-I", "docs/threat-model/p2i-malicious-artifacts.md", "evals.p2i_artifact_handling", DeploymentStatus.LAB_ONLY, _P3C_NON_DEFAULT_RUNTIME),
    Phase2Control("P2-J", "docs/threat-model/p2j-browser-prompt-injection.md", "evals.p2j_browser_prompt_injection", DeploymentStatus.LAB_ONLY, _P3C_NON_DEFAULT_RUNTIME),
    Phase2Control("P2-K", "docs/threat-model/p2k-durable-approval-workflow.md", "evals.p2k_durable_approval_workflow", DeploymentStatus.DEFAULT_API, ("aegis/approvals/durable.py", "aegis/agent/graph.py", "apps/api/dependencies.py")),
    Phase2Control("P2-L", "docs/threat-model/p2l-transactional-outbox.md", "evals.p2l_transactional_outbox", DeploymentStatus.DEFAULT_API, ("aegis/effects/durable.py", "apps/api/dependencies.py")),
    Phase2Control("P2-M", "docs/threat-model/p2m-execution-time-authorization.md", "evals.p2m_execution_time_authorization", DeploymentStatus.DEFAULT_API, ("aegis/effects/revalidation.py", "apps/api/dependencies.py")),
    Phase2Control("P2-N", "docs/threat-model/p2n-authorization-freshness.md", "evals.p2n_authorization_freshness", DeploymentStatus.DEFAULT_API, _P3A_RUNTIME),
    Phase2Control("P2-O", "docs/threat-model/p2o-authorization-provenance.md", "evals.p2o_authorization_provenance", DeploymentStatus.DEFAULT_API, _P3A_RUNTIME, ("P3-G06",)),
    Phase2Control("P2-P", "docs/threat-model/p2p-rollback-resistant-trust-anchor.md", "evals.p2p_rollback_resistant_anchor", DeploymentStatus.DEFAULT_API, _P3A_RUNTIME, ("P3-G06",)),
    Phase2Control("P2-Q", "docs/threat-model/p2q-control-plane-recovery.md", "evals.p2q_control_plane_recovery", DeploymentStatus.DEFAULT_API, _P3A_RUNTIME),
    Phase2Control("P2-R", "docs/threat-model/p2r-protected-recovery-checkpoint.md", "evals.p2r_protected_checkpoint", DeploymentStatus.DEFAULT_API, _P3A_RUNTIME, ("P3-G06",)),
    Phase2Control("P2-S", "docs/threat-model/p2s-checkpoint-authenticity.md", "evals.p2s_checkpoint_authenticity", DeploymentStatus.DEFAULT_API, _P3A_RUNTIME, ("P3-G06",)),
)


def expected_phase2_milestones() -> tuple[str, ...]:
    return tuple(f"P2-{chr(code)}" for code in range(ord("A"), ord("S") + 1))
