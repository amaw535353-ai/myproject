from __future__ import annotations

import hashlib

from aegis.architecture.attack_paths import ArchitectureManifest, VerifiedAttackPathAssessment
from aegis.architecture.privilege_paths import (
    DelegationType, IdentityCapabilityManifest, IdentityPrincipal, PrivilegeScope, PrivilegeTier,
    PrincipalType, PrivilegeTransition, privilege_path_identifier,
)
from aegis.assurance.posture_reporting import (
    ControlPostureAssessment, ControlStatus, PostureRating, VerifiedSecurityPosture,
)
from .p7b_fixture_defs import *
from .p7b_fixture_defs import _architecture_digest, _capabilities

def _principals() -> tuple[IdentityPrincipal, ...]:
    return (
        IdentityPrincipal("external-user-principal", PrincipalType.EXTERNAL_USER, "external-user", "external", PrivilegeTier.UNTRUSTED, PrivilegeScope.PUBLIC, (), "Untrusted user-origin principal."),
        IdentityPrincipal("tenant-user-principal", PrincipalType.TENANT_USER, "api-gateway", "platform", PrivilegeTier.TENANT, PrivilegeScope.TENANT, (CAP_AUTH_SESSION,), "Authenticated tenant principal."),
        IdentityPrincipal("agent-service-principal", PrincipalType.SERVICE_IDENTITY, "agent-orchestrator", "platform", PrivilegeTier.SERVICE, PrivilegeScope.WORKLOAD, (CAP_INVOKE_AGENT,), "Server-owned agent service identity."),
        IdentityPrincipal("tool-service-principal", PrincipalType.TOOL_IDENTITY, "tool-gateway", "ai-security", PrivilegeTier.PRIVILEGED, PrivilegeScope.WORKLOAD, (CAP_INVOKE_TOOL,), "Privileged tool service identity."),
        IdentityPrincipal("secret-broker-principal", PrincipalType.SECURITY_IDENTITY, "secret-store", "ai-security", PrivilegeTier.SECURITY, PrivilegeScope.SECURITY, (CAP_READ_SECRET,), "Synthetic secret broker identity."),
        IdentityPrincipal("registry-publisher-principal", PrincipalType.MODEL_PUBLISHER, "model-registry", "model-security", PrivilegeTier.SERVICE, PrivilegeScope.WORKLOAD, (CAP_PUBLISH_MODEL,), "Modeled publisher/registry identity."),
        IdentityPrincipal("runtime-service-principal", PrincipalType.MODEL_RUNTIME, "model-runtime", "model-security", PrivilegeTier.PRIVILEGED, PrivilegeScope.WORKLOAD, (CAP_EXECUTE_INFERENCE,), "Verified model runtime identity."),
        IdentityPrincipal("telemetry-service-principal", PrincipalType.SECURITY_IDENTITY, "security-telemetry", "ai-security", PrivilegeTier.SECURITY, PrivilegeScope.SECURITY, (CAP_WRITE_TELEMETRY,), "Security telemetry service identity."),
    )


def _transitions() -> tuple[PrivilegeTransition, ...]:
    return (
        PrivilegeTransition("edge-user-tenant", "external-user-principal", "tenant-user-principal", DelegationType.AUTHENTICATED_SESSION, "platform", ("flow-user-api",), (CTRL_TENANT_AUTHN,), (CAP_AUTH_SESSION,), "Authenticate an external user into a tenant-bound session."),
        PrivilegeTransition("edge-tenant-agent", "tenant-user-principal", "agent-service-principal", DelegationType.SERVER_PRINCIPAL_INJECTION, "platform", ("flow-api-agent",), (CTRL_SERVER_PRINCIPAL,), (CAP_INVOKE_AGENT,), "Delegate request execution to server-owned agent identity."),
        PrivilegeTransition("edge-agent-tool", "agent-service-principal", "tool-service-principal", DelegationType.TOOL_AUTHORIZATION, "ai-security", ("flow-agent-tool",), (CTRL_TOOL_AUTH,), (CAP_INVOKE_TOOL,), "Authorize typed privileged tool invocation."),
        PrivilegeTransition("edge-tool-secret", "tool-service-principal", "secret-broker-principal", DelegationType.CREDENTIAL_BROKER, "ai-security", ("flow-tool-secret",), (CTRL_CREDENTIAL_BROKER, CTRL_LEAST_PRIVILEGE), (CAP_READ_SECRET,), "Broker least-privilege synthetic credential access."),
        PrivilegeTransition("edge-registry-runtime", "registry-publisher-principal", "runtime-service-principal", DelegationType.MODEL_RELEASE_ADMISSION, "model-security", ("flow-registry-runtime",), (CTRL_MODEL_PROVENANCE, CTRL_RUNTIME_ISOLATION), (CAP_LOAD_MODEL,), "Admit an immutable provenance-verified model release."),
        PrivilegeTransition("edge-agent-runtime", "agent-service-principal", "runtime-service-principal", DelegationType.RUNTIME_INVOCATION, "model-security", ("flow-agent-runtime",), (CTRL_RUNTIME_ISOLATION, CTRL_INFERENCE_PRIVACY), (CAP_EXECUTE_INFERENCE,), "Delegate inference to isolated model runtime."),
        PrivilegeTransition("edge-runtime-telemetry", "runtime-service-principal", "telemetry-service-principal", DelegationType.TELEMETRY_DELEGATION, "ai-security", ("flow-runtime-telemetry",), (CTRL_TELEMETRY_BOUNDARY,), (CAP_WRITE_TELEMETRY,), "Delegate minimized security telemetry emission."),
    )


def _identity_manifest(architecture_sha: str) -> IdentityCapabilityManifest:
    return IdentityCapabilityManifest(
        identity_graph_id="aegisdesk-identity-capability-graph",
        version="7.2",
        architecture_sha256=architecture_sha,
        created_at_epoch=MANIFEST_EPOCH,
        principals=_principals(),
        capabilities=_capabilities(),
        transitions=_transitions(),
    )


def _assessment(control_catalog_sha: str, posture_sha: str, architecture: ArchitectureManifest) -> VerifiedAttackPathAssessment:
    arch_sha = _architecture_digest(architecture)
    return VerifiedAttackPathAssessment(
        architecture_id=architecture.architecture_id,
        architecture_version=architecture.version,
        architecture_sha256=arch_sha,
        posture_evidence_sha256=posture_sha,
        control_catalog_sha256=control_catalog_sha,
        attacker_profile_id="identity-escalation-context",
        entry_asset_ids=("external-user", "model-registry"),
        target_asset_ids=("secret-store", "model-runtime"),
        topology_path_count=3,
        exposed_path_count=1,
        controlled_path_count=2,
        critical_exposed_path_count=1,
        max_exposed_risk_score=139,
        prioritized_exposed_path_ids=("p7a-placeholder",),
        paths=(),
        assessment_evidence_sha256=P7A_EVIDENCE_SHA,
    )


def _control_assessment(control_id: str, status: ControlStatus) -> ControlPostureAssessment:
    return ControlPostureAssessment(
        control_id=control_id,
        risk_domain="identity-privilege",
        severity="high",
        status=status,
        mapped_case_ids=(f"case-{control_id.lower()}",),
        exception_case_ids=(f"exception-{control_id.lower()}",) if status == ControlStatus.EXCEPTIONED else (),
        missing_case_ids=(f"missing-{control_id.lower()}",) if status == ControlStatus.NOT_EVALUATED else (),
        missing_boundaries=(),
        evidence_sha256=hashlib.sha256(f"assessment:{control_id}:{status.value}".encode()).hexdigest(),
    )


def _posture(tool_status: ControlStatus = ControlStatus.EXCEPTIONED) -> VerifiedSecurityPosture:
    assessments = tuple(
        _control_assessment(control_id, tool_status if control_id == CTRL_TOOL_AUTH else ControlStatus.SATISFIED)
        for control_id in ALL_CONTROLS
    )
    satisfied = tuple(sorted(a.control_id for a in assessments if a.status == ControlStatus.SATISFIED))
    exceptioned = tuple(sorted(a.control_id for a in assessments if a.status == ControlStatus.EXCEPTIONED))
    not_eval = tuple(sorted(a.control_id for a in assessments if a.status == ControlStatus.NOT_EVALUATED))
    return VerifiedSecurityPosture(
        candidate_release_id="aegisdesk-0.62.0",
        candidate_commit_sha=hashlib.sha256(b"p7b-candidate").hexdigest(),
        candidate_package_version="0.62.0",
        corpus_id="aegis-security-regressions",
        corpus_version="7.2",
        corpus_sha256=hashlib.sha256(b"p7b-corpus").hexdigest(),
        control_catalog_id="aegis-ai-security-controls",
        control_catalog_version="7.2",
        control_catalog_sha256=CONTROL_CATALOG_SHA,
        waiver_governance_evidence_sha256=hashlib.sha256(b"p7b-waiver").hexdigest(),
        corpus_evolution_evidence_sha256=hashlib.sha256(b"p7b-evolution").hexdigest(),
        overall_rating=PostureRating.GREEN if not exceptioned and not not_eval else PostureRating.AMBER,
        control_count=len(assessments),
        satisfied_control_ids=satisfied,
        exceptioned_control_ids=exceptioned,
        not_evaluated_control_ids=not_eval,
        assessments=assessments,
        posture_evidence_sha256=POSTURE_EVIDENCE_SHA,
    )


def _secret_path_id() -> str:
    return privilege_path_identifier(
        "external-user-principal",
        CAP_READ_SECRET,
        (
            "external-user-principal",
            "tenant-user-principal",
            "agent-service-principal",
            "tool-service-principal",
            "secret-broker-principal",
        ),
        ("edge-user-tenant", "edge-tenant-agent", "edge-agent-tool", "edge-tool-secret"),
    )
