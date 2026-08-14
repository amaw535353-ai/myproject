from __future__ import annotations

import hashlib
import json
from dataclasses import replace

from aegis.architecture.attack_paths import (
    ArchitectureAsset,
    ArchitectureFlow,
    ArchitectureManifest,
    AssetSensitivity,
    AssetType,
    FlowType,
    VerifiedAttackPathAssessment,
)
from aegis.architecture.privilege_paths import (
    Capability,
    CapabilitySensitivity,
    DelegationType,
    IdentityCapabilityManifest,
    IdentityPrincipal,
    IdentityPrivilegeCapabilityAnalyzer,
    PrivilegePathPolicy,
    PrivilegePathRejected,
    PrivilegePathRequest,
    PrivilegeScope,
    PrivilegeTier,
    PrincipalType,
    PrivilegeTransition,
    identity_capability_manifest_digest,
    privilege_path_identifier,
)
from aegis.assurance.posture_reporting import (
    ControlPostureAssessment,
    ControlStatus,
    PostureRating,
    VerifiedSecurityPosture,
)
from aegis.vulnerable.privilege_paths import VulnerablePrivilegePathReporter

EVALUATION_EPOCH = 1_800_010_000
MANIFEST_EPOCH = 1_800_009_500
P7A_EVIDENCE_SHA = hashlib.sha256(b"p7b-p7a-assessment-evidence").hexdigest()
POSTURE_EVIDENCE_SHA = hashlib.sha256(b"p7b-p6d-posture-evidence").hexdigest()
CONTROL_CATALOG_SHA = hashlib.sha256(b"p7b-control-catalog").hexdigest()

CTRL_TENANT_AUTHN = "CTRL-TENANT-AUTHN"
CTRL_SERVER_PRINCIPAL = "CTRL-SERVER-PRINCIPAL"
CTRL_TOOL_AUTH = "CTRL-TOOL-AUTH"
CTRL_CREDENTIAL_BROKER = "CTRL-CREDENTIAL-BROKER"
CTRL_LEAST_PRIVILEGE = "CTRL-LEAST-PRIVILEGE"
CTRL_MODEL_PROVENANCE = "CTRL-MODEL-PROVENANCE"
CTRL_RUNTIME_ISOLATION = "CTRL-RUNTIME-ISOLATION"
CTRL_INFERENCE_PRIVACY = "CTRL-INFERENCE-PRIVACY"
CTRL_TELEMETRY_BOUNDARY = "CTRL-TELEMETRY-BOUNDARY"

ALL_CONTROLS = (
    CTRL_TENANT_AUTHN,
    CTRL_SERVER_PRINCIPAL,
    CTRL_TOOL_AUTH,
    CTRL_CREDENTIAL_BROKER,
    CTRL_LEAST_PRIVILEGE,
    CTRL_MODEL_PROVENANCE,
    CTRL_RUNTIME_ISOLATION,
    CTRL_INFERENCE_PRIVACY,
    CTRL_TELEMETRY_BOUNDARY,
)

CAP_AUTH_SESSION = "cap-authenticated-session"
CAP_INVOKE_AGENT = "cap-invoke-agent"
CAP_INVOKE_TOOL = "cap-invoke-privileged-tool"
CAP_READ_SECRET = "cap-read-synthetic-secret"
CAP_PUBLISH_MODEL = "cap-publish-model-release"
CAP_LOAD_MODEL = "cap-load-model-release"
CAP_EXECUTE_INFERENCE = "cap-execute-inference"
CAP_WRITE_TELEMETRY = "cap-write-security-telemetry"


def _architecture_digest(manifest: ArchitectureManifest) -> str:
    doc = {
        "architecture_id": manifest.architecture_id,
        "assets": [
            {
                "asset_id": a.asset_id,
                "asset_type": a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type),
                "description": a.description,
                "owner_id": a.owner_id,
                "sensitivity": a.sensitivity.value if hasattr(a.sensitivity, "value") else str(a.sensitivity),
                "trust_zone": a.trust_zone,
            }
            for a in sorted(manifest.assets, key=lambda x: x.asset_id)
        ],
        "created_at_epoch": manifest.created_at_epoch,
        "flows": [
            {
                "description": f.description,
                "flow_id": f.flow_id,
                "flow_type": f.flow_type.value if hasattr(f.flow_type, "value") else str(f.flow_type),
                "owner_id": f.owner_id,
                "required_control_ids": sorted(f.required_control_ids),
                "source_asset_id": f.source_asset_id,
                "target_asset_id": f.target_asset_id,
            }
            for f in sorted(manifest.flows, key=lambda x: x.flow_id)
        ],
        "schema_version": manifest.schema_version,
        "version": manifest.version,
    }
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _architecture() -> ArchitectureManifest:
    assets = (
        ArchitectureAsset("external-user", AssetType.EXTERNAL_ACTOR, "internet", "external", AssetSensitivity.LOW, "Untrusted external user."),
        ArchitectureAsset("api-gateway", AssetType.API_GATEWAY, "edge", "platform", AssetSensitivity.MEDIUM, "Authenticated API boundary."),
        ArchitectureAsset("agent-orchestrator", AssetType.AGENT_ORCHESTRATOR, "application", "platform", AssetSensitivity.HIGH, "Server-owned agent identity boundary."),
        ArchitectureAsset("tool-gateway", AssetType.TOOL_GATEWAY, "privileged-tools", "ai-security", AssetSensitivity.HIGH, "Typed privileged tool gateway."),
        ArchitectureAsset("secret-store", AssetType.SECRET_STORE, "secrets", "ai-security", AssetSensitivity.CRITICAL, "Synthetic secret broker boundary."),
        ArchitectureAsset("model-registry", AssetType.MODEL_REGISTRY, "model-supply-chain", "model-security", AssetSensitivity.HIGH, "Model release publisher/registry boundary."),
        ArchitectureAsset("model-runtime", AssetType.MODEL_RUNTIME, "inference", "model-security", AssetSensitivity.CRITICAL, "Model runtime identity boundary."),
        ArchitectureAsset("security-telemetry", AssetType.SECURITY_TELEMETRY, "security", "ai-security", AssetSensitivity.HIGH, "Security telemetry sink."),
    )
    flows = (
        ArchitectureFlow("flow-user-api", "external-user", "api-gateway", FlowType.USER_INPUT, "platform", (CTRL_TENANT_AUTHN,), "User obtains authenticated tenant session."),
        ArchitectureFlow("flow-api-agent", "api-gateway", "agent-orchestrator", FlowType.AGENT_CONTROL, "platform", (CTRL_SERVER_PRINCIPAL,), "Server injects authoritative principal into agent state."),
        ArchitectureFlow("flow-agent-tool", "agent-orchestrator", "tool-gateway", FlowType.TOOL_CALL, "ai-security", (CTRL_TOOL_AUTH,), "Agent requests a typed privileged tool."),
        ArchitectureFlow("flow-tool-secret", "tool-gateway", "secret-store", FlowType.SECRET_ACCESS, "ai-security", (CTRL_CREDENTIAL_BROKER, CTRL_LEAST_PRIVILEGE), "Tool gateway brokers scoped synthetic credentials."),
        ArchitectureFlow("flow-registry-runtime", "model-registry", "model-runtime", FlowType.MODEL_ACQUISITION, "model-security", (CTRL_MODEL_PROVENANCE, CTRL_RUNTIME_ISOLATION), "Verified model release admitted into runtime."),
        ArchitectureFlow("flow-agent-runtime", "agent-orchestrator", "model-runtime", FlowType.INFERENCE, "model-security", (CTRL_RUNTIME_ISOLATION, CTRL_INFERENCE_PRIVACY), "Agent invokes verified inference runtime."),
        ArchitectureFlow("flow-runtime-telemetry", "model-runtime", "security-telemetry", FlowType.SECURITY_TELEMETRY, "ai-security", (CTRL_TELEMETRY_BOUNDARY,), "Runtime delegates minimized security telemetry emission."),
    )
    return ArchitectureManifest("aegisdesk-ai-security-architecture", "7.2", MANIFEST_EPOCH, assets, flows)


def _capabilities() -> tuple[Capability, ...]:
    return (
        Capability(CAP_AUTH_SESSION, "api-gateway", "platform", CapabilitySensitivity.LOW, PrivilegeTier.TENANT, "Authenticated tenant session."),
        Capability(CAP_INVOKE_AGENT, "agent-orchestrator", "platform", CapabilitySensitivity.MEDIUM, PrivilegeTier.SERVICE, "Invoke server-owned agent."),
        Capability(CAP_INVOKE_TOOL, "tool-gateway", "ai-security", CapabilitySensitivity.HIGH, PrivilegeTier.PRIVILEGED, "Invoke privileged typed tool."),
        Capability(CAP_READ_SECRET, "secret-store", "ai-security", CapabilitySensitivity.CRITICAL, PrivilegeTier.SECURITY, "Read a synthetic scoped secret."),
        Capability(CAP_PUBLISH_MODEL, "model-registry", "model-security", CapabilitySensitivity.HIGH, PrivilegeTier.SERVICE, "Publish a model release candidate."),
        Capability(CAP_LOAD_MODEL, "model-runtime", "model-security", CapabilitySensitivity.CRITICAL, PrivilegeTier.PRIVILEGED, "Admit a model release into runtime."),
        Capability(CAP_EXECUTE_INFERENCE, "model-runtime", "model-security", CapabilitySensitivity.HIGH, PrivilegeTier.PRIVILEGED, "Execute verified model inference."),
        Capability(CAP_WRITE_TELEMETRY, "security-telemetry", "ai-security", CapabilitySensitivity.HIGH, PrivilegeTier.SECURITY, "Emit security telemetry evidence."),
    )
