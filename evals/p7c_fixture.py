from __future__ import annotations

import hashlib
from dataclasses import replace

from aegis.architecture.attack_paths import (
    ArchitectureAsset,
    ArchitectureFlow,
    ArchitectureManifest,
    AssetSensitivity,
    AssetType,
    FlowType,
    VerifiedAttackPathAssessment,
    architecture_manifest_digest,
)
from aegis.architecture.data_manifest import data_flow_manifest_digest
from aegis.architecture.data_paths import _enumerate_paths
from aegis.architecture.data_types import (
    DataClassification,
    DataFlowEdge,
    DataFlowManifest,
    DataKind,
    DataObject,
    DataPathPolicy,
    DataPathRequest,
    DataTransform,
)
from aegis.architecture.privilege_types import VerifiedPrivilegeEscalationAssessment
from aegis.assurance.posture_reporting import (
    ControlPostureAssessment,
    ControlStatus,
    PostureRating,
    VerifiedSecurityPosture,
)
from aegis.assurance.regression import AssuranceSeverity


EVALUATION_EPOCH = 1_800_020_000
MANIFEST_EPOCH = 1_800_019_500
P7A_EVIDENCE_SHA = hashlib.sha256(b"p7c-p7a-assessment-evidence").hexdigest()
P7B_EVIDENCE_SHA = hashlib.sha256(b"p7c-p7b-assessment-evidence").hexdigest()
POSTURE_EVIDENCE_SHA = hashlib.sha256(b"p7c-p6d-posture-evidence").hexdigest()
CONTROL_CATALOG_SHA = hashlib.sha256(b"p7c-control-catalog").hexdigest()
IDENTITY_GRAPH_SHA = hashlib.sha256(b"p7c-identity-graph").hexdigest()

CTRL_TENANT_ISOLATION = "CTRL-TENANT-ISOLATION"
CTRL_RAG_FILTER = "CTRL-RAG-FILTER"
CTRL_TOOL_AUTH = "CTRL-TOOL-AUTH"
CTRL_CREDENTIAL_BROKER = "CTRL-CREDENTIAL-BROKER"
CTRL_LEAST_PRIVILEGE = "CTRL-LEAST-PRIVILEGE"
CTRL_INFERENCE_PRIVACY = "CTRL-INFERENCE-PRIVACY"
CTRL_OUTPUT_FILTER = "CTRL-OUTPUT-FILTER"
CTRL_TELEMETRY_MINIMIZATION = "CTRL-TELEMETRY-MINIMIZATION"

ALL_CONTROLS = (
    CTRL_TENANT_ISOLATION,
    CTRL_RAG_FILTER,
    CTRL_TOOL_AUTH,
    CTRL_CREDENTIAL_BROKER,
    CTRL_LEAST_PRIVILEGE,
    CTRL_INFERENCE_PRIVACY,
    CTRL_OUTPUT_FILTER,
    CTRL_TELEMETRY_MINIMIZATION,
)

DATA_TICKET = "tenant-a-ticket"
DATA_SECRET = "synthetic-platform-secret"
DATA_TELEMETRY = "runtime-security-telemetry"

EDGE_TICKET_RETRIEVER = "edge-ticket-vector-retriever"
EDGE_TICKET_AGENT = "edge-ticket-retriever-agent"
EDGE_TICKET_MODEL = "edge-ticket-agent-model"
EDGE_TICKET_USER = "edge-ticket-agent-user"
EDGE_SECRET_TOOL = "edge-secret-store-tool"
EDGE_SECRET_AGENT = "edge-secret-tool-agent"
EDGE_SECRET_USER = "edge-secret-agent-user"
EDGE_TELEMETRY_SECURITY = "edge-telemetry-runtime-security"


def _architecture() -> ArchitectureManifest:
    assets = (
        ArchitectureAsset("external-user", AssetType.EXTERNAL_ACTOR, "internet", "external", AssetSensitivity.LOW, "Untrusted response recipient."),
        ArchitectureAsset("api-gateway", AssetType.API_GATEWAY, "edge", "platform", AssetSensitivity.MEDIUM, "Tenant-authenticated API edge."),
        ArchitectureAsset("agent-orchestrator", AssetType.AGENT_ORCHESTRATOR, "application", "platform", AssetSensitivity.HIGH, "Server-owned agent orchestration."),
        ArchitectureAsset("retriever", AssetType.RETRIEVER, "retrieval", "platform", AssetSensitivity.HIGH, "Tenant-filtered retrieval boundary."),
        ArchitectureAsset("vector-store", AssetType.VECTOR_STORE, "data", "platform", AssetSensitivity.HIGH, "Synthetic multi-tenant vector data."),
        ArchitectureAsset("tool-gateway", AssetType.TOOL_GATEWAY, "privileged-tools", "ai-security", AssetSensitivity.HIGH, "Typed privileged tool boundary."),
        ArchitectureAsset("secret-store", AssetType.SECRET_STORE, "secrets", "ai-security", AssetSensitivity.CRITICAL, "Synthetic secret source."),
        ArchitectureAsset("model-runtime", AssetType.MODEL_RUNTIME, "inference", "model-security", AssetSensitivity.CRITICAL, "Verified model runtime."),
        ArchitectureAsset("security-telemetry", AssetType.SECURITY_TELEMETRY, "security", "ai-security", AssetSensitivity.HIGH, "Security telemetry sink."),
    )
    flows = (
        ArchitectureFlow("flow-vector-retriever", "vector-store", "retriever", FlowType.DATA_ACCESS, "platform", (CTRL_TENANT_ISOLATION,), "Tenant-scoped retrieved content."),
        ArchitectureFlow("flow-retriever-agent", "retriever", "agent-orchestrator", FlowType.RETRIEVAL, "platform", (CTRL_TENANT_ISOLATION, CTRL_RAG_FILTER), "Filtered retrieval enters agent context."),
        ArchitectureFlow("flow-agent-model", "agent-orchestrator", "model-runtime", FlowType.INFERENCE, "model-security", (CTRL_INFERENCE_PRIVACY,), "Bounded model input."),
        ArchitectureFlow("flow-agent-user-response", "agent-orchestrator", "external-user", FlowType.DATA_ACCESS, "platform", (CTRL_TENANT_ISOLATION, CTRL_OUTPUT_FILTER), "Tenant-scoped model/tool response leaves the service."),
        ArchitectureFlow("flow-secret-tool", "secret-store", "tool-gateway", FlowType.SECRET_ACCESS, "ai-security", (CTRL_CREDENTIAL_BROKER, CTRL_LEAST_PRIVILEGE), "Brokered synthetic secret reaches tool boundary."),
        ArchitectureFlow("flow-tool-agent", "tool-gateway", "agent-orchestrator", FlowType.TOOL_CALL, "ai-security", (CTRL_TOOL_AUTH,), "Authorized tool result returns to agent."),
        ArchitectureFlow("flow-runtime-telemetry", "model-runtime", "security-telemetry", FlowType.SECURITY_TELEMETRY, "ai-security", (CTRL_TELEMETRY_MINIMIZATION,), "Minimized runtime telemetry enters security sink."),
    )
    return ArchitectureManifest(
        "aegisdesk-data-security-architecture",
        "7.3",
        MANIFEST_EPOCH,
        assets,
        flows,
    )


def _posture(tool_status: ControlStatus = ControlStatus.SATISFIED, tenant_status: ControlStatus = ControlStatus.EXCEPTIONED) -> VerifiedSecurityPosture:
    statuses = {
        control: ControlStatus.SATISFIED for control in ALL_CONTROLS
    }
    statuses[CTRL_TOOL_AUTH] = tool_status
    statuses[CTRL_TENANT_ISOLATION] = tenant_status
    assessments = tuple(
        ControlPostureAssessment(
            control_id=control,
            risk_domain="data-security",
            severity=AssuranceSeverity.HIGH,
            status=statuses[control],
            mapped_case_ids=(f"case-{index}",),
            exception_case_ids=(f"case-{index}",) if statuses[control] == ControlStatus.EXCEPTIONED else (),
            missing_case_ids=(f"case-{index}",) if statuses[control] == ControlStatus.NOT_EVALUATED else (),
            missing_boundaries=(),
            evidence_sha256=hashlib.sha256(f"p7c-control-{control}-{statuses[control].value}".encode()).hexdigest(),
        )
        for index, control in enumerate(ALL_CONTROLS, start=1)
    )
    return VerifiedSecurityPosture(
        candidate_release_id="aegisdesk-v0.63.0",
        candidate_commit_sha="c" * 64,
        candidate_package_version="0.63.0",
        corpus_id="p7c-synthetic-corpus",
        corpus_version="2026.08-p7c.1",
        corpus_sha256=hashlib.sha256(b"p7c-corpus").hexdigest(),
        control_catalog_id="p7c-data-control-catalog",
        control_catalog_version="1",
        control_catalog_sha256=CONTROL_CATALOG_SHA,
        waiver_governance_evidence_sha256=hashlib.sha256(b"p7c-waiver").hexdigest(),
        corpus_evolution_evidence_sha256=hashlib.sha256(b"p7c-corpus-evolution").hexdigest(),
        overall_rating=PostureRating.AMBER if any(a.status != ControlStatus.SATISFIED for a in assessments) else PostureRating.GREEN,
        control_count=len(assessments),
        satisfied_control_ids=tuple(sorted(a.control_id for a in assessments if a.status == ControlStatus.SATISFIED)),
        exceptioned_control_ids=tuple(sorted(a.control_id for a in assessments if a.status == ControlStatus.EXCEPTIONED)),
        not_evaluated_control_ids=tuple(sorted(a.control_id for a in assessments if a.status == ControlStatus.NOT_EVALUATED)),
        assessments=assessments,
        posture_evidence_sha256=POSTURE_EVIDENCE_SHA,
    )


def _p7a(architecture: ArchitectureManifest, posture: VerifiedSecurityPosture) -> VerifiedAttackPathAssessment:
    return VerifiedAttackPathAssessment(
        architecture_id=architecture.architecture_id,
        architecture_version=architecture.version,
        architecture_sha256=architecture_manifest_digest(architecture),
        posture_evidence_sha256=posture.posture_evidence_sha256,
        control_catalog_sha256=posture.control_catalog_sha256,
        attacker_profile_id="p7c-data-attacker",
        entry_asset_ids=("external-user",),
        target_asset_ids=("secret-store", "model-runtime"),
        topology_path_count=0,
        exposed_path_count=0,
        controlled_path_count=0,
        critical_exposed_path_count=0,
        max_exposed_risk_score=0,
        prioritized_exposed_path_ids=(),
        paths=(),
        assessment_evidence_sha256=P7A_EVIDENCE_SHA,
    )


def _p7b(architecture: ArchitectureManifest, p7a: VerifiedAttackPathAssessment, posture: VerifiedSecurityPosture) -> VerifiedPrivilegeEscalationAssessment:
    return VerifiedPrivilegeEscalationAssessment(
        identity_graph_id="p7c-identity-overlay",
        identity_graph_version="1",
        identity_graph_sha256=IDENTITY_GRAPH_SHA,
        architecture_sha256=architecture_manifest_digest(architecture),
        p7a_assessment_evidence_sha256=p7a.assessment_evidence_sha256,
        posture_evidence_sha256=posture.posture_evidence_sha256,
        control_catalog_sha256=posture.control_catalog_sha256,
        entry_principal_ids=("external-user-principal",),
        target_capability_ids=("cap-read-secret", "cap-model-context"),
        topology_path_count=0,
        exposed_path_count=0,
        controlled_path_count=0,
        critical_exposed_path_count=0,
        max_exposed_risk_score=0,
        prioritized_exposed_path_ids=(),
        paths=(),
        assessment_evidence_sha256=P7B_EVIDENCE_SHA,
    )


def _manifest(architecture_sha256: str) -> DataFlowManifest:
    data_objects = (
        DataObject(DATA_TICKET, "tenant-a", DataKind.TENANT_CONTENT, DataClassification.CONFIDENTIAL, "vector-store", "platform", "Tenant A synthetic support ticket."),
        DataObject(DATA_SECRET, "platform-security", DataKind.CREDENTIAL, DataClassification.SECRET, "secret-store", "ai-security", "Synthetic platform credential material."),
        DataObject(DATA_TELEMETRY, "platform-security", DataKind.SECURITY_TELEMETRY, DataClassification.INTERNAL, "model-runtime", "ai-security", "Synthetic runtime security event."),
    )
    edges = (
        DataFlowEdge(EDGE_TICKET_RETRIEVER, DATA_TICKET, "vector-store", "retriever", "tenant-a", DataTransform.NONE, "platform", ("flow-vector-retriever",), (CTRL_TENANT_ISOLATION,), "tenant retrieval"),
        DataFlowEdge(EDGE_TICKET_AGENT, DATA_TICKET, "retriever", "agent-orchestrator", "tenant-a", DataTransform.NONE, "platform", ("flow-retriever-agent",), (CTRL_TENANT_ISOLATION, CTRL_RAG_FILTER), "agent context"),
        DataFlowEdge(EDGE_TICKET_MODEL, DATA_TICKET, "agent-orchestrator", "model-runtime", "tenant-a", DataTransform.NONE, "model-security", ("flow-agent-model",), (CTRL_INFERENCE_PRIVACY,), "model context"),
        DataFlowEdge(EDGE_TICKET_USER, DATA_TICKET, "agent-orchestrator", "external-user", "tenant-b", DataTransform.NONE, "platform", ("flow-agent-user-response",), (CTRL_TENANT_ISOLATION, CTRL_OUTPUT_FILTER), "user response"),
        DataFlowEdge(EDGE_SECRET_TOOL, DATA_SECRET, "secret-store", "tool-gateway", "platform-security", DataTransform.TOKENIZED, "ai-security", ("flow-secret-tool",), (CTRL_CREDENTIAL_BROKER, CTRL_LEAST_PRIVILEGE), "brokered secret"),
        DataFlowEdge(EDGE_SECRET_AGENT, DATA_SECRET, "tool-gateway", "agent-orchestrator", "platform-security", DataTransform.TOKENIZED, "ai-security", ("flow-tool-agent",), (CTRL_TOOL_AUTH,), "tool result"),
        DataFlowEdge(EDGE_SECRET_USER, DATA_SECRET, "agent-orchestrator", "external-user", "tenant-a", DataTransform.NONE, "platform", ("flow-agent-user-response",), (CTRL_OUTPUT_FILTER,), "unsafe external response"),
        DataFlowEdge(EDGE_TELEMETRY_SECURITY, DATA_TELEMETRY, "model-runtime", "security-telemetry", "platform-security", DataTransform.REDACTED, "ai-security", ("flow-runtime-telemetry",), (CTRL_TELEMETRY_MINIMIZATION,), "security telemetry"),
    )
    return DataFlowManifest(
        "aegisdesk-data-flow-graph",
        "2026.08-p7c.1",
        architecture_sha256,
        MANIFEST_EPOCH,
        data_objects,
        edges,
    )


def _policy(manifest: DataFlowManifest, architecture_sha256: str) -> DataPathPolicy:
    data = {item.data_id: item for item in manifest.data_objects}
    edges = {item.edge_id: item for item in manifest.edges}
    return DataPathPolicy(
        expected_data_graph_id=manifest.data_graph_id,
        expected_data_graph_version=manifest.version,
        expected_data_graph_sha256=data_flow_manifest_digest(manifest),
        expected_architecture_sha256=architecture_sha256,
        expected_p7a_assessment_evidence_sha256=P7A_EVIDENCE_SHA,
        expected_p7b_assessment_evidence_sha256=P7B_EVIDENCE_SHA,
        expected_posture_evidence_sha256=POSTURE_EVIDENCE_SHA,
        expected_control_catalog_sha256=CONTROL_CATALOG_SHA,
        required_data_ids=frozenset(data),
        required_edge_ids=frozenset(edges),
        entry_data_ids=frozenset(data),
        target_sink_asset_ids=frozenset({"external-user", "model-runtime", "security-telemetry"}),
        trusted_owner_ids=frozenset({"platform", "ai-security", "model-security"}),
        expected_tenant_by_data={key: item.tenant_id for key, item in data.items()},
        expected_kind_by_data={key: item.data_kind for key, item in data.items()},
        expected_origin_asset_by_data={key: item.origin_asset_id for key, item in data.items()},
        minimum_classification_by_data={key: item.classification for key, item in data.items()},
        expected_data_id_by_edge={key: item.data_id for key, item in edges.items()},
        expected_endpoints_by_edge={key: (item.source_asset_id, item.target_asset_id) for key, item in edges.items()},
        expected_flow_ids_by_edge={key: tuple(item.via_flow_ids) for key, item in edges.items()},
        expected_control_ids_by_edge={key: frozenset(item.required_control_ids) for key, item in edges.items()},
        allowed_transforms_by_edge={
            key: frozenset({item.transform}) for key, item in edges.items()
        },
        allowed_destination_tenants_by_data={
            DATA_TICKET: frozenset({"tenant-a"}),
            DATA_SECRET: frozenset({"platform-security"}),
            DATA_TELEMETRY: frozenset({"platform-security"}),
        },
        allowed_sink_assets_by_data={
            DATA_TICKET: frozenset({"model-runtime", "external-user"}),
            DATA_SECRET: frozenset({"security-telemetry"}),
            DATA_TELEMETRY: frozenset({"security-telemetry"}),
        },
        max_classification_by_sink_asset={
            "external-user": DataClassification.CONFIDENTIAL,
            "model-runtime": DataClassification.RESTRICTED,
            "security-telemetry": DataClassification.INTERNAL,
        },
        allowed_final_transforms_by_sink_asset={
            "external-user": frozenset({DataTransform.NONE, DataTransform.REDACTED}),
            "model-runtime": frozenset({DataTransform.NONE, DataTransform.TOKENIZED}),
            "security-telemetry": frozenset({DataTransform.REDACTED, DataTransform.AGGREGATED, DataTransform.TOKENIZED}),
        },
        egress_sink_asset_ids=frozenset({"external-user"}),
        max_manifest_age_seconds=3_600,
        max_future_skew_seconds=30,
        max_path_hops=8,
        max_paths=128,
    )


def build_fixture(
    *,
    tool_status: ControlStatus = ControlStatus.SATISFIED,
    tenant_status: ControlStatus = ControlStatus.EXCEPTIONED,
) -> dict[str, object]:
    architecture = _architecture()
    architecture_sha = architecture_manifest_digest(architecture)
    posture = _posture(tool_status=tool_status, tenant_status=tenant_status)
    p7a = _p7a(architecture, posture)
    p7b = _p7b(architecture, p7a, posture)
    manifest = _manifest(architecture_sha)
    policy = _policy(manifest, architecture_sha)
    controls = {assessment.control_id: assessment.status for assessment in posture.assessments}
    data_objects = {item.data_id: item for item in manifest.data_objects}
    edges = {item.edge_id: item for item in manifest.edges}
    paths = _enumerate_paths(data_objects=data_objects, edges=edges, controls=controls, policy=policy)
    exposed = tuple(item.path_id for item in paths if item.exposed)
    max_risk = max((item.risk_score for item in paths if item.exposed), default=0)
    request = DataPathRequest(
        data_graph_id=manifest.data_graph_id,
        data_graph_version=manifest.version,
        data_graph_sha256=data_flow_manifest_digest(manifest),
        architecture_sha256=architecture_sha,
        p7a_assessment_evidence_sha256=p7a.assessment_evidence_sha256,
        p7b_assessment_evidence_sha256=p7b.assessment_evidence_sha256,
        posture_evidence_sha256=posture.posture_evidence_sha256,
        entry_data_ids=tuple(sorted(policy.entry_data_ids)),
        target_sink_asset_ids=tuple(sorted(policy.target_sink_asset_ids)),
        evaluated_at_epoch=EVALUATION_EPOCH,
        declared_exposed_path_ids=exposed,
        declared_max_exposed_risk_score=max_risk,
    )
    return {
        "architecture": architecture,
        "posture": posture,
        "p7a": p7a,
        "p7b": p7b,
        "manifest": manifest,
        "policy": policy,
        "request": request,
    }


def replace_data(manifest: DataFlowManifest, data_id: str, **changes) -> DataFlowManifest:
    return replace(
        manifest,
        data_objects=tuple(replace(item, **changes) if item.data_id == data_id else item for item in manifest.data_objects),
    )


def replace_edge(manifest: DataFlowManifest, edge_id: str, **changes) -> DataFlowManifest:
    return replace(
        manifest,
        edges=tuple(replace(item, **changes) if item.edge_id == edge_id else item for item in manifest.edges),
    )


def repin_manifest(fixture: dict[str, object], manifest: DataFlowManifest) -> dict[str, object]:
    digest = data_flow_manifest_digest(manifest)
    fixture["manifest"] = manifest
    fixture["policy"] = replace(fixture["policy"], expected_data_graph_sha256=digest)
    fixture["request"] = replace(fixture["request"], data_graph_sha256=digest)
    return fixture


def replace_posture_assessments(posture: VerifiedSecurityPosture, assessments) -> VerifiedSecurityPosture:
    assessments = tuple(assessments)
    return replace(
        posture,
        control_count=len(assessments),
        satisfied_control_ids=tuple(sorted(item.control_id for item in assessments if item.status == ControlStatus.SATISFIED)),
        exceptioned_control_ids=tuple(sorted(item.control_id for item in assessments if item.status == ControlStatus.EXCEPTIONED)),
        not_evaluated_control_ids=tuple(sorted(item.control_id for item in assessments if item.status == ControlStatus.NOT_EVALUATED)),
        assessments=assessments,
    )
