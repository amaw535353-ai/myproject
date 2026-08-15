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
from aegis.architecture.data_types import VerifiedDataExfiltrationAssessment
from aegis.architecture.privilege_types import VerifiedPrivilegeEscalationAssessment
from aegis.architecture.secrets_exposure import (
    ExposureScope,
    ExposureSurface,
    ExposureSurfaceType,
    SecretExposureManifest,
    SecretExposurePolicy,
    SecretExposureRequest,
    SecretKind,
    SecretMaterial,
    SecretScope,
    SecretSensitivity,
    SecretTransferChannel,
    SecretTransferEdge,
    secret_exposure_manifest_digest,
    secret_exposure_path_identifier,
)
from aegis.assurance.posture_reporting import (
    ControlPostureAssessment,
    ControlStatus,
    PostureRating,
    VerifiedSecurityPosture,
)
from aegis.assurance.regression import AssuranceSeverity


EVALUATION_EPOCH = 1_800_020_000
MANIFEST_EPOCH = EVALUATION_EPOCH - 300
ROTATED_EPOCH = EVALUATION_EPOCH - 86_400
EXPIRES_EPOCH = EVALUATION_EPOCH + 30 * 86_400

CTRL_SECRET_BROKER = "CTRL-SECRET-BROKER"
CTRL_BUILD_SECRET = "CTRL-BUILD-SECRET"
CTRL_ARTIFACT_SCAN = "CTRL-ARTIFACT-SCAN"
CTRL_SIGNING_KEY_ISOLATION = "CTRL-SIGNING-KEY-ISOLATION"
CTRL_RUNTIME_SECRET_INJECTION = "CTRL-RUNTIME-SECRET-INJECTION"
CTRL_TELEMETRY_REDACTION = "CTRL-TELEMETRY-REDACTION"
CTRL_EGRESS_FILTER = "CTRL-EGRESS-FILTER"
ALL_CONTROLS = (
    CTRL_SECRET_BROKER,
    CTRL_BUILD_SECRET,
    CTRL_ARTIFACT_SCAN,
    CTRL_SIGNING_KEY_ISOLATION,
    CTRL_RUNTIME_SECRET_INJECTION,
    CTRL_TELEMETRY_REDACTION,
    CTRL_EGRESS_FILTER,
)

SURFACE_CONFIG = "surface-app-config"
SURFACE_BUILD = "surface-build-runner"
SURFACE_ARTIFACT = "surface-release-artifact"
SURFACE_VAULT = "surface-key-vault"
SURFACE_TOOL = "surface-tool-gateway"
SURFACE_REGISTRY = "surface-model-registry"
SURFACE_RUNTIME = "surface-model-runtime"
SURFACE_TELEMETRY = "surface-telemetry"
SURFACE_EXTERNAL = "surface-external-egress"

SECRET_TOOL = "secret-tool-api"
SECRET_BUILD = "secret-build-token"
SECRET_MODEL = "secret-model-signing"
SECRET_RUNTIME = "secret-runtime-token"
SECRET_TELEMETRY = "secret-telemetry-export"
SECRET_ROOT = "secret-root-signing"
ALL_SECRETS = (SECRET_TOOL, SECRET_BUILD, SECRET_MODEL, SECRET_RUNTIME, SECRET_TELEMETRY, SECRET_ROOT)

EDGE_TOOL = "edge-tool-injection"
EDGE_BUILD_INJECT = "edge-build-injection"
EDGE_BUILD_ARTIFACT = "edge-build-artifact"
EDGE_MODEL_BUILD = "edge-model-key-build"
EDGE_MODEL_REGISTRY = "edge-model-key-registry"
EDGE_RUNTIME = "edge-runtime-injection"
EDGE_TELEMETRY = "edge-telemetry-export"
EDGE_ROOT_BUILD = "edge-root-build"
EDGE_ROOT_ARTIFACT = "edge-root-artifact"
ALL_EDGES = (
    EDGE_TOOL,
    EDGE_BUILD_INJECT,
    EDGE_BUILD_ARTIFACT,
    EDGE_MODEL_BUILD,
    EDGE_MODEL_REGISTRY,
    EDGE_RUNTIME,
    EDGE_TELEMETRY,
    EDGE_ROOT_BUILD,
    EDGE_ROOT_ARTIFACT,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


P7A_EVIDENCE_SHA = _sha("p7d-p7a-evidence")
P7B_EVIDENCE_SHA = _sha("p7d-p7b-evidence")
P7C_EVIDENCE_SHA = _sha("p7d-p7c-evidence")
POSTURE_EVIDENCE_SHA = _sha("p7d-p6d-posture")
CONTROL_CATALOG_SHA = _sha("p7d-control-catalog")
IDENTITY_GRAPH_SHA = _sha("p7d-identity-graph")
DATA_GRAPH_SHA = _sha("p7d-data-graph")
CORPUS_SHA = _sha("p7d-corpus")
WAIVER_SHA = _sha("p7d-waiver")
EVOLUTION_SHA = _sha("p7d-evolution")


def architecture() -> ArchitectureManifest:
    assets = (
        ArchitectureAsset("external-user", AssetType.EXTERNAL_ACTOR, "internet", "external", AssetSensitivity.LOW, "Synthetic external actor."),
        ArchitectureAsset("api-gateway", AssetType.API_GATEWAY, "edge", "platform", AssetSensitivity.MEDIUM, "API boundary."),
        ArchitectureAsset("agent-orchestrator", AssetType.AGENT_ORCHESTRATOR, "application", "platform", AssetSensitivity.HIGH, "Agent runtime."),
        ArchitectureAsset("tool-gateway", AssetType.TOOL_GATEWAY, "privileged-tools", "ai-security", AssetSensitivity.HIGH, "Privileged tool gateway."),
        ArchitectureAsset("secret-store", AssetType.SECRET_STORE, "secrets", "ai-security", AssetSensitivity.CRITICAL, "Synthetic secret store."),
        ArchitectureAsset("model-registry", AssetType.MODEL_REGISTRY, "model-supply-chain", "model-security", AssetSensitivity.HIGH, "Model registry."),
        ArchitectureAsset("model-runtime", AssetType.MODEL_RUNTIME, "inference", "model-security", AssetSensitivity.CRITICAL, "Model runtime."),
        ArchitectureAsset("security-telemetry", AssetType.SECURITY_TELEMETRY, "security", "ai-security", AssetSensitivity.HIGH, "Security telemetry."),
    )
    flows = (
        ArchitectureFlow("flow-user-api", "external-user", "api-gateway", FlowType.USER_INPUT, "platform", (), "User traffic."),
        ArchitectureFlow("flow-api-agent", "api-gateway", "agent-orchestrator", FlowType.AGENT_CONTROL, "platform", (), "Agent invocation."),
        ArchitectureFlow("flow-agent-tool", "agent-orchestrator", "tool-gateway", FlowType.TOOL_CALL, "ai-security", (CTRL_SECRET_BROKER,), "Tool authorization route."),
        ArchitectureFlow("flow-tool-secret", "tool-gateway", "secret-store", FlowType.SECRET_ACCESS, "ai-security", (CTRL_SECRET_BROKER,), "Credential brokerage route."),
        ArchitectureFlow("flow-registry-runtime", "model-registry", "model-runtime", FlowType.MODEL_ACQUISITION, "model-security", (CTRL_SIGNING_KEY_ISOLATION, CTRL_RUNTIME_SECRET_INJECTION), "Release/runtime route."),
        ArchitectureFlow("flow-runtime-telemetry", "model-runtime", "security-telemetry", FlowType.SECURITY_TELEMETRY, "ai-security", (CTRL_TELEMETRY_REDACTION,), "Telemetry route."),
    )
    return ArchitectureManifest("aegisdesk-ai-security-architecture", "7.4", MANIFEST_EPOCH, assets, flows)


def posture(exceptioned_control: str | None = None, not_evaluated_control: str | None = None) -> VerifiedSecurityPosture:
    assessments = []
    for control_id in ALL_CONTROLS:
        status = ControlStatus.SATISFIED
        if control_id == exceptioned_control:
            status = ControlStatus.EXCEPTIONED
        elif control_id == not_evaluated_control:
            status = ControlStatus.NOT_EVALUATED
        assessments.append(
            ControlPostureAssessment(
                control_id=control_id,
                risk_domain="secret-management",
                severity=AssuranceSeverity.HIGH,
                status=status,
                mapped_case_ids=(f"case-{control_id.casefold()}",),
                exception_case_ids=(f"case-{control_id.casefold()}",) if status == ControlStatus.EXCEPTIONED else (),
                missing_case_ids=(f"case-{control_id.casefold()}",) if status == ControlStatus.NOT_EVALUATED else (),
                missing_boundaries=(),
                evidence_sha256=_sha(f"control:{control_id}:{status.value}"),
            )
        )
    return VerifiedSecurityPosture(
        candidate_release_id="aegisdesk-v0.64.0",
        candidate_commit_sha="d" * 64,
        candidate_package_version="0.64.0",
        corpus_id="aegisdesk-cross-boundary-security-corpus",
        corpus_version="2026.08-p7d.1",
        corpus_sha256=CORPUS_SHA,
        control_catalog_id="aegisdesk-ai-security-controls",
        control_catalog_version="2026.08-p7d.1",
        control_catalog_sha256=CONTROL_CATALOG_SHA,
        waiver_governance_evidence_sha256=WAIVER_SHA,
        corpus_evolution_evidence_sha256=EVOLUTION_SHA,
        overall_rating=PostureRating.AMBER if exceptioned_control or not_evaluated_control else PostureRating.GREEN,
        control_count=len(assessments),
        satisfied_control_ids=tuple(sorted(item.control_id for item in assessments if item.status == ControlStatus.SATISFIED)),
        exceptioned_control_ids=tuple(sorted(item.control_id for item in assessments if item.status == ControlStatus.EXCEPTIONED)),
        not_evaluated_control_ids=tuple(sorted(item.control_id for item in assessments if item.status == ControlStatus.NOT_EVALUATED)),
        assessments=tuple(assessments),
        posture_evidence_sha256=POSTURE_EVIDENCE_SHA,
    )


def upstream(arch: ArchitectureManifest, posture_value: VerifiedSecurityPosture):
    arch_sha = architecture_manifest_digest(arch)
    p7a = VerifiedAttackPathAssessment(
        architecture_id=arch.architecture_id,
        architecture_version=arch.version,
        architecture_sha256=arch_sha,
        posture_evidence_sha256=posture_value.posture_evidence_sha256,
        control_catalog_sha256=posture_value.control_catalog_sha256,
        attacker_profile_id="synthetic-secret-exposure-attacker",
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
    p7b = VerifiedPrivilegeEscalationAssessment(
        identity_graph_id="aegisdesk-p7d-identity",
        identity_graph_version="7.4",
        identity_graph_sha256=IDENTITY_GRAPH_SHA,
        architecture_sha256=arch_sha,
        p7a_assessment_evidence_sha256=P7A_EVIDENCE_SHA,
        posture_evidence_sha256=posture_value.posture_evidence_sha256,
        control_catalog_sha256=posture_value.control_catalog_sha256,
        entry_principal_ids=("external-user-principal",),
        target_capability_ids=("cap-read-secret",),
        topology_path_count=0,
        exposed_path_count=0,
        controlled_path_count=0,
        critical_exposed_path_count=0,
        max_exposed_risk_score=0,
        prioritized_exposed_path_ids=(),
        paths=(),
        assessment_evidence_sha256=P7B_EVIDENCE_SHA,
    )
    p7c = VerifiedDataExfiltrationAssessment(
        data_graph_id="aegisdesk-p7d-data",
        data_graph_version="7.4",
        data_graph_sha256=DATA_GRAPH_SHA,
        architecture_sha256=arch_sha,
        p7a_assessment_evidence_sha256=P7A_EVIDENCE_SHA,
        p7b_assessment_evidence_sha256=P7B_EVIDENCE_SHA,
        posture_evidence_sha256=posture_value.posture_evidence_sha256,
        control_catalog_sha256=posture_value.control_catalog_sha256,
        entry_data_ids=("synthetic-secret-metadata",),
        target_sink_asset_ids=("security-telemetry",),
        topology_path_count=0,
        exposed_path_count=0,
        controlled_path_count=0,
        restricted_or_secret_exposed_path_count=0,
        cross_tenant_exposed_path_count=0,
        external_egress_exposed_path_count=0,
        max_exposed_risk_score=0,
        prioritized_exposed_path_ids=(),
        paths=(),
        assessment_evidence_sha256=P7C_EVIDENCE_SHA,
    )
    return p7a, p7b, p7c


def surfaces() -> tuple[ExposureSurface, ...]:
    return (
        ExposureSurface(SURFACE_CONFIG, ExposureSurfaceType.APPLICATION_CONFIG, ExposureScope.WORKLOAD, "application", "platform", None, False, "Application secret configuration boundary."),
        ExposureSurface(SURFACE_BUILD, ExposureSurfaceType.BUILD_RUNNER, ExposureScope.PLATFORM, "build", "platform", None, False, "Synthetic build runner."),
        ExposureSurface(SURFACE_ARTIFACT, ExposureSurfaceType.RELEASE_ARTIFACT, ExposureScope.PLATFORM, "release", "platform", None, False, "Synthetic release artifact."),
        ExposureSurface(SURFACE_VAULT, ExposureSurfaceType.KEY_VAULT, ExposureScope.SECURITY, "secrets", "ai-security", "secret-store", False, "Synthetic key-vault boundary."),
        ExposureSurface(SURFACE_TOOL, ExposureSurfaceType.TOOL_GATEWAY, ExposureScope.WORKLOAD, "privileged-tools", "ai-security", "tool-gateway", False, "Tool credential consumption boundary."),
        ExposureSurface(SURFACE_REGISTRY, ExposureSurfaceType.MODEL_REGISTRY, ExposureScope.MODEL_SUPPLY_CHAIN, "model-supply-chain", "model-security", "model-registry", False, "Model registry signing boundary."),
        ExposureSurface(SURFACE_RUNTIME, ExposureSurfaceType.MODEL_RUNTIME, ExposureScope.MODEL_SUPPLY_CHAIN, "inference", "model-security", "model-runtime", False, "Runtime injection boundary."),
        ExposureSurface(SURFACE_TELEMETRY, ExposureSurfaceType.TELEMETRY_PIPELINE, ExposureScope.SECURITY, "security", "ai-security", "security-telemetry", False, "Telemetry credential boundary."),
        ExposureSurface(SURFACE_EXTERNAL, ExposureSurfaceType.EXTERNAL_EGRESS, ExposureScope.EXTERNAL, "external", "external", None, True, "Synthetic untrusted external sink."),
    )


def secrets() -> tuple[SecretMaterial, ...]:
    return (
        SecretMaterial(SECRET_TOOL, SecretKind.API_TOKEN, SecretSensitivity.HIGH, SecretScope.WORKLOAD, "ai-security", SURFACE_CONFIG, ROTATED_EPOCH, EXPIRES_EPOCH, False, "Scoped privileged-tool API token."),
        SecretMaterial(SECRET_BUILD, SecretKind.BUILD_TOKEN, SecretSensitivity.HIGH, SecretScope.PLATFORM, "platform", SURFACE_CONFIG, ROTATED_EPOCH, EXPIRES_EPOCH, False, "Synthetic build token."),
        SecretMaterial(SECRET_MODEL, SecretKind.MODEL_PUBLISHER_KEY, SecretSensitivity.CRITICAL, SecretScope.MODEL_SUPPLY_CHAIN, "model-security", SURFACE_VAULT, ROTATED_EPOCH, EXPIRES_EPOCH, False, "Model publisher signing key."),
        SecretMaterial(SECRET_RUNTIME, SecretKind.SERVICE_CREDENTIAL, SecretSensitivity.HIGH, SecretScope.MODEL_SUPPLY_CHAIN, "model-security", SURFACE_REGISTRY, ROTATED_EPOCH, EXPIRES_EPOCH, False, "Runtime release-admission credential."),
        SecretMaterial(SECRET_TELEMETRY, SecretKind.TELEMETRY_CREDENTIAL, SecretSensitivity.HIGH, SecretScope.SECURITY, "ai-security", SURFACE_RUNTIME, ROTATED_EPOCH, EXPIRES_EPOCH, False, "Telemetry export credential."),
        SecretMaterial(SECRET_ROOT, SecretKind.ROOT_SIGNING_KEY, SecretSensitivity.CRITICAL, SecretScope.GLOBAL_TRUST_ROOT, "ai-security", SURFACE_VAULT, ROTATED_EPOCH, EXPIRES_EPOCH, True, "Offline synthetic root signing key."),
    )


def edges() -> tuple[SecretTransferEdge, ...]:
    return (
        SecretTransferEdge(EDGE_TOOL, SECRET_TOOL, SURFACE_CONFIG, SURFACE_TOOL, SecretTransferChannel.TOOL_CREDENTIAL_BROKER, "ai-security", (), (CTRL_SECRET_BROKER,), False, False, "Broker scoped tool token."),
        SecretTransferEdge(EDGE_BUILD_INJECT, SECRET_BUILD, SURFACE_CONFIG, SURFACE_BUILD, SecretTransferChannel.BUILD_SECRET, "platform", (), (CTRL_BUILD_SECRET,), False, False, "Inject ephemeral build token."),
        SecretTransferEdge(EDGE_BUILD_ARTIFACT, SECRET_BUILD, SURFACE_BUILD, SURFACE_ARTIFACT, SecretTransferChannel.ARTIFACT_EMBEDDING, "platform", (), (CTRL_ARTIFACT_SCAN,), False, False, "Release artifact scanning boundary."),
        SecretTransferEdge(EDGE_MODEL_BUILD, SECRET_MODEL, SURFACE_VAULT, SURFACE_BUILD, SecretTransferChannel.MODEL_RELEASE_SIGNING, "model-security", (), (CTRL_SIGNING_KEY_ISOLATION,), False, False, "Use isolated model publisher key for signing."),
        SecretTransferEdge(EDGE_MODEL_REGISTRY, SECRET_MODEL, SURFACE_BUILD, SURFACE_REGISTRY, SecretTransferChannel.MODEL_RELEASE_SIGNING, "model-security", (), (CTRL_SIGNING_KEY_ISOLATION,), False, False, "Publish signed release metadata."),
        SecretTransferEdge(EDGE_RUNTIME, SECRET_RUNTIME, SURFACE_REGISTRY, SURFACE_RUNTIME, SecretTransferChannel.RUNTIME_CREDENTIAL_INJECTION, "model-security", ("flow-registry-runtime",), (CTRL_SIGNING_KEY_ISOLATION, CTRL_RUNTIME_SECRET_INJECTION), False, False, "Inject bounded runtime admission credential."),
        SecretTransferEdge(EDGE_TELEMETRY, SECRET_TELEMETRY, SURFACE_RUNTIME, SURFACE_TELEMETRY, SecretTransferChannel.TELEMETRY_EXPORT, "ai-security", ("flow-runtime-telemetry",), (CTRL_TELEMETRY_REDACTION,), False, False, "Use scoped telemetry credential."),
        SecretTransferEdge(EDGE_ROOT_BUILD, SECRET_ROOT, SURFACE_VAULT, SURFACE_BUILD, SecretTransferChannel.MODEL_RELEASE_SIGNING, "ai-security", (), (CTRL_SIGNING_KEY_ISOLATION,), False, False, "Offline root signs release trust metadata."),
        SecretTransferEdge(EDGE_ROOT_ARTIFACT, SECRET_ROOT, SURFACE_BUILD, SURFACE_ARTIFACT, SecretTransferChannel.MODEL_RELEASE_SIGNING, "ai-security", (), (CTRL_SIGNING_KEY_ISOLATION, CTRL_ARTIFACT_SCAN), False, False, "Retain signature only; key material remains isolated."),
    )


def manifest(arch_sha: str) -> SecretExposureManifest:
    return SecretExposureManifest(
        secret_graph_id="aegisdesk-secret-trust-root-graph",
        version="2026.08-p7d.1",
        architecture_sha256=arch_sha,
        created_at_epoch=MANIFEST_EPOCH,
        surfaces=surfaces(),
        secrets=secrets(),
        edges=edges(),
    )


def _policy(manifest_value: SecretExposureManifest, arch_sha: str) -> SecretExposurePolicy:
    surface_map = {item.surface_id: item for item in manifest_value.surfaces}
    secret_map = {item.secret_id: item for item in manifest_value.secrets}
    edge_map = {item.edge_id: item for item in manifest_value.edges}
    return SecretExposurePolicy(
        expected_secret_graph_id=manifest_value.secret_graph_id,
        expected_secret_graph_version=manifest_value.version,
        expected_secret_graph_sha256=secret_exposure_manifest_digest(manifest_value),
        expected_architecture_sha256=arch_sha,
        expected_p7a_assessment_evidence_sha256=P7A_EVIDENCE_SHA,
        expected_p7b_assessment_evidence_sha256=P7B_EVIDENCE_SHA,
        expected_p7c_assessment_evidence_sha256=P7C_EVIDENCE_SHA,
        expected_posture_evidence_sha256=POSTURE_EVIDENCE_SHA,
        expected_control_catalog_sha256=CONTROL_CATALOG_SHA,
        required_surface_ids=frozenset(surface_map),
        required_secret_ids=frozenset(secret_map),
        required_edge_ids=frozenset(edge_map),
        entry_secret_ids=frozenset(secret_map),
        target_surface_ids=frozenset({SURFACE_TOOL, SURFACE_ARTIFACT, SURFACE_REGISTRY, SURFACE_RUNTIME, SURFACE_TELEMETRY, SURFACE_EXTERNAL}),
        trusted_owner_ids=frozenset({"platform", "ai-security", "model-security", "external"}),
        expected_surface_type={key: value.surface_type for key, value in surface_map.items()},
        expected_surface_scope={key: value.exposure_scope for key, value in surface_map.items()},
        expected_surface_zone={key: value.trust_zone for key, value in surface_map.items()},
        expected_architecture_asset_by_surface={key: value.architecture_asset_id for key, value in surface_map.items()},
        expected_kind_by_secret={key: value.kind for key, value in secret_map.items()},
        expected_scope_by_secret={key: value.authority_scope for key, value in secret_map.items()},
        expected_home_surface_by_secret={key: value.home_surface_id for key, value in secret_map.items()},
        minimum_sensitivity_by_secret={key: value.sensitivity for key, value in secret_map.items()},
        expected_trust_root_by_secret={key: value.trust_root for key, value in secret_map.items()},
        max_rotation_age_seconds_by_secret={key: 7 * 86_400 if value.trust_root else 30 * 86_400 for key, value in secret_map.items()},
        allowed_target_surfaces_by_secret={
            SECRET_TOOL: frozenset({SURFACE_TOOL}),
            SECRET_BUILD: frozenset({SURFACE_BUILD, SURFACE_ARTIFACT}),
            SECRET_MODEL: frozenset({SURFACE_BUILD, SURFACE_REGISTRY}),
            SECRET_RUNTIME: frozenset({SURFACE_RUNTIME}),
            SECRET_TELEMETRY: frozenset({SURFACE_TELEMETRY}),
            SECRET_ROOT: frozenset({SURFACE_BUILD, SURFACE_ARTIFACT}),
        },
        allowed_surface_scopes_by_secret={
            SECRET_TOOL: frozenset({ExposureScope.WORKLOAD}),
            SECRET_BUILD: frozenset({ExposureScope.PLATFORM}),
            SECRET_MODEL: frozenset({ExposureScope.PLATFORM, ExposureScope.MODEL_SUPPLY_CHAIN}),
            SECRET_RUNTIME: frozenset({ExposureScope.MODEL_SUPPLY_CHAIN}),
            SECRET_TELEMETRY: frozenset({ExposureScope.SECURITY}),
            SECRET_ROOT: frozenset({ExposureScope.PLATFORM}),
        },
        forbid_plaintext_by_secret={key: True for key in secret_map},
        forbid_persistent_copy_by_secret={key: value.sensitivity == SecretSensitivity.CRITICAL or value.trust_root for key, value in secret_map.items()},
        expected_secret_id_by_edge={key: value.secret_id for key, value in edge_map.items()},
        expected_endpoints_by_edge={key: (value.source_surface_id, value.target_surface_id) for key, value in edge_map.items()},
        expected_channel_by_edge={key: value.channel for key, value in edge_map.items()},
        expected_flow_ids_by_edge={key: tuple(value.via_flow_ids) for key, value in edge_map.items()},
        expected_control_ids_by_edge={key: frozenset(value.required_control_ids) for key, value in edge_map.items()},
        max_manifest_age_seconds=3_600,
        max_future_skew_seconds=30,
        max_path_hops=8,
        max_paths=64,
    )


def _path_ids() -> dict[str, str]:
    return {
        SECRET_TOOL: secret_exposure_path_identifier(SECRET_TOOL, (SURFACE_CONFIG, SURFACE_TOOL), (EDGE_TOOL,)),
        SECRET_BUILD: secret_exposure_path_identifier(SECRET_BUILD, (SURFACE_CONFIG, SURFACE_BUILD, SURFACE_ARTIFACT), (EDGE_BUILD_INJECT, EDGE_BUILD_ARTIFACT)),
        SECRET_MODEL: secret_exposure_path_identifier(SECRET_MODEL, (SURFACE_VAULT, SURFACE_BUILD, SURFACE_REGISTRY), (EDGE_MODEL_BUILD, EDGE_MODEL_REGISTRY)),
        SECRET_RUNTIME: secret_exposure_path_identifier(SECRET_RUNTIME, (SURFACE_REGISTRY, SURFACE_RUNTIME), (EDGE_RUNTIME,)),
        SECRET_TELEMETRY: secret_exposure_path_identifier(SECRET_TELEMETRY, (SURFACE_RUNTIME, SURFACE_TELEMETRY), (EDGE_TELEMETRY,)),
        SECRET_ROOT: secret_exposure_path_identifier(SECRET_ROOT, (SURFACE_VAULT, SURFACE_BUILD, SURFACE_ARTIFACT), (EDGE_ROOT_BUILD, EDGE_ROOT_ARTIFACT)),
    }


def _declared(exceptioned_control: str | None, not_evaluated_control: str | None) -> tuple[tuple[str, ...], int]:
    ids = _path_ids()
    exposed: list[str] = []
    scores: list[int] = []
    if exceptioned_control in {CTRL_BUILD_SECRET, CTRL_ARTIFACT_SCAN}:
        exposed.append(ids[SECRET_BUILD])
        scores.append(95)
    if not_evaluated_control in {CTRL_BUILD_SECRET, CTRL_ARTIFACT_SCAN}:
        exposed.append(ids[SECRET_BUILD])
        scores.append(91)
    if exceptioned_control == CTRL_SECRET_BROKER:
        exposed.append(ids[SECRET_TOOL])
        scores.append(91)
    if not_evaluated_control == CTRL_SECRET_BROKER:
        exposed.append(ids[SECRET_TOOL])
        scores.append(87)
    if exceptioned_control in {CTRL_SIGNING_KEY_ISOLATION, CTRL_RUNTIME_SECRET_INJECTION}:
        exposed.extend([ids[SECRET_MODEL], ids[SECRET_RUNTIME], ids[SECRET_ROOT]])
        scores.extend([118, 96, 163])
    if not_evaluated_control in {CTRL_SIGNING_KEY_ISOLATION, CTRL_RUNTIME_SECRET_INJECTION}:
        exposed.extend([ids[SECRET_MODEL], ids[SECRET_RUNTIME], ids[SECRET_ROOT]])
        scores.extend([114, 92, 159])
    if exceptioned_control == CTRL_TELEMETRY_REDACTION:
        exposed.append(ids[SECRET_TELEMETRY])
        scores.append(98)
    if not_evaluated_control == CTRL_TELEMETRY_REDACTION:
        exposed.append(ids[SECRET_TELEMETRY])
        scores.append(94)
    return tuple(sorted(set(exposed))), max(scores, default=0)


def build_fixture(exceptioned_control: str | None = None, not_evaluated_control: str | None = None) -> dict[str, object]:
    arch = architecture()
    arch_sha = architecture_manifest_digest(arch)
    posture_value = posture(exceptioned_control, not_evaluated_control)
    p7a, p7b, p7c = upstream(arch, posture_value)
    manifest_value = manifest(arch_sha)
    policy_value = _policy(manifest_value, arch_sha)
    exposed, max_score = _declared(exceptioned_control, not_evaluated_control)
    request = SecretExposureRequest(
        secret_graph_id=manifest_value.secret_graph_id,
        secret_graph_version=manifest_value.version,
        secret_graph_sha256=secret_exposure_manifest_digest(manifest_value),
        architecture_sha256=arch_sha,
        p7a_assessment_evidence_sha256=p7a.assessment_evidence_sha256,
        p7b_assessment_evidence_sha256=p7b.assessment_evidence_sha256,
        p7c_assessment_evidence_sha256=p7c.assessment_evidence_sha256,
        posture_evidence_sha256=posture_value.posture_evidence_sha256,
        entry_secret_ids=tuple(sorted(policy_value.entry_secret_ids)),
        target_surface_ids=tuple(sorted(policy_value.target_surface_ids)),
        evaluated_at_epoch=EVALUATION_EPOCH,
        declared_exposed_path_ids=exposed,
        declared_max_blast_radius_score=max_score,
    )
    return {
        "architecture": arch,
        "posture": posture_value,
        "p7a": p7a,
        "p7b": p7b,
        "p7c": p7c,
        "manifest": manifest_value,
        "policy": policy_value,
        "request": request,
    }


def replace_surface(manifest_value: SecretExposureManifest, surface_id: str, **changes) -> SecretExposureManifest:
    return replace(manifest_value, surfaces=tuple(replace(item, **changes) if item.surface_id == surface_id else item for item in manifest_value.surfaces))


def replace_secret(manifest_value: SecretExposureManifest, secret_id: str, **changes) -> SecretExposureManifest:
    return replace(manifest_value, secrets=tuple(replace(item, **changes) if item.secret_id == secret_id else item for item in manifest_value.secrets))


def replace_edge(manifest_value: SecretExposureManifest, edge_id: str, **changes) -> SecretExposureManifest:
    return replace(manifest_value, edges=tuple(replace(item, **changes) if item.edge_id == edge_id else item for item in manifest_value.edges))


def repin_manifest(fixture: dict[str, object], manifest_value: SecretExposureManifest, *, repin_structure: bool = False) -> dict[str, object]:
    digest = secret_exposure_manifest_digest(manifest_value)
    fixture["manifest"] = manifest_value
    fixture["request"] = replace(fixture["request"], secret_graph_sha256=digest)
    policy_value = replace(fixture["policy"], expected_secret_graph_sha256=digest)
    if repin_structure:
        surface_map = {item.surface_id: item for item in manifest_value.surfaces}
        secret_map = {item.secret_id: item for item in manifest_value.secrets}
        edge_map = {item.edge_id: item for item in manifest_value.edges}
        policy_value = replace(
            policy_value,
            required_surface_ids=frozenset(surface_map),
            required_secret_ids=frozenset(secret_map),
            required_edge_ids=frozenset(edge_map),
            expected_surface_type={key: value.surface_type for key, value in surface_map.items()},
            expected_surface_scope={key: value.exposure_scope for key, value in surface_map.items()},
            expected_surface_zone={key: value.trust_zone for key, value in surface_map.items()},
            expected_architecture_asset_by_surface={key: value.architecture_asset_id for key, value in surface_map.items()},
            expected_kind_by_secret={key: value.kind for key, value in secret_map.items()},
            expected_scope_by_secret={key: value.authority_scope for key, value in secret_map.items()},
            expected_home_surface_by_secret={key: value.home_surface_id for key, value in secret_map.items()},
            minimum_sensitivity_by_secret={key: value.sensitivity for key, value in secret_map.items()},
            expected_trust_root_by_secret={key: value.trust_root for key, value in secret_map.items()},
            max_rotation_age_seconds_by_secret={key: 7 * 86_400 if value.trust_root else 30 * 86_400 for key, value in secret_map.items()},
            forbid_plaintext_by_secret={key: True for key in secret_map},
            forbid_persistent_copy_by_secret={key: value.sensitivity == SecretSensitivity.CRITICAL or value.trust_root for key, value in secret_map.items()},
            expected_secret_id_by_edge={key: value.secret_id for key, value in edge_map.items()},
            expected_endpoints_by_edge={key: (value.source_surface_id, value.target_surface_id) for key, value in edge_map.items()},
            expected_channel_by_edge={key: value.channel for key, value in edge_map.items()},
            expected_flow_ids_by_edge={key: tuple(value.via_flow_ids) for key, value in edge_map.items()},
            expected_control_ids_by_edge={key: frozenset(value.required_control_ids) for key, value in edge_map.items()},
        )
    fixture["policy"] = policy_value
    return fixture
