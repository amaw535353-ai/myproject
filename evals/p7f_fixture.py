from __future__ import annotations

import hashlib
from dataclasses import replace
from types import SimpleNamespace

from aegis.architecture.dependency_trust import (
    AuthenticationMode,
    DependencyCriticality,
    DependencyType,
    EgressDataClass,
    ThirdPartyTrustPathFact,
    TransportMode,
    VerifiedDependencyTrustAssessment,
)
from aegis.architecture.resilience_security import (
    DependencyFailureScenario,
    DependencyFailureState,
    FallbackMode,
    FallbackStrategy,
    ResilienceSecurityManifest,
    ResilienceSecurityPolicy,
    ResilienceSecurityRequest,
    resilience_security_manifest_digest,
)
from aegis.assurance.posture_reporting import ControlStatus


NOW = 2_100_000_000
PLAN_ID = "aegisdesk-dependency-resilience-security-plan"
PLAN_VERSION = "2026.08-p7f.1"
DEPENDENCY_GRAPH_SHA256 = hashlib.sha256(b"p7f-dependency-graph").hexdigest()
P7E_EVIDENCE_SHA256 = hashlib.sha256(b"p7e-evidence-for-p7f").hexdigest()
POSTURE_SHA256 = hashlib.sha256(b"p6d-posture-for-p7f").hexdigest()
CONTROL_CATALOG_SHA256 = hashlib.sha256(b"p6d-control-catalog-for-p7f").hexdigest()

CTRL_MODEL_EGRESS = "CTRL-MODEL-EGRESS"
CTRL_TOOL_EGRESS = "CTRL-TOOL-EGRESS"
CTRL_TELEMETRY_EGRESS = "CTRL-TELEMETRY-EGRESS"
CTRL_REGISTRY_EGRESS = "CTRL-REGISTRY-EGRESS"
CTRL_IDP_EGRESS = "CTRL-IDP-EGRESS"
CTRL_FALLBACK_AUTHZ = "CTRL-FALLBACK-AUTHZ"
CTRL_LOCAL_SAFE_MODE = "CTRL-LOCAL-SAFE-MODE"
CTRL_CACHE_INTEGRITY = "CTRL-CACHE-INTEGRITY"
CTRL_FAIL_CLOSED = "CTRL-FAIL-CLOSED"

ALL_CONTROLS = (
    CTRL_MODEL_EGRESS,
    CTRL_TOOL_EGRESS,
    CTRL_TELEMETRY_EGRESS,
    CTRL_REGISTRY_EGRESS,
    CTRL_IDP_EGRESS,
    CTRL_FALLBACK_AUTHZ,
    CTRL_LOCAL_SAFE_MODE,
    CTRL_CACHE_INTEGRITY,
    CTRL_FAIL_CLOSED,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _path(
    dependency_id: str,
    provider_id: str,
    dependency_type: DependencyType,
    criticality: DependencyCriticality,
    transport_mode: TransportMode,
    authentication_mode: AuthenticationMode,
    *,
    data_classes: tuple[str, ...] = ("internal",),
    secret_ids: tuple[str, ...] = (),
    exposed: bool = False,
    risk_score: int = 0,
) -> ThirdPartyTrustPathFact:
    return ThirdPartyTrustPathFact(
        path_id=f"path-{dependency_id}",
        route_id=f"route-{dependency_id}",
        source_asset_id=f"asset-{dependency_id}",
        dependency_id=dependency_id,
        provider_id=provider_id,
        dependency_type=dependency_type,
        criticality=criticality,
        endpoint_host=f"{dependency_id}.example",
        endpoint_port=443,
        transport_mode=transport_mode,
        authentication_mode=authentication_mode,
        server_identity=f"spiffe://{dependency_id}.example/service",
        egress_data_classes=data_classes,
        exposed_secret_ids=secret_ids,
        architecture_flow_ids=(f"flow-{dependency_id}",),
        satisfied_control_ids=(),
        exceptioned_control_ids=(),
        not_evaluated_control_ids=(),
        fail_closed=True,
        exposed=exposed,
        risk_score=risk_score,
        exposure_reasons=("synthetic_upstream_exposure",) if exposed else (),
        mitigating_control_ids=(),
    )


def build_p7e_assessment(*, exposed_alternate: bool = False, weaker_alternate: bool = False) -> VerifiedDependencyTrustAssessment:
    alternate_transport = TransportMode.TLS if weaker_alternate else TransportMode.MTLS
    alternate_auth = AuthenticationMode.API_KEY if weaker_alternate else AuthenticationMode.OAUTH2
    paths = (
        _path("dep-model-primary", "provider-model-primary", DependencyType.MODEL_PROVIDER, DependencyCriticality.HIGH, TransportMode.MTLS, AuthenticationMode.OAUTH2, data_classes=("internal", "confidential")),
        _path("dep-model-secondary", "provider-model-secondary", DependencyType.MODEL_PROVIDER, DependencyCriticality.HIGH, alternate_transport, alternate_auth, data_classes=("internal", "confidential"), exposed=exposed_alternate, risk_score=88 if exposed_alternate else 0),
        _path("dep-tool-api", "provider-tool", DependencyType.TOOL_API, DependencyCriticality.CRITICAL, TransportMode.MTLS, AuthenticationMode.SIGNED_REQUEST, data_classes=("confidential", "restricted"), secret_ids=("secret-tool-api",)),
        _path("dep-idp", "provider-idp", DependencyType.IDENTITY_PROVIDER, DependencyCriticality.CRITICAL, TransportMode.MTLS, AuthenticationMode.MTLS),
        _path("dep-telemetry", "provider-telemetry", DependencyType.TELEMETRY_SINK, DependencyCriticality.MEDIUM, TransportMode.TLS, AuthenticationMode.OAUTH2, data_classes=("internal", "confidential")),
        _path("dep-registry", "provider-registry", DependencyType.PACKAGE_REGISTRY, DependencyCriticality.HIGH, TransportMode.PRIVATE_LINK, AuthenticationMode.MTLS),
    )
    exposed_paths = tuple(item for item in paths if item.exposed)
    return VerifiedDependencyTrustAssessment(
        dependency_graph_id="aegisdesk-third-party-egress-graph-p7f",
        dependency_graph_version="2026.08-p7f.1",
        dependency_graph_sha256=DEPENDENCY_GRAPH_SHA256,
        architecture_sha256=_sha("architecture-p7f"),
        p7a_assessment_evidence_sha256=_sha("p7a-p7f"),
        p7b_assessment_evidence_sha256=_sha("p7b-p7f"),
        p7c_assessment_evidence_sha256=_sha("p7c-p7f"),
        p7d_assessment_evidence_sha256=_sha("p7d-p7f"),
        posture_evidence_sha256=POSTURE_SHA256,
        control_catalog_sha256=CONTROL_CATALOG_SHA256,
        entry_source_asset_ids=tuple(sorted(item.source_asset_id for item in paths)),
        target_dependency_ids=tuple(sorted(item.dependency_id for item in paths)),
        topology_path_count=len(paths),
        exposed_path_count=len(exposed_paths),
        controlled_path_count=len(paths) - len(exposed_paths),
        critical_exposed_path_count=sum(item.exposed and item.criticality == DependencyCriticality.CRITICAL for item in paths),
        secret_bearing_exposed_path_count=sum(item.exposed and bool(item.exposed_secret_ids) for item in paths),
        restricted_or_secret_data_exposed_path_count=sum(item.exposed and bool(set(item.egress_data_classes) & {"restricted", "secret"}) for item in paths),
        fail_open_exposed_path_count=0,
        max_exposed_risk_score=max((item.risk_score for item in exposed_paths), default=0),
        prioritized_exposed_path_ids=tuple(item.path_id for item in sorted(exposed_paths, key=lambda value: (-value.risk_score, value.path_id))),
        paths=paths,
        assessment_evidence_sha256=P7E_EVIDENCE_SHA256,
    )


def _scenarios() -> tuple[DependencyFailureScenario, ...]:
    return (
        DependencyFailureScenario("scenario-model-unavailable", "dep-model-primary", DependencyFailureState.UNAVAILABLE, "model-security", (CTRL_MODEL_EGRESS, CTRL_FALLBACK_AUTHZ, CTRL_LOCAL_SAFE_MODE), "Hosted model provider is unavailable."),
        DependencyFailureScenario("scenario-model-untrusted", "dep-model-primary", DependencyFailureState.UNTRUSTED, "model-security", (CTRL_MODEL_EGRESS, CTRL_FALLBACK_AUTHZ), "Primary model provider loses trust."),
        DependencyFailureScenario("scenario-model-degraded", "dep-model-primary", DependencyFailureState.DEGRADED, "model-security", (CTRL_MODEL_EGRESS, CTRL_FALLBACK_AUTHZ), "Primary model provider is degraded."),
        DependencyFailureScenario("scenario-tool-unavailable", "dep-tool-api", DependencyFailureState.UNAVAILABLE, "tool-security", (CTRL_TOOL_EGRESS, CTRL_FAIL_CLOSED), "Privileged tool API is unavailable."),
        DependencyFailureScenario("scenario-idp-unavailable", "dep-idp", DependencyFailureState.UNAVAILABLE, "platform-security", (CTRL_IDP_EGRESS, CTRL_FAIL_CLOSED), "Identity provider is unavailable."),
        DependencyFailureScenario("scenario-telemetry-degraded", "dep-telemetry", DependencyFailureState.DEGRADED, "security-operations", (CTRL_TELEMETRY_EGRESS, CTRL_CACHE_INTEGRITY), "Telemetry processor is degraded."),
        DependencyFailureScenario("scenario-registry-unavailable", "dep-registry", DependencyFailureState.UNAVAILABLE, "model-security", (CTRL_REGISTRY_EGRESS, CTRL_CACHE_INTEGRITY), "Registry is unavailable."),
    )


def _fallbacks(*, stale_cache_fallback_id: str | None = None) -> tuple[FallbackStrategy, ...]:
    telemetry_cache_time = NOW - (900 if stale_cache_fallback_id == "fallback-telemetry-cache" else 60)
    registry_cache_time = NOW - (7_200 if stale_cache_fallback_id == "fallback-registry-cache" else 300)
    return (
        FallbackStrategy("fallback-model-local-safe", "scenario-model-unavailable", FallbackMode.LOCAL_SAFE_MODE, "model-security", None, (CTRL_MODEL_EGRESS, CTRL_FALLBACK_AUTHZ, CTRL_LOCAL_SAFE_MODE), (), (EgressDataClass.INTERNAL,), (), 0, None, "Return a local constrained safe-mode response without tool use."),
        FallbackStrategy("fallback-model-secondary", "scenario-model-untrusted", FallbackMode.ALTERNATE_DEPENDENCY, "model-security", "dep-model-secondary", (CTRL_MODEL_EGRESS, CTRL_FALLBACK_AUTHZ), (), (EgressDataClass.CONFIDENTIAL,), (), 0, None, "Use independently pinned secondary model provider."),
        FallbackStrategy("fallback-model-retry", "scenario-model-degraded", FallbackMode.RETRY_PRIMARY, "model-security", "dep-model-primary", (CTRL_MODEL_EGRESS, CTRL_FALLBACK_AUTHZ), (), (EgressDataClass.CONFIDENTIAL,), (), 2, None, "Retry primary model provider with a deterministic bound."),
        FallbackStrategy("fallback-tool-closed", "scenario-tool-unavailable", FallbackMode.FAIL_CLOSED, "tool-security", None, (CTRL_TOOL_EGRESS, CTRL_FAIL_CLOSED), (), (), (), 0, None, "Deny privileged tool execution while dependency is unavailable."),
        FallbackStrategy("fallback-idp-closed", "scenario-idp-unavailable", FallbackMode.FAIL_CLOSED, "platform-security", None, (CTRL_IDP_EGRESS, CTRL_FAIL_CLOSED), (), (), (), 0, None, "Reject new authorization when identity verification is unavailable."),
        FallbackStrategy("fallback-telemetry-cache", "scenario-telemetry-degraded", FallbackMode.CACHE_FALLBACK, "security-operations", None, (CTRL_TELEMETRY_EGRESS, CTRL_CACHE_INTEGRITY), (), (EgressDataClass.INTERNAL,), (), 0, telemetry_cache_time, "Buffer bounded synthetic telemetry locally."),
        FallbackStrategy("fallback-registry-cache", "scenario-registry-unavailable", FallbackMode.CACHE_FALLBACK, "model-security", None, (CTRL_REGISTRY_EGRESS, CTRL_CACHE_INTEGRITY), (), (EgressDataClass.INTERNAL,), (), 0, registry_cache_time, "Use a bounded previously verified local registry cache."),
    )


def _risk_for_fact(criticality: DependencyCriticality, data_classes: tuple[EgressDataClass, ...], exceptioned: int, not_evaluated: int, *, stale: bool = False, alternate_exposed: bool = False, weaker_alternate: bool = False) -> int:
    criticality_rank = {DependencyCriticality.LOW: 1, DependencyCriticality.MEDIUM: 2, DependencyCriticality.HIGH: 3, DependencyCriticality.CRITICAL: 4}[criticality]
    data_rank = {EgressDataClass.PUBLIC: 1, EgressDataClass.INTERNAL: 2, EgressDataClass.CONFIDENTIAL: 3, EgressDataClass.RESTRICTED: 4, EgressDataClass.SECRET: 5}
    score = criticality_rank * 18
    if data_classes:
        score += max(0, max(data_rank[value] for value in data_classes) - 2) * 7
    score += exceptioned * 14 + not_evaluated * 12
    if alternate_exposed:
        score += 24
    if weaker_alternate:
        score += 18
    if stale:
        score += 20
    return score


def _expected_exposure(
    statuses: dict[str, ControlStatus],
    *,
    stale_cache_fallback_id: str | None,
    exposed_alternate: bool,
    weaker_alternate: bool,
) -> tuple[tuple[str, ...], int]:
    primary_criticality = DependencyCriticality.HIGH
    facts = [
        ("scenario-model-unavailable", (CTRL_MODEL_EGRESS, CTRL_FALLBACK_AUTHZ, CTRL_LOCAL_SAFE_MODE), (EgressDataClass.INTERNAL,), primary_criticality, False, False, False),
        ("scenario-model-untrusted", (CTRL_MODEL_EGRESS, CTRL_FALLBACK_AUTHZ), (EgressDataClass.CONFIDENTIAL,), primary_criticality, False, exposed_alternate, weaker_alternate),
        ("scenario-model-degraded", (CTRL_MODEL_EGRESS, CTRL_FALLBACK_AUTHZ), (EgressDataClass.CONFIDENTIAL,), primary_criticality, False, False, False),
        ("scenario-telemetry-degraded", (CTRL_TELEMETRY_EGRESS, CTRL_CACHE_INTEGRITY), (EgressDataClass.INTERNAL,), DependencyCriticality.MEDIUM, stale_cache_fallback_id == "fallback-telemetry-cache", False, False),
        ("scenario-registry-unavailable", (CTRL_REGISTRY_EGRESS, CTRL_CACHE_INTEGRITY), (EgressDataClass.INTERNAL,), DependencyCriticality.HIGH, stale_cache_fallback_id == "fallback-registry-cache", False, False),
    ]
    exposed_scores: list[tuple[int, str]] = []
    for scenario_id, controls, data_classes, criticality, stale, alt_exposed, alt_weaker in facts:
        exceptioned = sum(statuses[control_id] == ControlStatus.EXCEPTIONED for control_id in controls)
        not_evaluated = sum(statuses[control_id] == ControlStatus.NOT_EVALUATED for control_id in controls)
        if exceptioned or not_evaluated or stale or alt_exposed or alt_weaker:
            exposed_scores.append((_risk_for_fact(criticality, data_classes, exceptioned, not_evaluated, stale=stale, alternate_exposed=alt_exposed, weaker_alternate=alt_weaker), scenario_id))
    exposed_scores.sort(key=lambda value: (-value[0], value[1]))
    return tuple(sorted(scenario_id for _, scenario_id in exposed_scores)), max((score for score, _ in exposed_scores), default=0)


def build_fixture(
    *,
    exceptioned_control: str | None = None,
    not_evaluated_control: str | None = None,
    stale_cache_fallback_id: str | None = None,
    exposed_alternate: bool = False,
    weaker_alternate: bool = False,
) -> dict[str, object]:
    statuses = {control_id: ControlStatus.SATISFIED for control_id in ALL_CONTROLS}
    if exceptioned_control is not None:
        statuses[exceptioned_control] = ControlStatus.EXCEPTIONED
    if not_evaluated_control is not None:
        statuses[not_evaluated_control] = ControlStatus.NOT_EVALUATED
    assessments = tuple(SimpleNamespace(control_id=control_id, status=statuses[control_id]) for control_id in ALL_CONTROLS)
    posture = SimpleNamespace(
        exact_release_identity_verified=True,
        exact_upstream_evidence_binding_verified=True,
        control_catalog_verified=True,
        status_derived_from_evidence=True,
        posture_evidence_sha256=POSTURE_SHA256,
        control_catalog_sha256=CONTROL_CATALOG_SHA256,
        assessments=assessments,
        satisfied_control_ids=tuple(sorted(key for key, value in statuses.items() if value == ControlStatus.SATISFIED)),
        exceptioned_control_ids=tuple(sorted(key for key, value in statuses.items() if value == ControlStatus.EXCEPTIONED)),
        not_evaluated_control_ids=tuple(sorted(key for key, value in statuses.items() if value == ControlStatus.NOT_EVALUATED)),
    )
    p7e = build_p7e_assessment(exposed_alternate=exposed_alternate, weaker_alternate=weaker_alternate)
    scenarios = _scenarios()
    fallbacks = _fallbacks(stale_cache_fallback_id=stale_cache_fallback_id)
    manifest = ResilienceSecurityManifest(
        resilience_plan_id=PLAN_ID,
        version=PLAN_VERSION,
        dependency_graph_sha256=DEPENDENCY_GRAPH_SHA256,
        p7e_assessment_evidence_sha256=P7E_EVIDENCE_SHA256,
        created_at_epoch=NOW - 60,
        scenarios=scenarios,
        fallbacks=fallbacks,
    )
    manifest_sha = resilience_security_manifest_digest(manifest)
    scenario_by_id = {item.scenario_id: item for item in scenarios}
    fallback_by_id = {item.fallback_id: item for item in fallbacks}
    fallback_ids_by_scenario: dict[str, frozenset[str]] = {
        scenario_id: frozenset(item.fallback_id for item in fallbacks if item.scenario_id == scenario_id)
        for scenario_id in scenario_by_id
    }
    policy = ResilienceSecurityPolicy(
        expected_resilience_plan_id=PLAN_ID,
        expected_resilience_plan_version=PLAN_VERSION,
        expected_resilience_plan_sha256=manifest_sha,
        expected_dependency_graph_sha256=DEPENDENCY_GRAPH_SHA256,
        expected_p7e_assessment_evidence_sha256=P7E_EVIDENCE_SHA256,
        expected_posture_evidence_sha256=POSTURE_SHA256,
        expected_control_catalog_sha256=CONTROL_CATALOG_SHA256,
        required_scenario_ids=frozenset(scenario_by_id),
        required_fallback_ids=frozenset(fallback_by_id),
        trusted_owner_ids=frozenset({"model-security", "tool-security", "platform-security", "security-operations"}),
        expected_dependency_by_scenario={key: value.dependency_id for key, value in scenario_by_id.items()},
        expected_failure_state_by_scenario={key: value.failure_state for key, value in scenario_by_id.items()},
        expected_required_control_ids_by_scenario={key: frozenset(value.required_control_ids) for key, value in scenario_by_id.items()},
        expected_fallback_ids_by_scenario=fallback_ids_by_scenario,
        expected_scenario_by_fallback={key: value.scenario_id for key, value in fallback_by_id.items()},
        expected_mode_by_fallback={key: value.mode for key, value in fallback_by_id.items()},
        expected_target_dependency_by_fallback={key: value.target_dependency_id for key, value in fallback_by_id.items()},
        expected_preserved_control_ids_by_fallback={key: frozenset(value.preserved_control_ids) for key, value in fallback_by_id.items()},
        expected_disabled_control_ids_by_fallback={key: frozenset(value.disabled_control_ids) for key, value in fallback_by_id.items()},
        allowed_data_classes_by_fallback={key: frozenset(value.egress_data_classes) for key, value in fallback_by_id.items()},
        allowed_secret_ids_by_fallback={key: frozenset(value.secret_ids) for key, value in fallback_by_id.items()},
        max_retry_attempts_by_fallback={key: value.retry_attempts for key, value in fallback_by_id.items()},
        max_cache_age_seconds_by_fallback={
            "fallback-model-local-safe": 0,
            "fallback-model-secondary": 0,
            "fallback-model-retry": 0,
            "fallback-tool-closed": 0,
            "fallback-idp-closed": 0,
            "fallback-telemetry-cache": 300,
            "fallback-registry-cache": 3_600,
        },
    )
    exposed_scenarios, max_risk = _expected_exposure(
        statuses,
        stale_cache_fallback_id=stale_cache_fallback_id,
        exposed_alternate=exposed_alternate,
        weaker_alternate=weaker_alternate,
    )
    request = ResilienceSecurityRequest(
        resilience_plan_id=PLAN_ID,
        resilience_plan_version=PLAN_VERSION,
        resilience_plan_sha256=manifest_sha,
        dependency_graph_sha256=DEPENDENCY_GRAPH_SHA256,
        p7e_assessment_evidence_sha256=P7E_EVIDENCE_SHA256,
        posture_evidence_sha256=POSTURE_SHA256,
        evaluated_at_epoch=NOW,
        scenario_ids=tuple(sorted(scenario_by_id)),
        declared_exposed_scenario_ids=exposed_scenarios,
        declared_max_security_risk_score=max_risk,
    )
    return {
        "p7e": p7e,
        "posture": posture,
        "manifest": manifest,
        "policy": policy,
        "request": request,
    }
