from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Mapping

P7I_INVARIANT_POLICY_VERSION = "security-architecture-invariant-blast-radius-v1"
P7I_INVARIANT_CATALOG_SCHEMA_VERSION = "aegis-security-architecture-invariant-catalog-v1"
P7I_ASSESSMENT_SCHEMA_VERSION = "aegis-cross-layer-invariant-blast-radius-assessment-v1"
P7I_ASSESSMENT_MODE = "deterministic-cross-layer-invariant-blast-radius-v1"


class InvariantSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InvariantState(StrEnum):
    HOLDS = "holds"
    DEGRADED = "degraded"
    VIOLATED = "violated"


class InvariantRejectReason(StrEnum):
    POLICY_INVALID = "policy_invalid"
    REQUEST_INVALID = "request_invalid"
    UPSTREAM_UNVERIFIED = "upstream_unverified"
    UPSTREAM_DIGEST_MISMATCH = "upstream_digest_mismatch"
    POSTURE_UNVERIFIED = "posture_unverified"
    POSTURE_DIGEST_MISMATCH = "posture_digest_mismatch"
    CONTROL_CATALOG_MISMATCH = "control_catalog_mismatch"
    CONTROL_EVIDENCE_INVALID = "control_evidence_invalid"
    CATALOG_INVALID = "catalog_invalid"
    CATALOG_DIGEST_MISMATCH = "catalog_digest_mismatch"
    CATALOG_STALE = "catalog_stale"
    CATALOG_FUTURE = "catalog_future"
    INVARIANT_DUPLICATE = "invariant_duplicate"
    INVARIANT_COVERAGE_MISMATCH = "invariant_coverage_mismatch"
    INVARIANT_OWNER_UNTRUSTED = "invariant_owner_untrusted"
    INVARIANT_SEVERITY_DOWNGRADE = "invariant_severity_downgrade"
    INVARIANT_BINDING_DRIFT = "invariant_binding_drift"
    INVARIANT_BINDING_DUPLICATE = "invariant_binding_duplicate"
    INVARIANT_BINDING_UNKNOWN = "invariant_binding_unknown"
    INVARIANT_LAYER_COVERAGE_WEAK = "invariant_layer_coverage_weak"
    INVARIANT_ASSET_DRIFT = "invariant_asset_drift"
    INVARIANT_IDENTITY_DRIFT = "invariant_identity_drift"
    INVARIANT_DEPENDENCY_DRIFT = "invariant_dependency_drift"
    INVARIANT_ROUTE_DRIFT = "invariant_route_drift"
    INVARIANT_CONTROL_DRIFT = "invariant_control_drift"
    INVARIANT_CONTROL_UNKNOWN = "invariant_control_unknown"
    INVARIANT_DESCRIPTION_EMPTY = "invariant_description_empty"
    DECLARED_STATE_MISMATCH = "declared_state_mismatch"
    DECLARED_BLAST_RADIUS_MISMATCH = "declared_blast_radius_mismatch"
    DECLARED_MAX_RISK_MISMATCH = "declared_max_risk_mismatch"


class InvariantAssessmentRejected(ValueError):
    def __init__(self, reason: InvariantRejectReason, message: str, *, invariant_id: str | None = None, binding_id: str | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.invariant_id = invariant_id
        self.binding_id = binding_id


@dataclass(frozen=True)
class ArchitectureInvariant:
    invariant_id: str
    title: str
    description: str
    owner_id: str
    severity: InvariantSeverity
    required_binding_ids: tuple[str, ...]
    protected_asset_ids: tuple[str, ...]
    affected_identity_ids: tuple[str, ...]
    dependency_ids: tuple[str, ...]
    control_plane_route_ids: tuple[str, ...]
    required_control_ids: tuple[str, ...]


@dataclass(frozen=True)
class InvariantCatalog:
    catalog_id: str
    version: str
    created_at_epoch: int
    p7a_assessment_evidence_sha256: str
    p7b_assessment_evidence_sha256: str
    p7c_assessment_evidence_sha256: str
    p7d_assessment_evidence_sha256: str
    p7e_assessment_evidence_sha256: str
    p7f_assessment_evidence_sha256: str
    p7g_assessment_evidence_sha256: str
    p7h_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    invariants: tuple[ArchitectureInvariant, ...]
    schema_version: str = P7I_INVARIANT_CATALOG_SCHEMA_VERSION


@dataclass(frozen=True)
class InvariantAssessmentRequest:
    catalog_id: str
    catalog_version: str
    catalog_sha256: str
    p7a_assessment_evidence_sha256: str
    p7b_assessment_evidence_sha256: str
    p7c_assessment_evidence_sha256: str
    p7d_assessment_evidence_sha256: str
    p7e_assessment_evidence_sha256: str
    p7f_assessment_evidence_sha256: str
    p7g_assessment_evidence_sha256: str
    p7h_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    evaluated_at_epoch: int
    invariant_ids: tuple[str, ...]
    declared_violated_invariant_ids: tuple[str, ...]
    declared_degraded_invariant_ids: tuple[str, ...]
    declared_cross_layer_blast_radius: int
    declared_max_blast_radius_score: int


@dataclass(frozen=True)
class InvariantBlastRadiusPolicy:
    expected_catalog_id: str
    expected_catalog_version: str
    expected_catalog_sha256: str
    expected_p7a_assessment_evidence_sha256: str
    expected_p7b_assessment_evidence_sha256: str
    expected_p7c_assessment_evidence_sha256: str
    expected_p7d_assessment_evidence_sha256: str
    expected_p7e_assessment_evidence_sha256: str
    expected_p7f_assessment_evidence_sha256: str
    expected_p7g_assessment_evidence_sha256: str
    expected_p7h_assessment_evidence_sha256: str
    expected_posture_evidence_sha256: str
    expected_control_catalog_sha256: str
    required_invariant_ids: frozenset[str]
    trusted_owner_ids: frozenset[str]
    minimum_severity_by_invariant: Mapping[str, InvariantSeverity]
    expected_binding_ids_by_invariant: Mapping[str, frozenset[str]]
    expected_asset_ids_by_invariant: Mapping[str, frozenset[str]]
    expected_identity_ids_by_invariant: Mapping[str, frozenset[str]]
    expected_dependency_ids_by_invariant: Mapping[str, frozenset[str]]
    expected_route_ids_by_invariant: Mapping[str, frozenset[str]]
    expected_control_ids_by_invariant: Mapping[str, frozenset[str]]
    min_distinct_layers_by_invariant: Mapping[str, int]
    max_catalog_age_seconds: int = 86_400
    max_future_skew_seconds: int = 30


@dataclass(frozen=True)
class InvariantBlastRadiusFact:
    invariant_id: str
    title: str
    severity: InvariantSeverity
    state: InvariantState
    violating_binding_ids: tuple[str, ...]
    degraded_control_ids: tuple[str, ...]
    exposed_layer_ids: tuple[str, ...]
    protected_asset_ids: tuple[str, ...]
    affected_identity_ids: tuple[str, ...]
    affected_dependency_ids: tuple[str, ...]
    affected_control_plane_route_ids: tuple[str, ...]
    blast_radius_units: int
    blast_radius_score: int
    mitigating_binding_ids: tuple[str, ...]


@dataclass(frozen=True)
class VerifiedInvariantBlastRadiusAssessment:
    catalog_id: str
    catalog_version: str
    catalog_sha256: str
    p7a_assessment_evidence_sha256: str
    p7b_assessment_evidence_sha256: str
    p7c_assessment_evidence_sha256: str
    p7d_assessment_evidence_sha256: str
    p7e_assessment_evidence_sha256: str
    p7f_assessment_evidence_sha256: str
    p7g_assessment_evidence_sha256: str
    p7h_assessment_evidence_sha256: str
    posture_evidence_sha256: str
    control_catalog_sha256: str
    invariant_count: int
    holding_invariant_count: int
    degraded_invariant_count: int
    violated_invariant_count: int
    critical_violated_invariant_count: int
    cross_layer_blast_radius: int
    max_blast_radius_score: int
    prioritized_invariant_ids: tuple[str, ...]
    invariants: tuple[InvariantBlastRadiusFact, ...]
    assessment_evidence_sha256: str
    exact_catalog_binding_verified: bool = True
    exact_p7a_binding_verified: bool = True
    exact_p7b_binding_verified: bool = True
    exact_p7c_binding_verified: bool = True
    exact_p7d_binding_verified: bool = True
    exact_p7e_binding_verified: bool = True
    exact_p7f_binding_verified: bool = True
    exact_p7g_binding_verified: bool = True
    exact_p7h_binding_verified: bool = True
    exact_p6d_posture_binding_verified: bool = True
    invariant_definitions_policy_pinned: bool = True
    cross_layer_binding_coverage_verified: bool = True
    blast_radius_derived_from_evidence: bool = True
    counterevidence_preserved: bool = True
    caller_declared_architecture_safety_trusted: bool = False
    exhaustive_attack_coverage: bool = False
    formal_end_to_end_security_proof: bool = False
    production_asset_inventory: bool = False
    production_dependency_discovery: bool = False
    production_control_plane_enforcement: bool = False
    compliance_certification: bool = False
    network_operations: int = 0
    schema_version: str = P7I_ASSESSMENT_SCHEMA_VERSION
    policy_version: str = P7I_INVARIANT_POLICY_VERSION
    assessment_mode: str = P7I_ASSESSMENT_MODE


def _reject(reason: InvariantRejectReason, message: str, **context: str | None) -> None:
    raise InvariantAssessmentRejected(reason, message, **context)


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def _rank(value: InvariantSeverity) -> int:
    return {InvariantSeverity.LOW: 1, InvariantSeverity.MEDIUM: 2, InvariantSeverity.HIGH: 3, InvariantSeverity.CRITICAL: 4}[value]


def _digest(value: object) -> str:
    return str(getattr(value, "assessment_evidence_sha256", "")).casefold()


def _status_value(value: object) -> str:
    return str(getattr(value, "value", value)).casefold()


def _verified(value: object, *flags: str) -> bool:
    return all(bool(getattr(value, flag, False)) for flag in flags)


def canonical_invariant_catalog_bytes(catalog: InvariantCatalog) -> bytes:
    document = {
        "catalog_id": catalog.catalog_id,
        "created_at_epoch": catalog.created_at_epoch,
        "invariants": [
            {
                "affected_identity_ids": sorted(item.affected_identity_ids),
                "control_plane_route_ids": sorted(item.control_plane_route_ids),
                "dependency_ids": sorted(item.dependency_ids),
                "description": item.description,
                "invariant_id": item.invariant_id,
                "owner_id": item.owner_id,
                "protected_asset_ids": sorted(item.protected_asset_ids),
                "required_binding_ids": sorted(item.required_binding_ids),
                "required_control_ids": sorted(item.required_control_ids),
                "severity": item.severity.value,
                "title": item.title,
            }
            for item in sorted(catalog.invariants, key=lambda value: value.invariant_id)
        ],
        "p7a_assessment_evidence_sha256": catalog.p7a_assessment_evidence_sha256.casefold(),
        "p7b_assessment_evidence_sha256": catalog.p7b_assessment_evidence_sha256.casefold(),
        "p7c_assessment_evidence_sha256": catalog.p7c_assessment_evidence_sha256.casefold(),
        "p7d_assessment_evidence_sha256": catalog.p7d_assessment_evidence_sha256.casefold(),
        "p7e_assessment_evidence_sha256": catalog.p7e_assessment_evidence_sha256.casefold(),
        "p7f_assessment_evidence_sha256": catalog.p7f_assessment_evidence_sha256.casefold(),
        "p7g_assessment_evidence_sha256": catalog.p7g_assessment_evidence_sha256.casefold(),
        "p7h_assessment_evidence_sha256": catalog.p7h_assessment_evidence_sha256.casefold(),
        "posture_evidence_sha256": catalog.posture_evidence_sha256.casefold(),
        "schema_version": catalog.schema_version,
        "version": catalog.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def invariant_catalog_digest(catalog: InvariantCatalog) -> str:
    return hashlib.sha256(canonical_invariant_catalog_bytes(catalog)).hexdigest()


def _validate_policy(policy: InvariantBlastRadiusPolicy) -> None:
    hashes = (
        policy.expected_catalog_sha256,
        policy.expected_p7a_assessment_evidence_sha256,
        policy.expected_p7b_assessment_evidence_sha256,
        policy.expected_p7c_assessment_evidence_sha256,
        policy.expected_p7d_assessment_evidence_sha256,
        policy.expected_p7e_assessment_evidence_sha256,
        policy.expected_p7f_assessment_evidence_sha256,
        policy.expected_p7g_assessment_evidence_sha256,
        policy.expected_p7h_assessment_evidence_sha256,
        policy.expected_posture_evidence_sha256,
        policy.expected_control_catalog_sha256,
    )
    if (
        not policy.expected_catalog_id
        or not policy.expected_catalog_version
        or not all(_is_sha256(value) for value in hashes)
        or not policy.required_invariant_ids
        or not policy.trusted_owner_ids
        or policy.max_catalog_age_seconds <= 0
        or policy.max_future_skew_seconds < 0
    ):
        _reject(InvariantRejectReason.POLICY_INVALID, "invariant policy metadata is invalid")
    maps = (
        policy.minimum_severity_by_invariant,
        policy.expected_binding_ids_by_invariant,
        policy.expected_asset_ids_by_invariant,
        policy.expected_identity_ids_by_invariant,
        policy.expected_dependency_ids_by_invariant,
        policy.expected_route_ids_by_invariant,
        policy.expected_control_ids_by_invariant,
        policy.min_distinct_layers_by_invariant,
    )
    if any(set(mapping) != set(policy.required_invariant_ids) for mapping in maps):
        _reject(InvariantRejectReason.POLICY_INVALID, "invariant policy maps must exactly cover required invariant IDs")
    for invariant_id in policy.required_invariant_ids:
        bindings = policy.expected_binding_ids_by_invariant[invariant_id]
        controls = policy.expected_control_ids_by_invariant[invariant_id]
        if not bindings or not controls or policy.min_distinct_layers_by_invariant[invariant_id] < 2:
            _reject(InvariantRejectReason.POLICY_INVALID, "invariant policy must require cross-layer evidence and controls", invariant_id=invariant_id)
        if not all(binding.startswith(("p7a:", "p7b:", "p7c:", "p7d:", "p7e:", "p7f:", "p7g:", "p7h:", "p6d:")) for binding in bindings):
            _reject(InvariantRejectReason.POLICY_INVALID, "invariant policy contains unsupported binding source", invariant_id=invariant_id)


def _collect_unique(items: tuple[object, ...], attribute: str) -> dict[str, object]:
    result: dict[str, object] = {}
    for item in items:
        object_id = str(getattr(item, attribute, ""))
        if not object_id or object_id in result:
            return {}
        result[object_id] = item
    return result


def _validate_upstreams(policy: InvariantBlastRadiusPolicy, upstreams: Mapping[str, object], posture: object) -> tuple[dict[str, dict[str, object]], dict[str, str]]:
    specs = {
        "p7a": ("expected_p7a_assessment_evidence_sha256", ("exact_architecture_binding_verified", "required_graph_coverage_verified"), "paths", "path_id"),
        "p7b": ("expected_p7b_assessment_evidence_sha256", ("exact_identity_graph_binding_verified", "privilege_amplification_derived_from_evidence"), "paths", "path_id"),
        "p7c": ("expected_p7c_assessment_evidence_sha256", ("exact_data_graph_binding_verified", "exfiltration_derived_from_evidence"), "paths", "path_id"),
        "p7d": ("expected_p7d_assessment_evidence_sha256", ("exact_secret_graph_binding_verified", "blast_radius_derived_from_evidence"), "paths", "path_id"),
        "p7e": ("expected_p7e_assessment_evidence_sha256", ("exact_dependency_graph_binding_verified", "risk_derived_from_evidence"), "paths", "path_id"),
        "p7f": ("expected_p7f_assessment_evidence_sha256", ("exact_resilience_plan_binding_verified", "security_degradation_derived_from_evidence"), "scenarios", "scenario_id"),
        "p7g": ("expected_p7g_assessment_evidence_sha256", ("exact_telemetry_plan_binding_verified", "audit_integrity_derived_from_evidence", "fallback_observability_derived_from_evidence"), "requirements", "requirement_id"),
        "p7h": ("expected_p7h_assessment_evidence_sha256", ("exact_control_plane_binding_verified", "path_risk_derived_from_evidence", "separation_of_duties_enforced"), "routes", "route_id"),
    }
    catalogs: dict[str, dict[str, object]] = {}
    for source, (policy_attr, flags, collection_attr, id_attr) in specs.items():
        evidence = upstreams[source]
        if not _verified(evidence, *flags):
            _reject(InvariantRejectReason.UPSTREAM_UNVERIFIED, f"{source.upper()} evidence is not fully verified")
        if _digest(evidence) != str(getattr(policy, policy_attr)).casefold():
            _reject(InvariantRejectReason.UPSTREAM_DIGEST_MISMATCH, f"{source.upper()} evidence digest does not match invariant policy")
        catalog = _collect_unique(tuple(getattr(evidence, collection_attr, ())), id_attr)
        if not catalog:
            _reject(InvariantRejectReason.UPSTREAM_UNVERIFIED, f"{source.upper()} object inventory is empty or malformed")
        catalogs[source] = catalog

    if not _verified(posture, "exact_release_identity_verified", "exact_upstream_evidence_binding_verified", "control_catalog_verified", "status_derived_from_evidence"):
        _reject(InvariantRejectReason.POSTURE_UNVERIFIED, "P6-D posture evidence is not fully verified")
    if str(getattr(posture, "posture_evidence_sha256", "")).casefold() != policy.expected_posture_evidence_sha256.casefold():
        _reject(InvariantRejectReason.POSTURE_DIGEST_MISMATCH, "P6-D posture digest does not match invariant policy")
    if str(getattr(posture, "control_catalog_sha256", "")).casefold() != policy.expected_control_catalog_sha256.casefold():
        _reject(InvariantRejectReason.CONTROL_CATALOG_MISMATCH, "P6-D control catalog digest does not match invariant policy")
    statuses: dict[str, str] = {}
    for assessment in tuple(getattr(posture, "assessments", ())):
        control_id = str(getattr(assessment, "control_id", ""))
        status = _status_value(getattr(assessment, "status", ""))
        if not control_id or control_id in statuses or status not in {"satisfied", "exceptioned", "not_evaluated"}:
            _reject(InvariantRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D control evidence is duplicate or malformed")
        statuses[control_id] = status
    if set(getattr(posture, "satisfied_control_ids", ())) != {key for key, value in statuses.items() if value == "satisfied"}:
        _reject(InvariantRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D satisfied-control summary is inconsistent")
    if set(getattr(posture, "exceptioned_control_ids", ())) != {key for key, value in statuses.items() if value == "exceptioned"}:
        _reject(InvariantRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D exception summary is inconsistent")
    if set(getattr(posture, "not_evaluated_control_ids", ())) != {key for key, value in statuses.items() if value == "not_evaluated"}:
        _reject(InvariantRejectReason.CONTROL_EVIDENCE_INVALID, "P6-D not-evaluated summary is inconsistent")
    catalogs["p6d"] = {key: object() for key in statuses}
    return catalogs, statuses


def _binding_exists(binding_id: str, catalogs: Mapping[str, Mapping[str, object]]) -> bool:
    if ":" not in binding_id:
        return False
    source, object_id = binding_id.split(":", 1)
    return object_id in catalogs.get(source, {})


def _unsafe(source: str, item: object, statuses: Mapping[str, str], object_id: str) -> bool:
    if source == "p6d":
        return statuses[object_id] != "satisfied"
    if source == "p7g":
        return bool(getattr(item, "blind_spot", False))
    if source == "p7c":
        return bool(getattr(item, "exposed", getattr(item, "exfiltration_possible", False)))
    return bool(getattr(item, "exposed", False))


def _validate_catalog(
    policy: InvariantBlastRadiusPolicy,
    request: InvariantAssessmentRequest,
    catalog: InvariantCatalog,
    catalogs: Mapping[str, Mapping[str, object]],
    statuses: Mapping[str, str],
) -> tuple[dict[str, ArchitectureInvariant], str]:
    if (
        catalog.schema_version != P7I_INVARIANT_CATALOG_SCHEMA_VERSION
        or catalog.catalog_id != policy.expected_catalog_id
        or catalog.version != policy.expected_catalog_version
        or not catalog.invariants
    ):
        _reject(InvariantRejectReason.CATALOG_INVALID, "invariant catalog metadata is invalid")
    expected_pins = (
        (catalog.p7a_assessment_evidence_sha256, policy.expected_p7a_assessment_evidence_sha256),
        (catalog.p7b_assessment_evidence_sha256, policy.expected_p7b_assessment_evidence_sha256),
        (catalog.p7c_assessment_evidence_sha256, policy.expected_p7c_assessment_evidence_sha256),
        (catalog.p7d_assessment_evidence_sha256, policy.expected_p7d_assessment_evidence_sha256),
        (catalog.p7e_assessment_evidence_sha256, policy.expected_p7e_assessment_evidence_sha256),
        (catalog.p7f_assessment_evidence_sha256, policy.expected_p7f_assessment_evidence_sha256),
        (catalog.p7g_assessment_evidence_sha256, policy.expected_p7g_assessment_evidence_sha256),
        (catalog.p7h_assessment_evidence_sha256, policy.expected_p7h_assessment_evidence_sha256),
        (catalog.posture_evidence_sha256, policy.expected_posture_evidence_sha256),
    )
    if any(left.casefold() != right.casefold() for left, right in expected_pins):
        _reject(InvariantRejectReason.CATALOG_INVALID, "invariant catalog upstream evidence binding is invalid")
    if catalog.created_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
        _reject(InvariantRejectReason.CATALOG_FUTURE, "invariant catalog is future-dated")
    if request.evaluated_at_epoch - catalog.created_at_epoch > policy.max_catalog_age_seconds:
        _reject(InvariantRejectReason.CATALOG_STALE, "invariant catalog is stale")
    actual_sha = invariant_catalog_digest(catalog)
    if not hmac.compare_digest(actual_sha, policy.expected_catalog_sha256.casefold()) or not hmac.compare_digest(actual_sha, request.catalog_sha256.casefold()):
        _reject(InvariantRejectReason.CATALOG_DIGEST_MISMATCH, "invariant catalog digest does not match request/policy")

    invariants: dict[str, ArchitectureInvariant] = {}
    for invariant in catalog.invariants:
        if not invariant.invariant_id or invariant.invariant_id in invariants:
            _reject(InvariantRejectReason.INVARIANT_DUPLICATE, "invariant ID is empty or duplicate", invariant_id=invariant.invariant_id or None)
        invariants[invariant.invariant_id] = invariant
    if set(invariants) != set(policy.required_invariant_ids):
        _reject(InvariantRejectReason.INVARIANT_COVERAGE_MISMATCH, "invariant coverage differs from policy")

    for invariant_id, invariant in invariants.items():
        if invariant.owner_id not in policy.trusted_owner_ids:
            _reject(InvariantRejectReason.INVARIANT_OWNER_UNTRUSTED, "invariant owner is untrusted", invariant_id=invariant_id)
        if _rank(invariant.severity) < _rank(policy.minimum_severity_by_invariant[invariant_id]):
            _reject(InvariantRejectReason.INVARIANT_SEVERITY_DOWNGRADE, "invariant severity is below policy floor", invariant_id=invariant_id)
        if not invariant.title or not invariant.description:
            _reject(InvariantRejectReason.INVARIANT_DESCRIPTION_EMPTY, "invariant title/description cannot be empty", invariant_id=invariant_id)
        if len(set(invariant.required_binding_ids)) != len(invariant.required_binding_ids):
            _reject(InvariantRejectReason.INVARIANT_BINDING_DUPLICATE, "invariant contains duplicate evidence binding", invariant_id=invariant_id)
        if set(invariant.required_binding_ids) != set(policy.expected_binding_ids_by_invariant[invariant_id]):
            _reject(InvariantRejectReason.INVARIANT_BINDING_DRIFT, "invariant evidence bindings differ from policy", invariant_id=invariant_id)
        for binding_id in invariant.required_binding_ids:
            if not _binding_exists(binding_id, catalogs):
                _reject(InvariantRejectReason.INVARIANT_BINDING_UNKNOWN, "invariant references unknown evidence object", invariant_id=invariant_id, binding_id=binding_id)
        layers = {value.split(":", 1)[0] for value in invariant.required_binding_ids}
        if len(layers) < policy.min_distinct_layers_by_invariant[invariant_id]:
            _reject(InvariantRejectReason.INVARIANT_LAYER_COVERAGE_WEAK, "invariant does not meet cross-layer coverage floor", invariant_id=invariant_id)
        if set(invariant.protected_asset_ids) != set(policy.expected_asset_ids_by_invariant[invariant_id]):
            _reject(InvariantRejectReason.INVARIANT_ASSET_DRIFT, "invariant protected assets differ from policy", invariant_id=invariant_id)
        if set(invariant.affected_identity_ids) != set(policy.expected_identity_ids_by_invariant[invariant_id]):
            _reject(InvariantRejectReason.INVARIANT_IDENTITY_DRIFT, "invariant identity blast-radius set differs from policy", invariant_id=invariant_id)
        if set(invariant.dependency_ids) != set(policy.expected_dependency_ids_by_invariant[invariant_id]):
            _reject(InvariantRejectReason.INVARIANT_DEPENDENCY_DRIFT, "invariant dependency blast-radius set differs from policy", invariant_id=invariant_id)
        if set(invariant.control_plane_route_ids) != set(policy.expected_route_ids_by_invariant[invariant_id]):
            _reject(InvariantRejectReason.INVARIANT_ROUTE_DRIFT, "invariant control-plane route set differs from policy", invariant_id=invariant_id)
        if set(invariant.required_control_ids) != set(policy.expected_control_ids_by_invariant[invariant_id]):
            _reject(InvariantRejectReason.INVARIANT_CONTROL_DRIFT, "invariant required controls differ from policy", invariant_id=invariant_id)
        if any(control_id not in statuses for control_id in invariant.required_control_ids):
            _reject(InvariantRejectReason.INVARIANT_CONTROL_UNKNOWN, "invariant references unknown P6-D control", invariant_id=invariant_id)
    return invariants, actual_sha


def _blast_score(severity: InvariantSeverity, state: InvariantState, layer_count: int, blast_units: int, violating_count: int) -> int:
    base = {InvariantSeverity.LOW: 20, InvariantSeverity.MEDIUM: 40, InvariantSeverity.HIGH: 65, InvariantSeverity.CRITICAL: 85}[severity]
    if state == InvariantState.HOLDS:
        return 0
    state_weight = 10 if state == InvariantState.DEGRADED else 25
    return base + state_weight + max(0, layer_count - 1) * 8 + max(0, blast_units - 1) * 3 + max(0, violating_count - 1) * 4


class SecurityArchitectureInvariantAnalyzer:
    def __init__(self, policy: InvariantBlastRadiusPolicy) -> None:
        _validate_policy(policy)
        self.policy = policy

    def evaluate(
        self,
        request: InvariantAssessmentRequest,
        catalog: InvariantCatalog,
        p7a_assessment: object,
        p7b_assessment: object,
        p7c_assessment: object,
        p7d_assessment: object,
        p7e_assessment: object,
        p7f_assessment: object,
        p7g_assessment: object,
        p7h_assessment: object,
        posture: object,
    ) -> VerifiedInvariantBlastRadiusAssessment:
        request_pins = (
            request.catalog_sha256,
            request.p7a_assessment_evidence_sha256,
            request.p7b_assessment_evidence_sha256,
            request.p7c_assessment_evidence_sha256,
            request.p7d_assessment_evidence_sha256,
            request.p7e_assessment_evidence_sha256,
            request.p7f_assessment_evidence_sha256,
            request.p7g_assessment_evidence_sha256,
            request.p7h_assessment_evidence_sha256,
            request.posture_evidence_sha256,
        )
        expected_pins = (
            self.policy.expected_catalog_sha256,
            self.policy.expected_p7a_assessment_evidence_sha256,
            self.policy.expected_p7b_assessment_evidence_sha256,
            self.policy.expected_p7c_assessment_evidence_sha256,
            self.policy.expected_p7d_assessment_evidence_sha256,
            self.policy.expected_p7e_assessment_evidence_sha256,
            self.policy.expected_p7f_assessment_evidence_sha256,
            self.policy.expected_p7g_assessment_evidence_sha256,
            self.policy.expected_p7h_assessment_evidence_sha256,
            self.policy.expected_posture_evidence_sha256,
        )
        if (
            request.catalog_id != self.policy.expected_catalog_id
            or request.catalog_version != self.policy.expected_catalog_version
            or not all(_is_sha256(value) for value in request_pins)
            or any(left.casefold() != right.casefold() for left, right in zip(request_pins, expected_pins))
            or set(request.invariant_ids) != set(self.policy.required_invariant_ids)
            or len(set(request.invariant_ids)) != len(request.invariant_ids)
        ):
            _reject(InvariantRejectReason.REQUEST_INVALID, "invariant assessment request identity/evidence/scope is invalid")

        upstreams = {
            "p7a": p7a_assessment,
            "p7b": p7b_assessment,
            "p7c": p7c_assessment,
            "p7d": p7d_assessment,
            "p7e": p7e_assessment,
            "p7f": p7f_assessment,
            "p7g": p7g_assessment,
            "p7h": p7h_assessment,
        }
        catalogs, statuses = _validate_upstreams(self.policy, upstreams, posture)
        invariants, catalog_sha = _validate_catalog(self.policy, request, catalog, catalogs, statuses)

        facts: list[InvariantBlastRadiusFact] = []
        all_blast_entities: set[str] = set()
        for invariant_id in sorted(invariants):
            invariant = invariants[invariant_id]
            violating: list[str] = []
            mitigating: list[str] = []
            degraded_controls = tuple(sorted(control_id for control_id in invariant.required_control_ids if statuses[control_id] != "satisfied"))
            for binding_id in sorted(invariant.required_binding_ids):
                source, object_id = binding_id.split(":", 1)
                item = catalogs[source][object_id]
                if _unsafe(source, item, statuses, object_id):
                    violating.append(binding_id)
                else:
                    mitigating.append(binding_id)
            non_control_violations = [value for value in violating if not value.startswith("p6d:")]
            if non_control_violations:
                state = InvariantState.VIOLATED
            elif degraded_controls:
                state = InvariantState.DEGRADED
            else:
                state = InvariantState.HOLDS
            exposed_layers = tuple(sorted({value.split(":", 1)[0] for value in violating}))
            blast_entities = {
                *(f"asset:{value}" for value in invariant.protected_asset_ids),
                *(f"identity:{value}" for value in invariant.affected_identity_ids),
                *(f"dependency:{value}" for value in invariant.dependency_ids),
                *(f"route:{value}" for value in invariant.control_plane_route_ids),
            }
            blast_units = len(blast_entities) if state != InvariantState.HOLDS else 0
            if state != InvariantState.HOLDS:
                all_blast_entities.update(blast_entities)
            score = _blast_score(invariant.severity, state, len(exposed_layers), blast_units, len(violating))
            facts.append(
                InvariantBlastRadiusFact(
                    invariant_id=invariant_id,
                    title=invariant.title,
                    severity=invariant.severity,
                    state=state,
                    violating_binding_ids=tuple(violating),
                    degraded_control_ids=degraded_controls,
                    exposed_layer_ids=exposed_layers,
                    protected_asset_ids=tuple(sorted(invariant.protected_asset_ids)),
                    affected_identity_ids=tuple(sorted(invariant.affected_identity_ids)),
                    affected_dependency_ids=tuple(sorted(invariant.dependency_ids)),
                    affected_control_plane_route_ids=tuple(sorted(invariant.control_plane_route_ids)),
                    blast_radius_units=blast_units,
                    blast_radius_score=score,
                    mitigating_binding_ids=tuple(mitigating),
                )
            )

        violated = tuple(item.invariant_id for item in facts if item.state == InvariantState.VIOLATED)
        degraded = tuple(item.invariant_id for item in facts if item.state == InvariantState.DEGRADED)
        blast_radius = len(all_blast_entities)
        max_score = max((item.blast_radius_score for item in facts), default=0)
        prioritized = tuple(item.invariant_id for item in sorted((item for item in facts if item.state != InvariantState.HOLDS), key=lambda value: (-value.blast_radius_score, value.invariant_id)))
        if set(request.declared_violated_invariant_ids) != set(violated) or set(request.declared_degraded_invariant_ids) != set(degraded):
            _reject(InvariantRejectReason.DECLARED_STATE_MISMATCH, "caller-declared invariant states differ from derived evidence")
        if request.declared_cross_layer_blast_radius != blast_radius:
            _reject(InvariantRejectReason.DECLARED_BLAST_RADIUS_MISMATCH, "caller-declared cross-layer blast radius differs from derived evidence")
        if request.declared_max_blast_radius_score != max_score:
            _reject(InvariantRejectReason.DECLARED_MAX_RISK_MISMATCH, "caller-declared maximum blast-radius score differs from derived evidence")

        evidence_document = {
            "catalog_sha256": catalog_sha,
            "control_catalog_sha256": str(getattr(posture, "control_catalog_sha256", "")).casefold(),
            "cross_layer_blast_radius": blast_radius,
            "invariants": [asdict(item) for item in facts],
            "p7a_assessment_evidence_sha256": _digest(p7a_assessment),
            "p7b_assessment_evidence_sha256": _digest(p7b_assessment),
            "p7c_assessment_evidence_sha256": _digest(p7c_assessment),
            "p7d_assessment_evidence_sha256": _digest(p7d_assessment),
            "p7e_assessment_evidence_sha256": _digest(p7e_assessment),
            "p7f_assessment_evidence_sha256": _digest(p7f_assessment),
            "p7g_assessment_evidence_sha256": _digest(p7g_assessment),
            "p7h_assessment_evidence_sha256": _digest(p7h_assessment),
            "posture_evidence_sha256": str(getattr(posture, "posture_evidence_sha256", "")).casefold(),
            "prioritized_invariant_ids": list(prioritized),
        }
        assessment_sha = hashlib.sha256(json.dumps(evidence_document, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()
        return VerifiedInvariantBlastRadiusAssessment(
            catalog_id=catalog.catalog_id,
            catalog_version=catalog.version,
            catalog_sha256=catalog_sha,
            p7a_assessment_evidence_sha256=_digest(p7a_assessment),
            p7b_assessment_evidence_sha256=_digest(p7b_assessment),
            p7c_assessment_evidence_sha256=_digest(p7c_assessment),
            p7d_assessment_evidence_sha256=_digest(p7d_assessment),
            p7e_assessment_evidence_sha256=_digest(p7e_assessment),
            p7f_assessment_evidence_sha256=_digest(p7f_assessment),
            p7g_assessment_evidence_sha256=_digest(p7g_assessment),
            p7h_assessment_evidence_sha256=_digest(p7h_assessment),
            posture_evidence_sha256=str(getattr(posture, "posture_evidence_sha256", "")).casefold(),
            control_catalog_sha256=str(getattr(posture, "control_catalog_sha256", "")).casefold(),
            invariant_count=len(facts),
            holding_invariant_count=sum(item.state == InvariantState.HOLDS for item in facts),
            degraded_invariant_count=len(degraded),
            violated_invariant_count=len(violated),
            critical_violated_invariant_count=sum(item.state == InvariantState.VIOLATED and item.severity == InvariantSeverity.CRITICAL for item in facts),
            cross_layer_blast_radius=blast_radius,
            max_blast_radius_score=max_score,
            prioritized_invariant_ids=prioritized,
            invariants=tuple(facts),
            assessment_evidence_sha256=assessment_sha,
        )
