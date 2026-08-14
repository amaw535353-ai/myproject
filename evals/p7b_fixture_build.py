from __future__ import annotations

from dataclasses import replace

from aegis.architecture.privilege_paths import (
    CapabilitySensitivity, IdentityCapabilityManifest, PrivilegePathPolicy, PrivilegePathRequest,
    PrivilegeTier, identity_capability_manifest_digest,
)
from aegis.assurance.posture_reporting import ControlStatus, VerifiedSecurityPosture
from .p7b_fixture_defs import *
from .p7b_fixture_defs import _architecture, _architecture_digest
from .p7b_fixture_identity import _assessment, _identity_manifest, _posture, _secret_path_id

def _policy(identity: IdentityCapabilityManifest, architecture: ArchitectureManifest) -> PrivilegePathPolicy:
    principals = {p.principal_id: p for p in identity.principals}
    capabilities = {c.capability_id: c for c in identity.capabilities}
    transitions = {e.edge_id: e for e in identity.transitions}
    return PrivilegePathPolicy(
        expected_identity_graph_id=identity.identity_graph_id,
        expected_identity_graph_version=identity.version,
        expected_identity_graph_sha256=identity_capability_manifest_digest(identity),
        expected_architecture_sha256=_architecture_digest(architecture),
        expected_p7a_assessment_evidence_sha256=P7A_EVIDENCE_SHA,
        expected_posture_evidence_sha256=POSTURE_EVIDENCE_SHA,
        expected_control_catalog_sha256=CONTROL_CATALOG_SHA,
        required_principal_ids=frozenset(principals),
        required_capability_ids=frozenset(capabilities),
        required_transition_ids=frozenset(transitions),
        entry_principal_ids=frozenset({"external-user-principal", "registry-publisher-principal"}),
        target_capability_ids=frozenset({CAP_READ_SECRET, CAP_LOAD_MODEL}),
        trusted_owner_ids=frozenset({"external", "platform", "ai-security", "model-security"}),
        expected_home_asset_by_principal={k: v.home_asset_id for k, v in principals.items()},
        expected_type_by_principal={k: v.principal_type for k, v in principals.items()},
        expected_tier_by_principal={k: v.privilege_tier for k, v in principals.items()},
        expected_scope_by_principal={k: v.privilege_scope for k, v in principals.items()},
        expected_native_capabilities_by_principal={k: frozenset(v.native_capability_ids) for k, v in principals.items()},
        expected_target_asset_by_capability={k: v.target_asset_id for k, v in capabilities.items()},
        minimum_sensitivity_by_capability={k: v.sensitivity for k, v in capabilities.items()},
        minimum_tier_by_capability={k: v.minimum_privilege_tier for k, v in capabilities.items()},
        expected_transition_endpoints={k: (v.source_principal_id, v.target_principal_id) for k, v in transitions.items()},
        expected_flow_ids_by_transition={k: tuple(v.via_flow_ids) for k, v in transitions.items()},
        expected_control_ids_by_transition={k: frozenset(v.required_control_ids) for k, v in transitions.items()},
        expected_granted_capability_ids_by_transition={k: frozenset(v.granted_capability_ids) for k, v in transitions.items()},
        max_manifest_age_seconds=3_600,
        max_future_skew_seconds=30,
        max_path_hops=8,
        max_paths=128,
    )


def build_fixture(tool_status: ControlStatus = ControlStatus.EXCEPTIONED):
    architecture = _architecture()
    arch_sha = _architecture_digest(architecture)
    identity = _identity_manifest(arch_sha)
    posture = _posture(tool_status)
    assessment = _assessment(posture.control_catalog_sha256, posture.posture_evidence_sha256, architecture)
    exposed = () if tool_status == ControlStatus.SATISFIED else (_secret_path_id(),)
    max_risk = {ControlStatus.EXCEPTIONED: 139, ControlStatus.NOT_EVALUATED: 134, ControlStatus.SATISFIED: 0}[tool_status]
    request = PrivilegePathRequest(
        identity_graph_id=identity.identity_graph_id,
        identity_graph_version=identity.version,
        identity_graph_sha256=identity_capability_manifest_digest(identity),
        architecture_sha256=arch_sha,
        p7a_assessment_evidence_sha256=assessment.assessment_evidence_sha256,
        posture_evidence_sha256=posture.posture_evidence_sha256,
        entry_principal_ids=("external-user-principal", "registry-publisher-principal"),
        target_capability_ids=(CAP_LOAD_MODEL, CAP_READ_SECRET),
        evaluated_at_epoch=EVALUATION_EPOCH,
        declared_exposed_path_ids=exposed,
        declared_max_exposed_risk_score=max_risk,
    )
    return {"architecture": architecture, "identity": identity, "posture": posture, "assessment": assessment, "policy": _policy(identity, architecture), "request": request}


def _replace_principal(manifest: IdentityCapabilityManifest, principal_id: str, **changes):
    return replace(manifest, principals=tuple(replace(p, **changes) if p.principal_id == principal_id else p for p in manifest.principals))

def _replace_capability(manifest: IdentityCapabilityManifest, capability_id: str, **changes):
    return replace(manifest, capabilities=tuple(replace(c, **changes) if c.capability_id == capability_id else c for c in manifest.capabilities))

def _replace_transition(manifest: IdentityCapabilityManifest, edge_id: str, **changes):
    return replace(manifest, transitions=tuple(replace(e, **changes) if e.edge_id == edge_id else e for e in manifest.transitions))

def _repin_identity(fixture: dict, identity: IdentityCapabilityManifest) -> dict:
    digest = identity_capability_manifest_digest(identity)
    fixture["identity"] = identity
    fixture["policy"] = replace(fixture["policy"], expected_identity_graph_sha256=digest)
    fixture["request"] = replace(fixture["request"], identity_graph_sha256=digest)
    return fixture

def _replace_posture_assessments(posture: VerifiedSecurityPosture, assessments):
    assessments = tuple(assessments)
    return replace(
        posture,
        control_count=len(assessments),
        satisfied_control_ids=tuple(sorted(a.control_id for a in assessments if a.status == ControlStatus.SATISFIED)),
        exceptioned_control_ids=tuple(sorted(a.control_id for a in assessments if a.status == ControlStatus.EXCEPTIONED)),
        not_evaluated_control_ids=tuple(sorted(a.control_id for a in assessments if a.status == ControlStatus.NOT_EVALUATED)),
        assessments=assessments,
    )
