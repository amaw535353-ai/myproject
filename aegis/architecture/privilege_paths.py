from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import Mapping

from aegis.assurance.posture_reporting import ControlStatus, VerifiedSecurityPosture
from .attack_paths import ArchitectureManifest, VerifiedAttackPathAssessment
from .privilege_types import *
from .privilege_core import (
    canonical_identity_capability_manifest_bytes,
    identity_capability_manifest_digest,
    privilege_path_identifier,
    _reject,
    _scope_rank,
    _sensitivity_rank,
    _tier_rank,
    _validate_policy,
    _validate_request,
)
from .privilege_evidence import _posture_controls, _validate_architecture
from .privilege_manifest import _validate_identity_manifest

def _path_fact(
    entry_principal_id: str,
    target_capability: Capability,
    principal_ids: tuple[str, ...],
    transition_ids: tuple[str, ...],
    *,
    principals: Mapping[str, IdentityPrincipal],
    transitions: Mapping[str, PrivilegeTransition],
    controls: Mapping[str, ControlStatus],
) -> PrivilegePathFact:
    tier_values = tuple(principals[item].privilege_tier for item in principal_ids)
    scope_values = tuple(principals[item].privilege_scope for item in principal_ids)
    privilege_increase = max(0, max(_tier_rank(item) for item in tier_values) - _tier_rank(tier_values[0]))
    scope_increase = max(0, max(_scope_rank(item) for item in scope_values) - _scope_rank(scope_values[0]))
    satisfied: set[str] = set()
    exceptioned: set[str] = set()
    not_evaluated: set[str] = set()
    architecture_flow_ids: list[str] = []
    for edge_id in transition_ids:
        edge = transitions[edge_id]
        architecture_flow_ids.extend(edge.via_flow_ids)
        for control_id in edge.required_control_ids:
            status = controls[control_id]
            if status == ControlStatus.SATISFIED:
                satisfied.add(control_id)
            elif status == ControlStatus.EXCEPTIONED:
                exceptioned.add(control_id)
            else:
                not_evaluated.add(control_id)

    exposed = bool((privilege_increase or scope_increase or _sensitivity_rank(target_capability.sensitivity) >= 3) and (exceptioned or not_evaluated))
    risk_score = (
        _sensitivity_rank(target_capability.sensitivity) * 20
        + privilege_increase * 7
        + scope_increase * 5
        + len(exceptioned) * 12
        + len(not_evaluated) * 7
        + max(0, 8 - len(transition_ids))
    )
    reasons = tuple(
        sorted(
            [f"exceptioned_control:{item}" for item in exceptioned]
            + [f"not_evaluated_control:{item}" for item in not_evaluated]
        )
    )
    return PrivilegePathFact(
        path_id=privilege_path_identifier(entry_principal_id, target_capability.capability_id, principal_ids, transition_ids),
        entry_principal_id=entry_principal_id,
        final_principal_id=principal_ids[-1],
        target_capability_id=target_capability.capability_id,
        principal_ids=principal_ids,
        transition_ids=transition_ids,
        architecture_flow_ids=tuple(architecture_flow_ids),
        privilege_tier_sequence=tuple(item.value for item in tier_values),
        privilege_scope_sequence=tuple(item.value for item in scope_values),
        privilege_increase=privilege_increase,
        scope_increase=scope_increase,
        satisfied_control_ids=tuple(sorted(satisfied)),
        exceptioned_control_ids=tuple(sorted(exceptioned)),
        not_evaluated_control_ids=tuple(sorted(not_evaluated)),
        capability_sensitivity=target_capability.sensitivity,
        exposed=exposed,
        risk_score=risk_score,
        exposure_reasons=reasons,
        mitigating_control_ids=tuple(sorted(satisfied)),
    )


def _enumerate_privilege_paths(
    *,
    principals: Mapping[str, IdentityPrincipal],
    capabilities: Mapping[str, Capability],
    transitions: Mapping[str, PrivilegeTransition],
    controls: Mapping[str, ControlStatus],
    policy: PrivilegePathPolicy,
) -> tuple[PrivilegePathFact, ...]:
    adjacency: dict[str, list[PrivilegeTransition]] = {principal_id: [] for principal_id in principals}
    for edge in transitions.values():
        adjacency[edge.source_principal_id].append(edge)
    for outgoing in adjacency.values():
        outgoing.sort(key=lambda item: item.edge_id)

    results: list[PrivilegePathFact] = []
    truncated = False

    def walk(
        entry: str,
        current: str,
        principal_path: tuple[str, ...],
        edge_path: tuple[str, ...],
        acquired_capabilities: frozenset[str],
        newly_acquired_capabilities: frozenset[str],
        visited: frozenset[str],
    ) -> None:
        nonlocal truncated
        for target_capability_id in sorted(policy.target_capability_ids & newly_acquired_capabilities):
            capability = capabilities[target_capability_id]
            results.append(
                _path_fact(
                    entry,
                    capability,
                    principal_path,
                    edge_path,
                    principals=principals,
                    transitions=transitions,
                    controls=controls,
                )
            )
            if len(results) > policy.max_paths:
                _reject(PrivilegePathRejectReason.PATH_LIMIT_EXCEEDED, "identity graph produced more privilege paths than policy permits")

        outgoing = [edge for edge in adjacency.get(current, ()) if edge.target_principal_id not in visited]
        if len(edge_path) >= policy.max_path_hops:
            if outgoing:
                truncated = True
            return
        for edge in outgoing:
            target = edge.target_principal_id
            target_native = frozenset(principals[target].native_capability_ids)
            candidate_capabilities = frozenset(edge.granted_capability_ids) | target_native
            newly_acquired = candidate_capabilities - acquired_capabilities
            walk(
                entry,
                target,
                principal_path + (target,),
                edge_path + (edge.edge_id,),
                acquired_capabilities | candidate_capabilities,
                newly_acquired,
                visited | frozenset({target}),
            )

    for entry in sorted(policy.entry_principal_ids):
        initial_capabilities = frozenset(principals[entry].native_capability_ids)
        walk(entry, entry, (entry,), (), initial_capabilities, initial_capabilities, frozenset({entry}))
    if truncated:
        _reject(PrivilegePathRejectReason.PATH_LIMIT_EXCEEDED, "privilege-path hop bound truncated a reachable identity frontier")

    unique: dict[str, PrivilegePathFact] = {}
    for path in results:
        if path.path_id in unique:
            continue
        unique[path.path_id] = path
    return tuple(sorted(unique.values(), key=lambda item: item.path_id))


class IdentityPrivilegeCapabilityAnalyzer:
    """Map synthetic identity delegation and capability escalation over P7-A/P6-D evidence.

    The analyzer models authorized delegation and privilege amplification; it does not discover
    real IAM state, test credentials, impersonate identities, or prove production exploitability.
    """

    def __init__(self, policy: PrivilegePathPolicy) -> None:
        self._policy = policy

    def evaluate(
        self,
        request: PrivilegePathRequest,
        identity_manifest: IdentityCapabilityManifest,
        architecture: ArchitectureManifest,
        p7a_assessment: VerifiedAttackPathAssessment,
        posture: VerifiedSecurityPosture,
    ) -> VerifiedPrivilegeEscalationAssessment:
        _validate_policy(self._policy)
        _validate_request(request, self._policy)
        architecture_assets, architecture_flows = _validate_architecture(
            architecture,
            p7a_assessment,
            posture,
            request=request,
            policy=self._policy,
        )
        controls = _posture_controls(posture)
        principals, capabilities, transitions, manifest_sha = _validate_identity_manifest(
            identity_manifest,
            architecture_assets=architecture_assets,
            architecture_flows=architecture_flows,
            controls=controls,
            request=request,
            policy=self._policy,
        )
        paths = _enumerate_privilege_paths(
            principals=principals,
            capabilities=capabilities,
            transitions=transitions,
            controls=controls,
            policy=self._policy,
        )
        exposed = tuple(path for path in paths if path.exposed)
        controlled = tuple(path for path in paths if not path.exposed)
        critical_exposed = tuple(
            path for path in exposed if path.capability_sensitivity == CapabilitySensitivity.CRITICAL
        )
        prioritized = tuple(
            path.path_id
            for path in sorted(
                exposed,
                key=lambda item: (-item.risk_score, item.target_capability_id, item.path_id),
            )
        )
        max_risk = max((path.risk_score for path in exposed), default=0)
        if set(request.declared_exposed_path_ids) != set(prioritized):
            _reject(PrivilegePathRejectReason.DECLARED_PATH_MISMATCH, "caller-declared exposed privilege paths differ from evidence-derived paths")
        if request.declared_max_exposed_risk_score != max_risk:
            _reject(PrivilegePathRejectReason.DECLARED_RISK_MISMATCH, "caller-declared privilege risk differs from evidence-derived risk")

        evidence_document = {
            "architecture_sha256": request.architecture_sha256.casefold(),
            "control_catalog_sha256": posture.control_catalog_sha256.casefold(),
            "entry_principal_ids": sorted(request.entry_principal_ids),
            "exposed_path_ids": list(prioritized),
            "identity_graph_sha256": manifest_sha,
            "max_exposed_risk_score": max_risk,
            "p7a_assessment_evidence_sha256": p7a_assessment.assessment_evidence_sha256.casefold(),
            "path_facts": [asdict(path) for path in paths],
            "posture_evidence_sha256": posture.posture_evidence_sha256.casefold(),
            "target_capability_ids": sorted(request.target_capability_ids),
        }
        for item in evidence_document["path_facts"]:
            item["capability_sensitivity"] = str(item["capability_sensitivity"])
        evidence_sha = hashlib.sha256(
            json.dumps(evidence_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        return VerifiedPrivilegeEscalationAssessment(
            identity_graph_id=identity_manifest.identity_graph_id,
            identity_graph_version=identity_manifest.version,
            identity_graph_sha256=manifest_sha,
            architecture_sha256=request.architecture_sha256.casefold(),
            p7a_assessment_evidence_sha256=p7a_assessment.assessment_evidence_sha256.casefold(),
            posture_evidence_sha256=posture.posture_evidence_sha256.casefold(),
            control_catalog_sha256=posture.control_catalog_sha256.casefold(),
            entry_principal_ids=tuple(sorted(request.entry_principal_ids)),
            target_capability_ids=tuple(sorted(request.target_capability_ids)),
            topology_path_count=len(paths),
            exposed_path_count=len(exposed),
            controlled_path_count=len(controlled),
            critical_exposed_path_count=len(critical_exposed),
            max_exposed_risk_score=max_risk,
            prioritized_exposed_path_ids=prioritized,
            paths=paths,
            assessment_evidence_sha256=evidence_sha,
        )
