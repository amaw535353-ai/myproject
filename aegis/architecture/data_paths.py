from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import Mapping

from aegis.assurance.posture_reporting import ControlStatus, VerifiedSecurityPosture

from .attack_paths import ArchitectureManifest, VerifiedAttackPathAssessment
from .data_evidence import validate_upstream_evidence
from .data_manifest import (
    classification_rank,
    reject,
    validate_architecture,
    validate_manifest,
    validate_policy,
    validate_request,
)
from .data_types import (
    DataClassification,
    DataFlowEdge,
    DataFlowManifest,
    DataObject,
    DataPathFact,
    DataPathPolicy,
    DataPathRejectReason,
    DataPathRequest,
    DataTransform,
    VerifiedDataExfiltrationAssessment,
)
from .privilege_types import VerifiedPrivilegeEscalationAssessment


def data_path_identifier(
    data_id: str,
    origin_asset_id: str,
    target_sink_asset_id: str,
    asset_ids: tuple[str, ...],
    edge_ids: tuple[str, ...],
) -> str:
    document = {
        "asset_ids": list(asset_ids),
        "data_id": data_id,
        "edge_ids": list(edge_ids),
        "origin_asset_id": origin_asset_id,
        "target_sink_asset_id": target_sink_asset_id,
    }
    digest = hashlib.sha256(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"data-path-{digest[:20]}"


def _path_fact(
    *,
    data: DataObject,
    edge_path: tuple[DataFlowEdge, ...],
    controls: Mapping[str, ControlStatus],
    policy: DataPathPolicy,
) -> DataPathFact:
    asset_ids = (edge_path[0].source_asset_id,) + tuple(item.target_asset_id for item in edge_path)
    edge_ids = tuple(item.edge_id for item in edge_path)
    flow_ids = tuple(flow_id for item in edge_path for flow_id in item.via_flow_ids)
    tenant_sequence = (data.tenant_id,) + tuple(item.destination_tenant_id for item in edge_path)
    transform_sequence = tuple(item.transform.value for item in edge_path)

    satisfied: set[str] = set()
    exceptioned: set[str] = set()
    not_evaluated: set[str] = set()
    tenant_violations: list[str] = []
    for edge in edge_path:
        if edge.destination_tenant_id not in policy.allowed_destination_tenants_by_data[data.data_id]:
            tenant_violations.append(edge.edge_id)
        for control_id in edge.required_control_ids:
            status = controls[control_id]
            if status == ControlStatus.SATISFIED:
                satisfied.add(control_id)
            elif status == ControlStatus.EXCEPTIONED:
                exceptioned.add(control_id)
            else:
                not_evaluated.add(control_id)

    sink = edge_path[-1].target_asset_id
    final_transform = edge_path[-1].transform
    sink_allowed = sink in policy.allowed_sink_assets_by_data[data.data_id]
    final_transform_allowed = final_transform in policy.allowed_final_transforms_by_sink_asset[sink]
    ceiling = policy.max_classification_by_sink_asset[sink]
    transformed_payload = final_transform in {
        DataTransform.REDACTED,
        DataTransform.AGGREGATED,
        DataTransform.TOKENIZED,
    }
    classification_allowed = (
        classification_rank(data.classification) <= classification_rank(ceiling)
        or (transformed_payload and final_transform_allowed)
    )
    external_egress = sink in policy.egress_sink_asset_ids

    reasons = (
        [f"tenant_boundary_violation:{edge_id}" for edge_id in tenant_violations]
        + ([] if sink_allowed else [f"sink_not_authorized:{sink}"])
        + ([] if classification_allowed else [f"classification_exceeds_sink:{sink}"])
        + ([] if final_transform_allowed else [f"final_transform_not_authorized:{final_transform.value}"])
        + [f"exceptioned_control:{item}" for item in sorted(exceptioned)]
        + [f"not_evaluated_control:{item}" for item in sorted(not_evaluated)]
    )
    exposed = bool(reasons)
    risk_score = (
        5
        + classification_rank(data.classification) * 20
        + len(edge_path) * 2
        + (12 if external_egress else 0)
        + len(tenant_violations) * 20
        + (0 if sink_allowed else 16)
        + (0 if classification_allowed else 18)
        + (0 if final_transform_allowed else 12)
        + len(exceptioned) * 10
        + len(not_evaluated) * 6
    )

    return DataPathFact(
        path_id=data_path_identifier(data.data_id, data.origin_asset_id, sink, asset_ids, edge_ids),
        data_id=data.data_id,
        origin_asset_id=data.origin_asset_id,
        target_sink_asset_id=sink,
        asset_ids=asset_ids,
        edge_ids=edge_ids,
        architecture_flow_ids=flow_ids,
        tenant_sequence=tenant_sequence,
        transform_sequence=transform_sequence,
        classification=data.classification,
        data_kind=data.data_kind,
        satisfied_control_ids=tuple(sorted(satisfied)),
        exceptioned_control_ids=tuple(sorted(exceptioned)),
        not_evaluated_control_ids=tuple(sorted(not_evaluated)),
        tenant_violation_edge_ids=tuple(tenant_violations),
        sink_allowed=sink_allowed,
        classification_allowed=classification_allowed,
        final_transform_allowed=final_transform_allowed,
        external_egress=external_egress,
        exposed=exposed,
        risk_score=risk_score,
        exposure_reasons=tuple(sorted(reasons)),
        mitigating_control_ids=tuple(sorted(satisfied)),
    )


def _enumerate_paths(
    *,
    data_objects: Mapping[str, DataObject],
    edges: Mapping[str, DataFlowEdge],
    controls: Mapping[str, ControlStatus],
    policy: DataPathPolicy,
) -> tuple[DataPathFact, ...]:
    adjacency: dict[tuple[str, str], list[DataFlowEdge]] = {}
    for edge in edges.values():
        adjacency.setdefault((edge.data_id, edge.source_asset_id), []).append(edge)
    for outgoing in adjacency.values():
        outgoing.sort(key=lambda item: item.edge_id)

    results: list[DataPathFact] = []
    truncated = False

    def walk(
        data: DataObject,
        current_asset: str,
        edge_path: tuple[DataFlowEdge, ...],
        visited_assets: frozenset[str],
    ) -> None:
        nonlocal truncated
        if current_asset in policy.target_sink_asset_ids and edge_path:
            results.append(
                _path_fact(data=data, edge_path=edge_path, controls=controls, policy=policy)
            )
            if len(results) > policy.max_paths:
                reject(DataPathRejectReason.PATH_LIMIT_EXCEEDED, "data topology produced more paths than policy permits")
            return

        outgoing = [
            edge
            for edge in adjacency.get((data.data_id, current_asset), ())
            if edge.target_asset_id not in visited_assets
        ]
        if len(edge_path) >= policy.max_path_hops:
            if outgoing:
                truncated = True
            return
        for edge in outgoing:
            walk(
                data,
                edge.target_asset_id,
                edge_path + (edge,),
                visited_assets | frozenset({edge.target_asset_id}),
            )

    for data_id in sorted(policy.entry_data_ids):
        data = data_objects[data_id]
        walk(data, data.origin_asset_id, (), frozenset({data.origin_asset_id}))

    if truncated:
        reject(DataPathRejectReason.PATH_LIMIT_EXCEEDED, "data-path hop bound truncated a reachable topology frontier")

    unique: dict[str, DataPathFact] = {}
    for path in results:
        if path.path_id in unique:
            reject(DataPathRejectReason.PATH_LIMIT_EXCEEDED, "deterministic data-path identifier collision detected")
        unique[path.path_id] = path
    return tuple(sorted(unique.values(), key=lambda item: item.path_id))


class TenantIsolationExfiltrationAnalyzer:
    """Derive synthetic tenant-isolation and exfiltration paths from pinned evidence.

    This analyzer does not read production data or execute exfiltration. It checks a canonical
    data-flow graph against policy-pinned tenant ownership, classification floors, approved sinks,
    transforms, P7-A architecture evidence, P7-B privilege evidence, and P6-D control status.
    """

    def __init__(self, policy: DataPathPolicy) -> None:
        self._policy = policy

    def evaluate(
        self,
        request: DataPathRequest,
        manifest: DataFlowManifest,
        architecture: ArchitectureManifest,
        p7a_assessment: VerifiedAttackPathAssessment,
        p7b_assessment: VerifiedPrivilegeEscalationAssessment,
        posture: VerifiedSecurityPosture,
    ) -> VerifiedDataExfiltrationAssessment:
        validate_policy(self._policy)
        validate_request(request, self._policy)
        architecture_assets, architecture_flows, architecture_sha = validate_architecture(
            architecture,
            request=request,
            policy=self._policy,
        )
        controls = validate_upstream_evidence(
            request=request,
            policy=self._policy,
            architecture_sha256=architecture_sha,
            p7a_assessment=p7a_assessment,
            p7b_assessment=p7b_assessment,
            posture=posture,
        )
        data_objects, edges, manifest_sha = validate_manifest(
            manifest,
            request=request,
            policy=self._policy,
            architecture_sha256=architecture_sha,
            architecture_assets=architecture_assets,
            architecture_flows=architecture_flows,
            control_ids=frozenset(controls),
        )
        paths = _enumerate_paths(
            data_objects=data_objects,
            edges=edges,
            controls=controls,
            policy=self._policy,
        )
        exposed = tuple(item for item in paths if item.exposed)
        controlled = tuple(item for item in paths if not item.exposed)
        restricted = tuple(
            item
            for item in exposed
            if item.classification in {DataClassification.RESTRICTED, DataClassification.SECRET}
        )
        cross_tenant = tuple(item for item in exposed if item.tenant_violation_edge_ids)
        egress = tuple(item for item in exposed if item.external_egress)
        prioritized = tuple(
            item.path_id
            for item in sorted(
                exposed,
                key=lambda value: (-value.risk_score, value.data_id, value.path_id),
            )
        )
        max_risk = max((item.risk_score for item in exposed), default=0)

        if set(request.declared_exposed_path_ids) != set(prioritized):
            reject(DataPathRejectReason.DECLARED_PATH_MISMATCH, "caller-declared exposed data paths differ from evidence-derived paths")
        if request.declared_max_exposed_risk_score != max_risk:
            reject(DataPathRejectReason.DECLARED_RISK_MISMATCH, "caller-declared maximum exfiltration risk differs from evidence-derived risk")

        evidence_document = {
            "architecture_sha256": architecture_sha,
            "control_catalog_sha256": posture.control_catalog_sha256.casefold(),
            "data_graph_sha256": manifest_sha,
            "entry_data_ids": sorted(request.entry_data_ids),
            "exposed_path_ids": list(prioritized),
            "max_exposed_risk_score": max_risk,
            "p7a_assessment_evidence_sha256": p7a_assessment.assessment_evidence_sha256.casefold(),
            "p7b_assessment_evidence_sha256": p7b_assessment.assessment_evidence_sha256.casefold(),
            "path_facts": [asdict(item) for item in paths],
            "posture_evidence_sha256": posture.posture_evidence_sha256.casefold(),
            "target_sink_asset_ids": sorted(request.target_sink_asset_ids),
        }
        evidence_sha = hashlib.sha256(
            json.dumps(evidence_document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        return VerifiedDataExfiltrationAssessment(
            data_graph_id=manifest.data_graph_id,
            data_graph_version=manifest.version,
            data_graph_sha256=manifest_sha,
            architecture_sha256=architecture_sha,
            p7a_assessment_evidence_sha256=p7a_assessment.assessment_evidence_sha256.casefold(),
            p7b_assessment_evidence_sha256=p7b_assessment.assessment_evidence_sha256.casefold(),
            posture_evidence_sha256=posture.posture_evidence_sha256.casefold(),
            control_catalog_sha256=posture.control_catalog_sha256.casefold(),
            entry_data_ids=tuple(sorted(request.entry_data_ids)),
            target_sink_asset_ids=tuple(sorted(request.target_sink_asset_ids)),
            topology_path_count=len(paths),
            exposed_path_count=len(exposed),
            controlled_path_count=len(controlled),
            restricted_or_secret_exposed_path_count=len(restricted),
            cross_tenant_exposed_path_count=len(cross_tenant),
            external_egress_exposed_path_count=len(egress),
            max_exposed_risk_score=max_risk,
            prioritized_exposed_path_ids=prioritized,
            paths=paths,
            assessment_evidence_sha256=evidence_sha,
        )
