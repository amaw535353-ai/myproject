from __future__ import annotations

import hashlib
import hmac
import json
from typing import Mapping

from .attack_paths import ArchitectureManifest, architecture_manifest_digest
from .data_types import (
    P7C_DATA_MANIFEST_SCHEMA_VERSION,
    DataClassification,
    DataFlowEdge,
    DataFlowManifest,
    DataKind,
    DataObject,
    DataPathPolicy,
    DataPathRejectReason,
    DataPathRejected,
    DataPathRequest,
    DataTransform,
)


def reject(
    reason: DataPathRejectReason,
    message: str,
    *,
    data_id: str | None = None,
    edge_id: str | None = None,
    control_id: str | None = None,
) -> None:
    raise DataPathRejected(
        reason,
        message,
        data_id=data_id,
        edge_id=edge_id,
        control_id=control_id,
    )


def is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def classification_rank(value: DataClassification) -> int:
    return {
        DataClassification.PUBLIC: 0,
        DataClassification.INTERNAL: 1,
        DataClassification.CONFIDENTIAL: 2,
        DataClassification.RESTRICTED: 3,
        DataClassification.SECRET: 4,
    }[value]


def _canonical_data_object(item: DataObject) -> dict[str, object]:
    return {
        "classification": item.classification.value
        if isinstance(item.classification, DataClassification)
        else str(item.classification),
        "data_id": item.data_id,
        "data_kind": item.data_kind.value
        if isinstance(item.data_kind, DataKind)
        else str(item.data_kind),
        "description": item.description,
        "origin_asset_id": item.origin_asset_id,
        "owner_id": item.owner_id,
        "tenant_id": item.tenant_id,
    }


def _canonical_edge(item: DataFlowEdge) -> dict[str, object]:
    return {
        "data_id": item.data_id,
        "destination_tenant_id": item.destination_tenant_id,
        "edge_id": item.edge_id,
        "owner_id": item.owner_id,
        "purpose": item.purpose,
        "required_control_ids": sorted(item.required_control_ids),
        "source_asset_id": item.source_asset_id,
        "target_asset_id": item.target_asset_id,
        "transform": item.transform.value
        if isinstance(item.transform, DataTransform)
        else str(item.transform),
        "via_flow_ids": list(item.via_flow_ids),
    }


def canonical_data_flow_manifest_bytes(manifest: DataFlowManifest) -> bytes:
    document = {
        "architecture_sha256": manifest.architecture_sha256.casefold(),
        "created_at_epoch": manifest.created_at_epoch,
        "data_graph_id": manifest.data_graph_id,
        "data_objects": [
            _canonical_data_object(item)
            for item in sorted(manifest.data_objects, key=lambda value: value.data_id)
        ],
        "edges": [
            _canonical_edge(item)
            for item in sorted(manifest.edges, key=lambda value: value.edge_id)
        ],
        "schema_version": manifest.schema_version,
        "version": manifest.version,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def data_flow_manifest_digest(manifest: DataFlowManifest) -> str:
    return hashlib.sha256(canonical_data_flow_manifest_bytes(manifest)).hexdigest()


def validate_policy(policy: DataPathPolicy) -> None:
    if (
        not policy.expected_data_graph_id
        or not policy.expected_data_graph_version
        or not is_sha256(policy.expected_data_graph_sha256)
        or not is_sha256(policy.expected_architecture_sha256)
        or not is_sha256(policy.expected_p7a_assessment_evidence_sha256)
        or not is_sha256(policy.expected_p7b_assessment_evidence_sha256)
        or not is_sha256(policy.expected_posture_evidence_sha256)
        or not is_sha256(policy.expected_control_catalog_sha256)
        or not policy.required_data_ids
        or not policy.required_edge_ids
        or not policy.entry_data_ids
        or not policy.target_sink_asset_ids
        or not policy.trusted_owner_ids
        or not policy.entry_data_ids.issubset(policy.required_data_ids)
        or policy.max_manifest_age_seconds < 0
        or policy.max_future_skew_seconds < 0
        or policy.max_path_hops <= 0
        or policy.max_paths <= 0
    ):
        reject(DataPathRejectReason.POLICY_INVALID, "data-path policy metadata is invalid")

    data_maps: tuple[Mapping[str, object], ...] = (
        policy.expected_tenant_by_data,
        policy.expected_kind_by_data,
        policy.expected_origin_asset_by_data,
        policy.minimum_classification_by_data,
        policy.allowed_destination_tenants_by_data,
        policy.allowed_sink_assets_by_data,
    )
    if any(not policy.required_data_ids.issubset(set(mapping)) for mapping in data_maps):
        reject(DataPathRejectReason.POLICY_INVALID, "required data objects lack policy-pinned metadata")

    edge_maps: tuple[Mapping[str, object], ...] = (
        policy.expected_data_id_by_edge,
        policy.expected_endpoints_by_edge,
        policy.expected_flow_ids_by_edge,
        policy.expected_control_ids_by_edge,
        policy.allowed_transforms_by_edge,
    )
    if any(not policy.required_edge_ids.issubset(set(mapping)) for mapping in edge_maps):
        reject(DataPathRejectReason.POLICY_INVALID, "required data-flow edges lack policy-pinned metadata")

    if not policy.target_sink_asset_ids.issubset(set(policy.max_classification_by_sink_asset)):
        reject(DataPathRejectReason.POLICY_INVALID, "target sinks lack classification ceilings")
    if not policy.target_sink_asset_ids.issubset(set(policy.allowed_final_transforms_by_sink_asset)):
        reject(DataPathRejectReason.POLICY_INVALID, "target sinks lack final-transform policy")
    if not policy.egress_sink_asset_ids.issubset(policy.target_sink_asset_ids):
        reject(DataPathRejectReason.POLICY_INVALID, "egress sinks must be within the target sink set")

    for data_id in policy.required_data_ids:
        tenant = policy.expected_tenant_by_data[data_id]
        kind = policy.expected_kind_by_data[data_id]
        origin = policy.expected_origin_asset_by_data[data_id]
        minimum = policy.minimum_classification_by_data[data_id]
        destinations = policy.allowed_destination_tenants_by_data[data_id]
        sinks = policy.allowed_sink_assets_by_data[data_id]
        if (
            not tenant
            or not origin
            or not isinstance(kind, DataKind)
            or not isinstance(minimum, DataClassification)
            or not destinations
            or not sinks
            or any(not item for item in destinations)
            or any(not item for item in sinks)
        ):
            reject(DataPathRejectReason.POLICY_INVALID, "data-object policy mapping is invalid", data_id=data_id)

    for edge_id in policy.required_edge_ids:
        data_id = policy.expected_data_id_by_edge[edge_id]
        endpoints = policy.expected_endpoints_by_edge[edge_id]
        flow_ids = policy.expected_flow_ids_by_edge[edge_id]
        controls = policy.expected_control_ids_by_edge[edge_id]
        transforms = policy.allowed_transforms_by_edge[edge_id]
        if (
            data_id not in policy.required_data_ids
            or len(endpoints) != 2
            or not endpoints[0]
            or not endpoints[1]
            or endpoints[0] == endpoints[1]
            or not flow_ids
            or len(set(flow_ids)) != len(flow_ids)
            or any(not item for item in flow_ids)
            or any(not item for item in controls)
            or not transforms
            or any(not isinstance(item, DataTransform) for item in transforms)
        ):
            reject(DataPathRejectReason.POLICY_INVALID, "data-flow edge policy mapping is invalid", edge_id=edge_id)

    for sink_id, ceiling in policy.max_classification_by_sink_asset.items():
        if not sink_id or not isinstance(ceiling, DataClassification):
            reject(DataPathRejectReason.POLICY_INVALID, "sink classification policy is invalid")
    for sink_id, transforms in policy.allowed_final_transforms_by_sink_asset.items():
        if not sink_id or not transforms or any(not isinstance(item, DataTransform) for item in transforms):
            reject(DataPathRejectReason.POLICY_INVALID, "sink transform policy is invalid")


def validate_request(request: DataPathRequest, policy: DataPathPolicy) -> None:
    if (
        not request.data_graph_id
        or not request.data_graph_version
        or not is_sha256(request.data_graph_sha256)
        or not is_sha256(request.architecture_sha256)
        or not is_sha256(request.p7a_assessment_evidence_sha256)
        or not is_sha256(request.p7b_assessment_evidence_sha256)
        or not is_sha256(request.posture_evidence_sha256)
        or not request.entry_data_ids
        or not request.target_sink_asset_ids
        or request.evaluated_at_epoch <= 0
        or request.declared_max_exposed_risk_score < 0
        or len(set(request.entry_data_ids)) != len(request.entry_data_ids)
        or len(set(request.target_sink_asset_ids)) != len(request.target_sink_asset_ids)
        or len(set(request.declared_exposed_path_ids)) != len(request.declared_exposed_path_ids)
    ):
        reject(DataPathRejectReason.REQUEST_INVALID, "data-path request metadata is invalid")
    if set(request.entry_data_ids) != set(policy.entry_data_ids):
        reject(DataPathRejectReason.ENTRY_DATA_SCOPE_MISMATCH, "entry data scope differs from policy")
    if set(request.target_sink_asset_ids) != set(policy.target_sink_asset_ids):
        reject(DataPathRejectReason.TARGET_SINK_SCOPE_MISMATCH, "target sink scope differs from policy")


def validate_architecture(
    architecture: ArchitectureManifest,
    *,
    request: DataPathRequest,
    policy: DataPathPolicy,
) -> tuple[dict[str, object], dict[str, object], str]:
    if not architecture.architecture_id or not architecture.version or not architecture.assets or not architecture.flows:
        reject(DataPathRejectReason.ARCHITECTURE_INVALID, "architecture manifest metadata is invalid")
    architecture_sha = architecture_manifest_digest(architecture)
    if (
        not hmac.compare_digest(architecture_sha, policy.expected_architecture_sha256.casefold())
        or not hmac.compare_digest(request.architecture_sha256.casefold(), architecture_sha)
    ):
        reject(DataPathRejectReason.ARCHITECTURE_DIGEST_MISMATCH, "request/policy do not bind to exact P7-A architecture")
    assets = {item.asset_id: item for item in architecture.assets}
    flows = {item.flow_id: item for item in architecture.flows}
    if len(assets) != len(architecture.assets) or len(flows) != len(architecture.flows):
        reject(DataPathRejectReason.ARCHITECTURE_INVALID, "architecture contains duplicate asset or flow IDs")
    return assets, flows, architecture_sha


def validate_manifest(
    manifest: DataFlowManifest,
    *,
    request: DataPathRequest,
    policy: DataPathPolicy,
    architecture_sha256: str,
    architecture_assets: Mapping[str, object],
    architecture_flows: Mapping[str, object],
    control_ids: frozenset[str],
) -> tuple[dict[str, DataObject], dict[str, DataFlowEdge], str]:
    if (
        manifest.schema_version != P7C_DATA_MANIFEST_SCHEMA_VERSION
        or not manifest.data_graph_id
        or not manifest.version
        or not is_sha256(manifest.architecture_sha256)
        or manifest.created_at_epoch <= 0
        or not manifest.data_objects
        or not manifest.edges
    ):
        reject(DataPathRejectReason.DATA_MANIFEST_INVALID, "data-flow manifest metadata is invalid")

    manifest_sha = data_flow_manifest_digest(manifest)
    if (
        manifest.data_graph_id != policy.expected_data_graph_id
        or manifest.version != policy.expected_data_graph_version
        or request.data_graph_id != manifest.data_graph_id
        or request.data_graph_version != manifest.version
        or not hmac.compare_digest(manifest_sha, policy.expected_data_graph_sha256.casefold())
        or not hmac.compare_digest(request.data_graph_sha256.casefold(), manifest_sha)
        or not hmac.compare_digest(manifest.architecture_sha256.casefold(), architecture_sha256.casefold())
    ):
        reject(DataPathRejectReason.DATA_MANIFEST_DIGEST_MISMATCH, "request/policy do not bind to exact data-flow manifest")
    if manifest.created_at_epoch > request.evaluated_at_epoch + policy.max_future_skew_seconds:
        reject(DataPathRejectReason.DATA_MANIFEST_FUTURE, "data-flow manifest is future-dated")
    if request.evaluated_at_epoch - manifest.created_at_epoch > policy.max_manifest_age_seconds:
        reject(DataPathRejectReason.DATA_MANIFEST_STALE, "data-flow manifest is older than policy permits")

    data_objects: dict[str, DataObject] = {}
    for item in manifest.data_objects:
        if (
            not item.data_id
            or not item.tenant_id
            or not isinstance(item.data_kind, DataKind)
            or not isinstance(item.classification, DataClassification)
            or not item.origin_asset_id
            or not item.owner_id
            or not item.description
        ):
            reject(DataPathRejectReason.DATA_MANIFEST_INVALID, "data object metadata is invalid", data_id=item.data_id or None)
        if item.data_id in data_objects:
            reject(DataPathRejectReason.DATA_DUPLICATE, "data-flow manifest contains duplicate data IDs", data_id=item.data_id)
        if item.owner_id not in policy.trusted_owner_ids:
            reject(DataPathRejectReason.DATA_OWNER_UNTRUSTED, "data owner is not trusted", data_id=item.data_id)
        if item.origin_asset_id not in architecture_assets:
            reject(DataPathRejectReason.DATA_ORIGIN_INVALID, "data object origin is not in the architecture", data_id=item.data_id)
        data_objects[item.data_id] = item

    if set(data_objects) != set(policy.required_data_ids):
        reject(DataPathRejectReason.DATA_COVERAGE_MISMATCH, "data-object coverage differs from policy")
    for data_id, item in data_objects.items():
        if item.tenant_id != policy.expected_tenant_by_data[data_id]:
            reject(DataPathRejectReason.DATA_TENANT_DRIFT, "data tenant ownership differs from policy", data_id=data_id)
        if item.data_kind != policy.expected_kind_by_data[data_id]:
            reject(DataPathRejectReason.DATA_KIND_DRIFT, "data kind differs from policy", data_id=data_id)
        if item.origin_asset_id != policy.expected_origin_asset_by_data[data_id]:
            reject(DataPathRejectReason.DATA_ORIGIN_INVALID, "data origin differs from policy", data_id=data_id)
        if classification_rank(item.classification) < classification_rank(policy.minimum_classification_by_data[data_id]):
            reject(DataPathRejectReason.DATA_CLASSIFICATION_DOWNGRADE, "data classification is below policy floor", data_id=data_id)

    edges: dict[str, DataFlowEdge] = {}
    for item in manifest.edges:
        if (
            not item.edge_id
            or not item.data_id
            or not item.source_asset_id
            or not item.target_asset_id
            or not item.destination_tenant_id
            or not isinstance(item.transform, DataTransform)
            or not item.owner_id
            or not item.via_flow_ids
            or not item.purpose
            or len(set(item.via_flow_ids)) != len(item.via_flow_ids)
            or len(set(item.required_control_ids)) != len(item.required_control_ids)
            or any(not value for value in item.required_control_ids)
        ):
            reject(DataPathRejectReason.DATA_MANIFEST_INVALID, "data-flow edge metadata is invalid", edge_id=item.edge_id or None)
        if item.edge_id in edges:
            reject(DataPathRejectReason.EDGE_DUPLICATE, "data-flow manifest contains duplicate edge IDs", edge_id=item.edge_id)
        if item.owner_id not in policy.trusted_owner_ids:
            reject(DataPathRejectReason.EDGE_OWNER_UNTRUSTED, "data-flow edge owner is not trusted", edge_id=item.edge_id)
        if item.data_id not in data_objects or item.source_asset_id not in architecture_assets or item.target_asset_id not in architecture_assets:
            reject(DataPathRejectReason.EDGE_REFERENCE_INVALID, "data-flow edge references unknown data or assets", edge_id=item.edge_id)
        if item.source_asset_id == item.target_asset_id:
            reject(DataPathRejectReason.EDGE_SELF_LOOP, "data-flow edge may not self-loop", edge_id=item.edge_id)
        edges[item.edge_id] = item

    if set(edges) != set(policy.required_edge_ids):
        reject(DataPathRejectReason.EDGE_COVERAGE_MISMATCH, "data-flow edge coverage differs from policy")

    for edge_id, item in edges.items():
        if item.data_id != policy.expected_data_id_by_edge[edge_id]:
            reject(DataPathRejectReason.EDGE_DATA_DRIFT, "data-flow edge data binding differs from policy", edge_id=edge_id)
        if (item.source_asset_id, item.target_asset_id) != tuple(policy.expected_endpoints_by_edge[edge_id]):
            reject(DataPathRejectReason.EDGE_ENDPOINT_DRIFT, "data-flow edge endpoints differ from policy", edge_id=edge_id)
        if tuple(item.via_flow_ids) != tuple(policy.expected_flow_ids_by_edge[edge_id]):
            reject(DataPathRejectReason.EDGE_FLOW_DRIFT, "data-flow edge architecture route differs from policy", edge_id=edge_id)
        if frozenset(item.required_control_ids) != frozenset(policy.expected_control_ids_by_edge[edge_id]):
            reject(DataPathRejectReason.EDGE_CONTROL_DRIFT, "data-flow edge control set differs from policy", edge_id=edge_id)
        if item.transform not in policy.allowed_transforms_by_edge[edge_id]:
            reject(DataPathRejectReason.EDGE_TRANSFORM_DISALLOWED, "data-flow edge transform is not policy-authorized", edge_id=edge_id)
        for control_id in item.required_control_ids:
            if control_id not in control_ids:
                reject(DataPathRejectReason.EDGE_CONTROL_UNKNOWN, "data-flow edge references control absent from P6-D posture", edge_id=edge_id, control_id=control_id)

        current = item.source_asset_id
        for flow_id in item.via_flow_ids:
            flow = architecture_flows.get(flow_id)
            if flow is None or getattr(flow, "source_asset_id", None) != current:
                reject(DataPathRejectReason.EDGE_FLOW_INVALID, "data-flow edge route is not contiguous in P7-A architecture", edge_id=edge_id)
            current = getattr(flow, "target_asset_id", "")
        if current != item.target_asset_id:
            reject(DataPathRejectReason.EDGE_FLOW_INVALID, "data-flow edge route does not terminate at its target asset", edge_id=edge_id)

    return data_objects, edges, manifest_sha
