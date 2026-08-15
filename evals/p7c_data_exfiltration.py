from __future__ import annotations

import hashlib
import json
from dataclasses import replace

from aegis.architecture.data_manifest import canonical_data_flow_manifest_bytes, data_flow_manifest_digest
from aegis.architecture.data_paths import TenantIsolationExfiltrationAnalyzer
from aegis.architecture.data_types import (
    P7C_DATA_POLICY_VERSION,
    DataClassification,
    DataFlowEdge,
    DataKind,
    DataPathRejected,
    DataTransform,
)
from aegis.assurance.posture_reporting import ControlStatus
from aegis.vulnerable.data_exfiltration import VulnerableDataExfiltrationReporter

from .p7c_fixture import *


def _safe_summary(fixture: dict[str, object]) -> dict[str, object]:
    fixture["request"] = replace(
        fixture["request"],
        declared_exposed_path_ids=(),
        declared_max_exposed_risk_score=0,
    )
    return fixture


def _mapping_with(mapping, key, value):
    updated = dict(mapping)
    updated[key] = value
    return updated


def _mutate_case(name: str) -> dict[str, object]:
    f = build_fixture()
    manifest = f["manifest"]
    request = f["request"]
    policy = f["policy"]
    posture = f["posture"]
    p7a = f["p7a"]
    p7b = f["p7b"]

    if name == "caller_safe_summary_forgery":
        return _safe_summary(f)
    if name == "request_graph_id_substitution":
        f["request"] = replace(request, data_graph_id="other-graph")
    elif name == "request_graph_version_substitution":
        f["request"] = replace(request, data_graph_version="other-version")
    elif name == "request_graph_digest_substitution":
        f["request"] = replace(request, data_graph_sha256="0" * 64)
    elif name == "request_architecture_digest_substitution":
        f["request"] = replace(request, architecture_sha256="1" * 64)
    elif name == "request_p7a_evidence_substitution":
        f["request"] = replace(request, p7a_assessment_evidence_sha256="2" * 64)
    elif name == "request_p7b_evidence_substitution":
        f["request"] = replace(request, p7b_assessment_evidence_sha256="3" * 64)
    elif name == "request_posture_evidence_substitution":
        f["request"] = replace(request, posture_evidence_sha256="4" * 64)
    elif name == "request_entry_data_omission":
        f["request"] = replace(request, entry_data_ids=(DATA_TICKET, DATA_SECRET))
    elif name == "request_target_sink_omission":
        f["request"] = replace(request, target_sink_asset_ids=("external-user", "model-runtime"))
    elif name == "request_duplicate_entry_data":
        f["request"] = replace(request, entry_data_ids=(DATA_TICKET, DATA_TICKET, DATA_SECRET, DATA_TELEMETRY))
    elif name == "request_invalid_evaluation_time":
        f["request"] = replace(request, evaluated_at_epoch=0)
    elif name == "manifest_schema_substitution":
        repin_manifest(f, replace(manifest, schema_version="aegis-data-flow-manifest-v0"))
    elif name == "manifest_graph_id_substitution":
        repin_manifest(f, replace(manifest, data_graph_id="other-data-graph"))
    elif name == "manifest_version_substitution":
        repin_manifest(f, replace(manifest, version="2026.08-attacker"))
    elif name == "manifest_architecture_substitution":
        repin_manifest(f, replace(manifest, architecture_sha256="5" * 64))
    elif name == "manifest_future_timestamp":
        repin_manifest(f, replace(manifest, created_at_epoch=EVALUATION_EPOCH + 31))
    elif name == "manifest_stale_timestamp":
        repin_manifest(f, replace(manifest, created_at_epoch=EVALUATION_EPOCH - 3_601))
    elif name == "data_duplicate":
        repin_manifest(f, replace(manifest, data_objects=manifest.data_objects + (manifest.data_objects[0],)))
    elif name == "data_omission":
        repin_manifest(f, replace(manifest, data_objects=tuple(item for item in manifest.data_objects if item.data_id != DATA_TELEMETRY)))
    elif name == "data_extra":
        extra = replace(manifest.data_objects[0], data_id="extra-data")
        repin_manifest(f, replace(manifest, data_objects=manifest.data_objects + (extra,)))
    elif name == "data_owner_substitution":
        repin_manifest(f, replace_data(manifest, DATA_TICKET, owner_id="attacker"))
    elif name == "data_origin_substitution":
        repin_manifest(f, replace_data(manifest, DATA_TICKET, origin_asset_id="secret-store"))
    elif name == "data_tenant_substitution":
        repin_manifest(f, replace_data(manifest, DATA_TICKET, tenant_id="tenant-b"))
    elif name == "data_kind_substitution":
        repin_manifest(f, replace_data(manifest, DATA_TICKET, data_kind=DataKind.MODEL_OUTPUT))
    elif name == "data_classification_downgrade":
        repin_manifest(f, replace_data(manifest, DATA_SECRET, classification=DataClassification.PUBLIC))
    elif name == "edge_duplicate":
        repin_manifest(f, replace(manifest, edges=manifest.edges + (manifest.edges[0],)))
    elif name == "edge_omission":
        repin_manifest(f, replace(manifest, edges=tuple(item for item in manifest.edges if item.edge_id != EDGE_TELEMETRY_SECURITY)))
    elif name == "edge_extra":
        extra = replace(manifest.edges[0], edge_id="extra-edge")
        repin_manifest(f, replace(manifest, edges=manifest.edges + (extra,)))
    elif name == "edge_owner_substitution":
        repin_manifest(f, replace_edge(manifest, EDGE_TICKET_AGENT, owner_id="attacker"))
    elif name == "edge_unknown_data_reference":
        repin_manifest(f, replace_edge(manifest, EDGE_TICKET_AGENT, data_id="unknown-data"))
    elif name == "edge_self_loop":
        repin_manifest(f, replace_edge(manifest, EDGE_TICKET_AGENT, target_asset_id="retriever"))
    elif name == "edge_data_binding_substitution":
        repin_manifest(f, replace_edge(manifest, EDGE_TICKET_AGENT, data_id=DATA_SECRET))
    elif name == "edge_endpoint_substitution":
        repin_manifest(f, replace_edge(manifest, EDGE_TICKET_AGENT, target_asset_id="tool-gateway"))
    elif name == "edge_flow_substitution":
        repin_manifest(f, replace_edge(manifest, EDGE_TICKET_AGENT, via_flow_ids=("flow-agent-model",)))
    elif name == "edge_control_substitution":
        repin_manifest(f, replace_edge(manifest, EDGE_TICKET_AGENT, required_control_ids=(CTRL_RAG_FILTER,)))
    elif name == "edge_transform_substitution":
        repin_manifest(f, replace_edge(manifest, EDGE_TICKET_AGENT, transform=DataTransform.REDACTED))
    elif name == "edge_noncontiguous_route":
        altered = replace_edge(manifest, EDGE_TICKET_AGENT, via_flow_ids=("flow-runtime-telemetry",))
        repin_manifest(f, altered)
        f["policy"] = replace(
            f["policy"],
            expected_flow_ids_by_edge=_mapping_with(f["policy"].expected_flow_ids_by_edge, EDGE_TICKET_AGENT, ("flow-runtime-telemetry",)),
        )
    elif name == "edge_unknown_control":
        unknown = "CTRL-UNKNOWN-DATA-CONTROL"
        altered = replace_edge(manifest, EDGE_TICKET_AGENT, required_control_ids=(unknown,))
        repin_manifest(f, altered)
        f["policy"] = replace(
            f["policy"],
            expected_control_ids_by_edge=_mapping_with(f["policy"].expected_control_ids_by_edge, EDGE_TICKET_AGENT, frozenset({unknown})),
        )
    elif name == "p7a_schema_substitution":
        f["p7a"] = replace(p7a, schema_version="aegis-attack-path-assessment-v0")
    elif name == "p7a_binding_flag_downgrade":
        f["p7a"] = replace(p7a, exact_architecture_binding_verified=False)
    elif name == "p7a_caller_summary_trusted":
        f["p7a"] = replace(p7a, caller_summary_trusted=True)
    elif name == "p7a_assessment_digest_substitution":
        f["p7a"] = replace(p7a, assessment_evidence_sha256="6" * 64)
    elif name == "p7b_schema_substitution":
        f["p7b"] = replace(p7b, schema_version="aegis-privilege-escalation-assessment-v0")
    elif name == "p7b_binding_flag_downgrade":
        f["p7b"] = replace(p7b, exact_p7a_assessment_binding_verified=False)
    elif name == "p7b_caller_summary_trusted":
        f["p7b"] = replace(p7b, caller_summary_trusted=True)
    elif name == "p7b_assessment_digest_substitution":
        f["p7b"] = replace(p7b, assessment_evidence_sha256="7" * 64)
    elif name == "posture_schema_substitution":
        f["posture"] = replace(posture, schema_version="aegis-ai-security-posture-evidence-v0")
    elif name == "posture_binding_flag_downgrade":
        f["posture"] = replace(posture, exact_upstream_evidence_binding_verified=False)
    elif name == "posture_caller_green_trusted":
        f["posture"] = replace(posture, caller_declared_green_trusted=True)
    elif name == "posture_digest_substitution":
        f["posture"] = replace(posture, posture_evidence_sha256="8" * 64)
    elif name == "control_catalog_substitution":
        f["posture"] = replace(posture, control_catalog_sha256="9" * 64)
    elif name == "control_duplicate_assessment":
        f["posture"] = replace_posture_assessments(posture, posture.assessments + (posture.assessments[0],))
    elif name == "control_count_forgery":
        f["posture"] = replace(posture, control_count=posture.control_count + 1)
    elif name == "control_status_aggregate_forgery":
        f["posture"] = replace(posture, satisfied_control_ids=())
    elif name == "policy_empty_trusted_owners":
        f["policy"] = replace(policy, trusted_owner_ids=frozenset())
    elif name == "policy_missing_sink_ceiling":
        f["policy"] = replace(policy, max_classification_by_sink_asset={"external-user": DataClassification.CONFIDENTIAL})
    elif name == "policy_missing_edge_metadata":
        mapping = dict(policy.expected_data_id_by_edge)
        mapping.pop(EDGE_TICKET_AGENT)
        f["policy"] = replace(policy, expected_data_id_by_edge=mapping)
    elif name == "path_count_limit":
        f["policy"] = replace(policy, max_paths=1)
    elif name == "path_hop_limit":
        f["policy"] = replace(policy, max_path_hops=1)
    elif name == "tenant_destination_substitution":
        repin_manifest(f, replace_edge(manifest, EDGE_TICKET_USER, destination_tenant_id="tenant-c"))
    else:
        raise KeyError(name)

    return _safe_summary(f)


ADVERSARIAL_CASES = (
    "caller_safe_summary_forgery",
    "request_graph_id_substitution",
    "request_graph_version_substitution",
    "request_graph_digest_substitution",
    "request_architecture_digest_substitution",
    "request_p7a_evidence_substitution",
    "request_p7b_evidence_substitution",
    "request_posture_evidence_substitution",
    "request_entry_data_omission",
    "request_target_sink_omission",
    "request_duplicate_entry_data",
    "request_invalid_evaluation_time",
    "manifest_schema_substitution",
    "manifest_graph_id_substitution",
    "manifest_version_substitution",
    "manifest_architecture_substitution",
    "manifest_future_timestamp",
    "manifest_stale_timestamp",
    "data_duplicate",
    "data_omission",
    "data_extra",
    "data_owner_substitution",
    "data_origin_substitution",
    "data_tenant_substitution",
    "data_kind_substitution",
    "data_classification_downgrade",
    "edge_duplicate",
    "edge_omission",
    "edge_extra",
    "edge_owner_substitution",
    "edge_unknown_data_reference",
    "edge_self_loop",
    "edge_data_binding_substitution",
    "edge_endpoint_substitution",
    "edge_flow_substitution",
    "edge_control_substitution",
    "edge_transform_substitution",
    "edge_noncontiguous_route",
    "edge_unknown_control",
    "p7a_schema_substitution",
    "p7a_binding_flag_downgrade",
    "p7a_caller_summary_trusted",
    "p7a_assessment_digest_substitution",
    "p7b_schema_substitution",
    "p7b_binding_flag_downgrade",
    "p7b_caller_summary_trusted",
    "p7b_assessment_digest_substitution",
    "posture_schema_substitution",
    "posture_binding_flag_downgrade",
    "posture_caller_green_trusted",
    "posture_digest_substitution",
    "control_catalog_substitution",
    "control_duplicate_assessment",
    "control_count_forgery",
    "control_status_aggregate_forgery",
    "policy_empty_trusted_owners",
    "policy_missing_sink_ceiling",
    "policy_missing_edge_metadata",
    "path_count_limit",
    "path_hop_limit",
    "tenant_destination_substitution",
)


def _evaluate_hardened(fixture: dict[str, object]) -> bool:
    analyzer = TenantIsolationExfiltrationAnalyzer(fixture["policy"])
    try:
        result = analyzer.evaluate(
            fixture["request"],
            fixture["manifest"],
            fixture["architecture"],
            fixture["p7a"],
            fixture["p7b"],
            fixture["posture"],
        )
    except DataPathRejected:
        return False
    return result.exposed_path_count == 0 and result.max_exposed_risk_score == 0


def _benign_fixtures() -> tuple[dict[str, object], ...]:
    baseline = build_fixture()
    all_satisfied = build_fixture(tenant_status=ControlStatus.SATISFIED)
    not_evaluated = build_fixture(tenant_status=ControlStatus.NOT_EVALUATED)
    return baseline, all_satisfied, not_evaluated


def run_evaluation() -> dict[str, object]:
    vulnerable = VulnerableDataExfiltrationReporter()
    vulnerable_successes = 0
    hardened_successes = 0
    adversarial_results = []
    for name in ADVERSARIAL_CASES:
        vulnerable_result = vulnerable.evaluate(
            data_graph_complete=True,
            declared_exposed_path_count=0,
            declared_max_risk_score=0,
        )
        vulnerable_successes += int(vulnerable_result.accepted)
        fixture = _mutate_case(name)
        hardened_attack_succeeded = _evaluate_hardened(fixture)
        hardened_successes += int(hardened_attack_succeeded)
        adversarial_results.append(
            {
                "case": name,
                "vulnerable_attack_succeeded": vulnerable_result.accepted,
                "hardened_attack_succeeded": hardened_attack_succeeded,
            }
        )

    benign_results = []
    hardened_false_positives = 0
    safe_successes = 0
    for index, fixture in enumerate(_benign_fixtures(), start=1):
        analyzer = TenantIsolationExfiltrationAnalyzer(fixture["policy"])
        try:
            result = analyzer.evaluate(
                fixture["request"], fixture["manifest"], fixture["architecture"], fixture["p7a"], fixture["p7b"], fixture["posture"]
            )
            accepted = True
            safe_successes += 1
            exposed_count = result.exposed_path_count
            max_risk = result.max_exposed_risk_score
        except DataPathRejected:
            accepted = False
            hardened_false_positives += 1
            exposed_count = None
            max_risk = None
        benign_results.append(
            {
                "case": f"benign_{index}",
                "accepted": accepted,
                "exposed_path_count": exposed_count,
                "max_exposed_risk_score": max_risk,
            }
        )

    baseline = build_fixture()
    dataset_sha = hashlib.sha256(
        json.dumps(list(ADVERSARIAL_CASES), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    fixture_sha = hashlib.sha256(
        canonical_data_flow_manifest_bytes(baseline["manifest"])
        + baseline["p7a"].assessment_evidence_sha256.encode()
        + baseline["p7b"].assessment_evidence_sha256.encode()
        + baseline["posture"].posture_evidence_sha256.encode()
    ).hexdigest()

    return {
        "policy_version": P7C_DATA_POLICY_VERSION,
        "adversarial_cases": len(ADVERSARIAL_CASES),
        "vulnerable_asr_numerator": vulnerable_successes,
        "vulnerable_asr_denominator": len(ADVERSARIAL_CASES),
        "hardened_asr_numerator": hardened_successes,
        "hardened_asr_denominator": len(ADVERSARIAL_CASES),
        "hardened_fpr_numerator": hardened_false_positives,
        "hardened_fpr_denominator": len(benign_results),
        "safe_task_rate_numerator": safe_successes,
        "safe_task_rate_denominator": len(benign_results),
        "data_graph_sha256": data_flow_manifest_digest(baseline["manifest"]),
        "architecture_sha256": baseline["request"].architecture_sha256,
        "p7a_assessment_evidence_sha256": baseline["p7a"].assessment_evidence_sha256,
        "p7b_assessment_evidence_sha256": baseline["p7b"].assessment_evidence_sha256,
        "posture_evidence_sha256": baseline["posture"].posture_evidence_sha256,
        "control_catalog_sha256": baseline["posture"].control_catalog_sha256,
        "dataset_sha256": dataset_sha,
        "fixture_sha256": fixture_sha,
        "adversarial_results": adversarial_results,
        "benign_results": benign_results,
    }


def main() -> None:
    print(json.dumps(run_evaluation(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
