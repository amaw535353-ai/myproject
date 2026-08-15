from __future__ import annotations

from dataclasses import replace

import pytest

from aegis.architecture.data_paths import TenantIsolationExfiltrationAnalyzer
from aegis.architecture.data_types import DataPathRejectReason, DataPathRejected
from aegis.assurance.posture_reporting import ControlStatus
from evals.p7c_data_exfiltration import ADVERSARIAL_CASES, _mutate_case, run_evaluation
from evals.p7c_fixture import DATA_SECRET, DATA_TICKET, build_fixture


def _evaluate(fixture):
    return TenantIsolationExfiltrationAnalyzer(fixture["policy"]).evaluate(
        fixture["request"],
        fixture["manifest"],
        fixture["architecture"],
        fixture["p7a"],
        fixture["p7b"],
        fixture["posture"],
    )


def test_p7c_baseline_derives_tenant_and_secret_exfiltration_risk() -> None:
    result = _evaluate(build_fixture())
    assert result.topology_path_count == 4
    assert result.exposed_path_count == 3
    assert result.controlled_path_count == 1
    assert result.cross_tenant_exposed_path_count == 2
    assert result.external_egress_exposed_path_count == 2
    assert result.restricted_or_secret_exposed_path_count == 1
    assert result.max_exposed_risk_score > 100
    assert result.caller_summary_trusted is False
    assert result.network_operations == 0


def test_p7c_all_satisfied_controls_do_not_hide_policy_violations() -> None:
    result = _evaluate(build_fixture(tenant_status=ControlStatus.SATISFIED))
    assert result.topology_path_count == 4
    assert result.exposed_path_count == 2
    assert result.controlled_path_count == 2
    secret = next(path for path in result.paths if path.data_id == DATA_SECRET)
    assert secret.exposed is True
    assert secret.sink_allowed is False
    assert secret.classification_allowed is False


def test_p7c_not_evaluated_tenant_control_remains_visible() -> None:
    result = _evaluate(build_fixture(tenant_status=ControlStatus.NOT_EVALUATED))
    ticket_paths = [path for path in result.paths if path.data_id == DATA_TICKET]
    assert ticket_paths
    assert any(path.not_evaluated_control_ids for path in ticket_paths)
    assert any(path.exposed for path in ticket_paths)


@pytest.mark.parametrize(
    ("case_name", "reason"),
    (
        ("caller_safe_summary_forgery", DataPathRejectReason.DECLARED_PATH_MISMATCH),
        ("request_entry_data_omission", DataPathRejectReason.ENTRY_DATA_SCOPE_MISMATCH),
        ("manifest_future_timestamp", DataPathRejectReason.DATA_MANIFEST_FUTURE),
        ("manifest_stale_timestamp", DataPathRejectReason.DATA_MANIFEST_STALE),
        ("data_duplicate", DataPathRejectReason.DATA_DUPLICATE),
        ("data_omission", DataPathRejectReason.DATA_COVERAGE_MISMATCH),
        ("data_owner_substitution", DataPathRejectReason.DATA_OWNER_UNTRUSTED),
        ("data_tenant_substitution", DataPathRejectReason.DATA_TENANT_DRIFT),
        ("data_classification_downgrade", DataPathRejectReason.DATA_CLASSIFICATION_DOWNGRADE),
        ("edge_duplicate", DataPathRejectReason.EDGE_DUPLICATE),
        ("edge_omission", DataPathRejectReason.EDGE_COVERAGE_MISMATCH),
        ("edge_owner_substitution", DataPathRejectReason.EDGE_OWNER_UNTRUSTED),
        ("edge_unknown_data_reference", DataPathRejectReason.EDGE_REFERENCE_INVALID),
        ("edge_self_loop", DataPathRejectReason.EDGE_SELF_LOOP),
        ("edge_endpoint_substitution", DataPathRejectReason.EDGE_ENDPOINT_DRIFT),
        ("edge_flow_substitution", DataPathRejectReason.EDGE_FLOW_DRIFT),
        ("edge_control_substitution", DataPathRejectReason.EDGE_CONTROL_DRIFT),
        ("edge_transform_substitution", DataPathRejectReason.EDGE_TRANSFORM_DISALLOWED),
        ("edge_noncontiguous_route", DataPathRejectReason.EDGE_FLOW_INVALID),
        ("edge_unknown_control", DataPathRejectReason.EDGE_CONTROL_UNKNOWN),
        ("p7a_binding_flag_downgrade", DataPathRejectReason.P7A_ASSESSMENT_UNVERIFIED),
        ("p7b_binding_flag_downgrade", DataPathRejectReason.P7B_ASSESSMENT_UNVERIFIED),
        ("posture_binding_flag_downgrade", DataPathRejectReason.POSTURE_UNVERIFIED),
        ("control_duplicate_assessment", DataPathRejectReason.CONTROL_EVIDENCE_INVALID),
        ("control_status_aggregate_forgery", DataPathRejectReason.CONTROL_STATUS_MISMATCH),
        ("policy_empty_trusted_owners", DataPathRejectReason.POLICY_INVALID),
        ("path_count_limit", DataPathRejectReason.PATH_LIMIT_EXCEEDED),
        ("path_hop_limit", DataPathRejectReason.PATH_LIMIT_EXCEEDED),
    ),
)
def test_p7c_selected_attacks_fail_closed(case_name: str, reason: DataPathRejectReason) -> None:
    fixture = _mutate_case(case_name)
    with pytest.raises(DataPathRejected) as exc_info:
        _evaluate(fixture)
    assert exc_info.value.reason == reason


def test_p7c_evaluation_has_zero_hardened_asr_and_zero_fpr() -> None:
    report = run_evaluation()
    assert report["adversarial_cases"] == len(ADVERSARIAL_CASES)
    assert report["adversarial_cases"] >= 55
    assert report["vulnerable_asr_numerator"] == report["vulnerable_asr_denominator"]
    assert report["hardened_asr_numerator"] == 0
    assert report["hardened_asr_denominator"] == report["adversarial_cases"]
    assert report["hardened_fpr_numerator"] == 0
    assert report["hardened_fpr_denominator"] == 3
    assert report["safe_task_rate_numerator"] == 3
    assert report["safe_task_rate_denominator"] == 3


def test_p7c_upstream_evidence_binding_rejects_digest_forgery() -> None:
    fixture = build_fixture()
    fixture["request"] = replace(
        fixture["request"],
        p7b_assessment_evidence_sha256="f" * 64,
    )
    with pytest.raises(DataPathRejected) as exc_info:
        _evaluate(fixture)
    assert exc_info.value.reason == DataPathRejectReason.P7B_ASSESSMENT_MISMATCH
