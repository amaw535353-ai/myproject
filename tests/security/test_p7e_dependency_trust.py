from __future__ import annotations

import pytest

from aegis.architecture.dependency_trust import (
    DependencyCriticality,
    DependencyTrustRejected,
    ExternalDependencyTrustAnalyzer,
)
from evals.p7e_dependency_trust import adversarial_cases, run_evaluation
from evals.p7e_fixture import CTRL_TELEMETRY_EGRESS, CTRL_TOOL_EGRESS, build_fixture


def _evaluate(fixture):
    return ExternalDependencyTrustAnalyzer(fixture["policy"]).evaluate(
        fixture["request"],
        fixture["manifest"],
        fixture["architecture"],
        fixture["p7a"],
        fixture["p7b"],
        fixture["p7c"],
        fixture["p7d"],
        fixture["posture"],
    )


@pytest.mark.parametrize("name,mutation", adversarial_cases(), ids=lambda value: value if isinstance(value, str) else None)
def test_adversarial_dependency_trust_cases_reject(name, mutation):
    fixture = mutation(build_fixture())
    with pytest.raises(DependencyTrustRejected):
        _evaluate(fixture)


def test_all_satisfied_dependency_paths_are_controlled():
    result = _evaluate(build_fixture())
    assert result.topology_path_count == 5
    assert result.exposed_path_count == 0
    assert result.controlled_path_count == 5
    assert result.max_exposed_risk_score == 0
    assert result.caller_summary_trusted is False
    assert result.production_dependency_discovery is False
    assert result.live_dns_or_certificate_validation is False
    assert result.production_egress_enforcement is False
    assert result.network_operations == 0


def test_tool_egress_exception_surfaces_critical_secret_bearing_path():
    result = _evaluate(build_fixture(exceptioned_control=CTRL_TOOL_EGRESS))
    assert result.exposed_path_count == 1
    assert result.controlled_path_count == 4
    assert result.critical_exposed_path_count == 1
    assert result.secret_bearing_exposed_path_count == 1
    assert result.restricted_or_secret_data_exposed_path_count == 1
    assert result.max_exposed_risk_score == 134
    path = next(item for item in result.paths if item.exposed)
    assert path.criticality == DependencyCriticality.CRITICAL
    assert CTRL_TOOL_EGRESS in path.exceptioned_control_ids


def test_telemetry_missing_evidence_remains_visible():
    result = _evaluate(build_fixture(not_evaluated_control=CTRL_TELEMETRY_EGRESS))
    assert result.exposed_path_count == 1
    assert result.max_exposed_risk_score == 60
    path = next(item for item in result.paths if item.exposed)
    assert CTRL_TELEMETRY_EGRESS in path.not_evaluated_control_ids
    assert path.exposure_reasons == ("not_evaluated_egress_control",)


def test_evaluation_metrics_hold():
    metrics = run_evaluation()["metrics"]
    total = len(adversarial_cases())
    assert metrics["vulnerable_asr"] == f"{total}/{total}"
    assert metrics["hardened_asr"] == f"0/{total}"
    assert metrics["hardened_fpr"] == "0/3"
    assert metrics["safe_task_rate"] == "3/3"
