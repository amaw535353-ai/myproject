from __future__ import annotations

import pytest

from aegis.architecture.telemetry_security import (
    SecurityTelemetryIntegrityAnalyzer,
    TelemetryBlindSpotRejected,
    TelemetrySeverity,
)
from evals.p7g_fixture import CTRL_ALERT_ROUTING, CTRL_TELEMETRY_FAILOVER, build_fixture
from evals.p7g_telemetry_security import adversarial_cases, run_evaluation


def _evaluate(fixture):
    return SecurityTelemetryIntegrityAnalyzer(fixture["policy"]).evaluate(
        fixture["request"],
        fixture["manifest"],
        fixture["p7a"],
        fixture["p7b"],
        fixture["p7c"],
        fixture["p7d"],
        fixture["p7e"],
        fixture["p7f"],
        fixture["posture"],
    )


@pytest.mark.parametrize("name,mutation", adversarial_cases(), ids=lambda value: value if isinstance(value, str) else None)
def test_adversarial_telemetry_cases_reject(name, mutation):
    fixture = mutation(build_fixture())
    with pytest.raises(TelemetryBlindSpotRejected):
        _evaluate(fixture)


def test_all_required_telemetry_is_monitored_when_evidence_is_intact():
    result = _evaluate(build_fixture())
    assert result.requirement_count == 12
    assert result.monitored_requirement_count == 12
    assert result.blind_spot_requirement_count == 0
    assert result.max_blind_spot_risk_score == 0
    assert result.caller_summary_trusted is False
    assert result.production_log_ingestion is False
    assert result.production_siem_integration is False
    assert result.real_detection_effectiveness_measurement is False
    assert result.network_operations == 0


def test_failover_control_exception_surfaces_observability_control_gaps():
    result = _evaluate(build_fixture(exceptioned_control=CTRL_TELEMETRY_FAILOVER))
    assert result.blind_spot_requirement_count == 6
    assert result.critical_blind_spot_count == 3
    assert result.max_blind_spot_risk_score == 103
    assert "req-failover" in result.prioritized_blind_spot_requirement_ids
    fact = next(item for item in result.requirements if item.requirement_id == "req-failover")
    assert CTRL_TELEMETRY_FAILOVER in fact.exceptioned_control_ids
    assert "exceptioned_telemetry_control" in fact.blind_spot_reasons


def test_alert_path_outage_is_an_explicit_critical_blind_spot():
    result = _evaluate(build_fixture(route_overrides={"route-secret-access": {"alert_path_operational": False}}))
    assert result.blind_spot_requirement_count == 1
    assert result.critical_blind_spot_count == 1
    assert result.alerting_blind_spot_count == 1
    assert result.max_blind_spot_risk_score == 109
    fact = next(item for item in result.requirements if item.requirement_id == "req-secret-access")
    assert fact.severity == TelemetrySeverity.CRITICAL
    assert fact.blind_spot_reasons == ("alert_path_unavailable",)


def test_missing_fallback_coverage_is_not_hidden_by_healthy_primary_telemetry():
    result = _evaluate(build_fixture(route_overrides={"route-tool-execution": {"covered_fallback_scenario_ids": ()}}))
    assert result.blind_spot_requirement_count == 1
    assert result.fallback_blind_spot_count == 1
    assert result.max_blind_spot_risk_score == 105
    fact = next(item for item in result.requirements if item.requirement_id == "req-tool-execution")
    assert fact.missing_fallback_scenario_ids == ("scenario-tool-unavailable",)
    assert "fallback_observability_gap" in fact.blind_spot_reasons


def test_chain_tamper_evidence_creates_integrity_blind_spot():
    result = _evaluate(build_fixture(route_overrides={"route-model-release": {"chain_integrity_valid": False}}))
    assert result.blind_spot_requirement_count == 1
    assert result.integrity_blind_spot_count == 1
    assert result.max_blind_spot_risk_score == 115
    fact = next(item for item in result.requirements if item.requirement_id == "req-model-release")
    assert fact.chain_integrity_valid is False
    assert fact.blind_spot_reasons == ("telemetry_chain_integrity_invalid",)


def test_not_evaluated_alert_control_remains_visible():
    result = _evaluate(build_fixture(not_evaluated_control=CTRL_ALERT_ROUTING))
    assert result.blind_spot_requirement_count == 9
    assert result.critical_blind_spot_count == 7
    assert result.max_blind_spot_risk_score == 101
    assert all(
        "not_evaluated_telemetry_control" in item.blind_spot_reasons
        for item in result.requirements
        if item.blind_spot
    )


def test_evaluation_metrics_hold():
    metrics = run_evaluation()["metrics"]
    total = len(adversarial_cases())
    assert metrics["vulnerable_asr"] == f"{total}/{total}"
    assert metrics["hardened_asr"] == f"0/{total}"
    assert metrics["hardened_fpr"] == "0/3"
    assert metrics["safe_task_rate"] == "3/3"
