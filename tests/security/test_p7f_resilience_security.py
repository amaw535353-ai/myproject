from __future__ import annotations

import pytest

from aegis.architecture.resilience_security import (
    DependencyFailureSecurityAnalyzer,
    FallbackMode,
    ResilienceSecurityRejected,
)
from evals.p7f_fixture import (
    CTRL_CACHE_INTEGRITY,
    CTRL_FAIL_CLOSED,
    CTRL_FALLBACK_AUTHZ,
    build_fixture,
)
from evals.p7f_resilience_security import adversarial_cases, run_evaluation


def _evaluate(fixture):
    return DependencyFailureSecurityAnalyzer(fixture["policy"]).evaluate(
        fixture["request"],
        fixture["manifest"],
        fixture["p7e"],
        fixture["posture"],
    )


@pytest.mark.parametrize("name,mutation", adversarial_cases(), ids=lambda value: value if isinstance(value, str) else None)
def test_adversarial_resilience_cases_reject(name, mutation):
    fixture = mutation(build_fixture())
    with pytest.raises(ResilienceSecurityRejected):
        _evaluate(fixture)


def test_all_satisfied_fallbacks_preserve_security():
    result = _evaluate(build_fixture())
    assert result.scenario_count == 7
    assert result.exposed_scenario_count == 0
    assert result.controlled_scenario_count == 7
    assert result.service_continuity_scenario_count == 5
    assert result.fail_closed_scenario_count == 2
    assert result.max_security_risk_score == 0
    assert result.caller_summary_trusted is False
    assert result.production_dependency_health_monitoring is False
    assert result.production_failover_orchestration is False
    assert result.live_chaos_testing is False
    assert result.network_operations == 0


def test_cache_control_exception_exposes_only_cache_scenarios():
    result = _evaluate(build_fixture(exceptioned_control=CTRL_CACHE_INTEGRITY))
    assert result.exposed_scenario_count == 2
    assert result.controlled_scenario_count == 5
    assert set(result.prioritized_exposed_scenario_ids) == {
        "scenario-telemetry-degraded",
        "scenario-registry-unavailable",
    }
    assert result.max_security_risk_score == 68
    assert result.critical_dependency_exposed_scenario_count == 0


def test_fallback_authorization_not_evaluated_exposes_model_continuity_paths():
    result = _evaluate(build_fixture(not_evaluated_control=CTRL_FALLBACK_AUTHZ))
    assert result.exposed_scenario_count == 3
    assert result.controlled_scenario_count == 4
    assert result.untrusted_dependency_exposed_scenario_count == 1
    assert result.max_security_risk_score == 73
    assert "scenario-model-untrusted" in result.prioritized_exposed_scenario_ids


def test_fail_closed_remains_security_preserving_when_no_operation_proceeds():
    result = _evaluate(build_fixture(exceptioned_control=CTRL_FAIL_CLOSED))
    assert result.exposed_scenario_count == 0
    fail_closed = [item for item in result.scenarios if item.fallback_mode == FallbackMode.FAIL_CLOSED]
    assert len(fail_closed) == 2
    assert all(not item.service_continuity_expected for item in fail_closed)
    assert all(item.security_preserved for item in fail_closed)
    assert all(CTRL_FAIL_CLOSED in item.exceptioned_control_ids for item in fail_closed)


def test_stale_telemetry_cache_is_visible_as_security_degradation():
    result = _evaluate(build_fixture(stale_cache_fallback_id="fallback-telemetry-cache"))
    assert result.exposed_scenario_count == 1
    assert result.max_security_risk_score == 56
    fact = next(item for item in result.scenarios if item.scenario_id == "scenario-telemetry-degraded")
    assert fact.exposed is True
    assert fact.cache_age_seconds == 900
    assert "stale_cache_fallback" in fact.exposure_reasons


def test_evaluation_metrics_hold():
    metrics = run_evaluation()["metrics"]
    total = len(adversarial_cases())
    assert metrics["vulnerable_asr"] == f"{total}/{total}"
    assert metrics["hardened_asr"] == f"0/{total}"
    assert metrics["hardened_fpr"] == "0/3"
    assert metrics["safe_task_rate"] == "3/3"
