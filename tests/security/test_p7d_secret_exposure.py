from __future__ import annotations

import pytest

from aegis.architecture.secrets_exposure import (
    SecretExposureRejected,
    SecretSensitivity,
    SecretsCredentialTrustRootExposureAnalyzer,
)
from evals.p7d_fixture import (
    CTRL_BUILD_SECRET,
    CTRL_TELEMETRY_REDACTION,
    build_fixture,
)
from evals.p7d_secret_exposure import adversarial_cases
from evals.p7d_secret_exposure_run import run_evaluation


def _evaluate(fixture):
    return SecretsCredentialTrustRootExposureAnalyzer(fixture["policy"]).evaluate(
        fixture["request"],
        fixture["manifest"],
        fixture["architecture"],
        fixture["p7a"],
        fixture["p7b"],
        fixture["p7c"],
        fixture["posture"],
    )


@pytest.mark.parametrize("name,mutation", adversarial_cases(), ids=lambda item: item if isinstance(item, str) else None)
def test_adversarial_secret_exposure_cases_reject(name, mutation):
    fixture = mutation(build_fixture())
    with pytest.raises(SecretExposureRejected):
        _evaluate(fixture)


def test_all_satisfied_secret_paths_are_controlled():
    result = _evaluate(build_fixture())
    assert result.topology_path_count == 6
    assert result.exposed_path_count == 0
    assert result.controlled_path_count == 6
    assert result.max_blast_radius_score == 0
    assert result.caller_summary_trusted is False
    assert result.production_secret_discovery is False
    assert result.real_credential_use is False
    assert result.network_operations == 0


def test_build_secret_exception_is_explicitly_exposed():
    result = _evaluate(build_fixture(exceptioned_control=CTRL_BUILD_SECRET))
    assert result.exposed_path_count == 1
    assert result.controlled_path_count == 5
    assert result.critical_exposed_path_count == 0
    assert result.trust_root_exposed_path_count == 0
    assert result.max_blast_radius_score == 95
    path = next(item for item in result.paths if item.exposed)
    assert CTRL_BUILD_SECRET in path.exceptioned_control_ids
    assert path.secret_sensitivity == SecretSensitivity.HIGH


def test_telemetry_missing_evidence_is_not_treated_as_satisfied():
    result = _evaluate(build_fixture(not_evaluated_control=CTRL_TELEMETRY_REDACTION))
    assert result.exposed_path_count == 1
    assert result.max_blast_radius_score == 94
    path = next(item for item in result.paths if item.exposed)
    assert CTRL_TELEMETRY_REDACTION in path.not_evaluated_control_ids


def test_evaluation_metrics_hold():
    metrics = run_evaluation()["metrics"]
    total = len(adversarial_cases())
    assert metrics["vulnerable_asr"] == f"{total}/{total}"
    assert metrics["hardened_asr"] == f"0/{total}"
    assert metrics["hardened_fpr"] == "0/3"
    assert metrics["safe_task_rate"] == "3/3"
