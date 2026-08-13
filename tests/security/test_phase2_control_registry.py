from importlib.metadata import version

from apps.api.main import app
from aegis.security.phase2_controls import PHASE2_CONTROLS, PHASE3_GAPS, DeploymentStatus, expected_phase2_milestones
from evals.phase2_exit_gate import build_p3c_surface_posture_report, build_report


def test_phase2_registry_is_complete_and_ordered() -> None:
    assert tuple(item.milestone for item in PHASE2_CONTROLS) == expected_phase2_milestones()
    assert len(PHASE2_CONTROLS) == 19


def test_phase2_registry_classifies_runtime_posture() -> None:
    counts = {status: sum(item.deployment_status is status for item in PHASE2_CONTROLS) for status in DeploymentStatus}
    assert counts == {
        DeploymentStatus.DEFAULT_API: 15,
        DeploymentStatus.PARTIAL_DEFAULT_API: 0,
        DeploymentStatus.LAB_ONLY: 4,
    }


def test_non_default_controls_have_gap_or_explicit_runtime_posture() -> None:
    for item in PHASE2_CONTROLS:
        if item.deployment_status is DeploymentStatus.DEFAULT_API:
            continue
        assert item.phase3_gaps or item.runtime_evidence
        assert set(item.phase3_gaps) <= set(PHASE3_GAPS)


def test_p3a_p3b_p3c_and_p3d_closed_runtime_gaps() -> None:
    assert "P3-G01" not in PHASE3_GAPS
    assert "P3-G02" not in PHASE3_GAPS
    assert "P3-G03" not in PHASE3_GAPS
    assert "P3-G04" not in PHASE3_GAPS
    assert len(PHASE3_GAPS) == 2

    p2d = PHASE2_CONTROLS[3]
    assert p2d.deployment_status is DeploymentStatus.DEFAULT_API
    assert "aegis/downstream/credential_broker.py" in p2d.runtime_evidence
    assert "aegis/mcp_gateway/gateway.py" in p2d.runtime_evidence

    p2g = PHASE2_CONTROLS[6]
    assert p2g.deployment_status is DeploymentStatus.DEFAULT_API
    assert "aegis/agent/default_budgeted_runner.py" in p2g.runtime_evidence

    for item in PHASE2_CONTROLS[13:19]:
        assert item.deployment_status is DeploymentStatus.DEFAULT_API
        assert "aegis/effects/default_high_impact.py" in item.runtime_evidence

    for item in (PHASE2_CONTROLS[4], PHASE2_CONTROLS[8], PHASE2_CONTROLS[9]):
        assert item.deployment_status is DeploymentStatus.LAB_ONLY
        assert not item.phase3_gaps
        assert "aegis/security/default_surfaces.py" in item.runtime_evidence
        assert "apps/api/dependencies.py" in item.runtime_evidence


def test_p3c_default_surface_posture_metrics_are_exact() -> None:
    report = build_p3c_surface_posture_report()
    assert report["metrics"] == {
        "implicit_baseline_asr": [3, 3],
        "hardened_asr": [0, 3],
        "hardened_fpr": [0, 2],
        "hardened_safe_task_rate": [2, 2],
    }
    assert report["default_tool_contract_ok"] is True
    assert report["default_route_contract_ok"] is True
    assert report["real_network_requests"] is False
    assert report["real_artifacts_processed"] is False
    assert report["real_browser_navigation"] is False
    assert report["passed"] is True


def test_phase2_exit_gate_has_no_missing_evidence() -> None:
    report = build_report()
    assert report["phase2_exit_gate_passed"] is True
    assert all(report["checks"].values())
    assert not any(report["failures"].values())


def test_fastapi_version_tracks_installed_package_version() -> None:
    assert app.version == version("aegisdesk")
