from importlib.metadata import version

from apps.api.main import app
from aegis.security.phase2_controls import PHASE2_CONTROLS, PHASE3_GAPS, DeploymentStatus, expected_phase2_milestones
from evals.phase2_exit_gate import build_report


def test_phase2_registry_is_complete_and_ordered() -> None:
    assert tuple(item.milestone for item in PHASE2_CONTROLS) == expected_phase2_milestones()
    assert len(PHASE2_CONTROLS) == 19


def test_phase2_registry_classifies_runtime_posture() -> None:
    counts = {status: sum(item.deployment_status is status for item in PHASE2_CONTROLS) for status in DeploymentStatus}
    assert counts == {
        DeploymentStatus.DEFAULT_API: 7,
        DeploymentStatus.PARTIAL_DEFAULT_API: 1,
        DeploymentStatus.LAB_ONLY: 11,
    }


def test_non_default_controls_have_explicit_phase3_gap() -> None:
    for item in PHASE2_CONTROLS:
        if item.deployment_status is DeploymentStatus.DEFAULT_API:
            continue
        assert item.phase3_gaps
        assert set(item.phase3_gaps) <= set(PHASE3_GAPS)


def test_phase2_exit_gate_has_no_missing_evidence() -> None:
    report = build_report()
    assert report["phase2_exit_gate_passed"] is True
    assert all(report["checks"].values())
    assert not any(report["failures"].values())


def test_fastapi_version_tracks_installed_package_version() -> None:
    assert app.version == version("aegisdesk")
