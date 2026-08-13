from __future__ import annotations

from copy import deepcopy

from aegis.security.phase2_exit import (
    EXPECTED_CONTROL_IDS,
    EXPECTED_RUNTIME_STATUS,
    REPOSITORY_ROOT,
    load_registry,
    summary,
    validate_registry_data,
    validate_repository,
)


def test_phase2_exit_registry_validates_repository() -> None:
    assert validate_repository(REPOSITORY_ROOT) == []


def test_phase2_exit_registry_covers_exact_phase2_sequence() -> None:
    registry = load_registry(REPOSITORY_ROOT)
    assert tuple(control["id"] for control in registry["controls"]) == EXPECTED_CONTROL_IDS
    assert {
        control["id"]: control["runtime_status"] for control in registry["controls"]
    } == EXPECTED_RUNTIME_STATUS


def test_phase2_exit_summary_keeps_promotion_gap_explicit() -> None:
    report = summary(load_registry(REPOSITORY_ROOT))
    assert report["controls"] == 19
    assert report["runtime_status_counts"] == {
        "component_only": 7,
        "default_api": 6,
        "evaluation_only": 6,
    }
    assert report["open_phase3_gaps"] == 5
    assert report["gap_severity_counts"] == {
        "critical": 2,
        "high": 2,
        "medium": 1,
    }
    assert report["production_readiness"] is False


def test_phase2_exit_registry_fails_closed_on_missing_control() -> None:
    registry = deepcopy(load_registry(REPOSITORY_ROOT))
    registry["controls"] = registry["controls"][:-1]
    errors = validate_registry_data(registry, REPOSITORY_ROOT)
    assert any("exact ordered Phase 2 set" in error for error in errors)


def test_phase2_exit_registry_fails_closed_on_runtime_promotion_without_review() -> None:
    registry = deepcopy(load_registry(REPOSITORY_ROOT))
    p2s = next(control for control in registry["controls"] if control["id"] == "P2-S")
    p2s["runtime_status"] = "default_api"
    errors = validate_registry_data(registry, REPOSITORY_ROOT)
    assert any("P2-S: runtime_status must be evaluation_only" in error for error in errors)


def test_phase2_exit_registry_requires_isolated_comparison_baseline() -> None:
    registry = deepcopy(load_registry(REPOSITORY_ROOT))
    p2a = registry["controls"][0]
    p2a["vulnerable_path"] = "aegis/rag/store.py"
    errors = validate_registry_data(registry, REPOSITORY_ROOT)
    assert any("must stay under aegis/vulnerable/" in error for error in errors)
