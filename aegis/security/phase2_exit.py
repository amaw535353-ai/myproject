from __future__ import annotations

import json
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = Path("docs/security/phase2-control-evidence.json")
EXIT_REVIEW_PATH = Path("docs/security/phase2-exit-review.md")
GAP_REGISTER_PATH = Path("docs/security/phase3-gap-register.md")
CI_PATH = Path(".github/workflows/ci.yml")
PYPROJECT_PATH = Path("pyproject.toml")
API_MAIN_PATH = Path("apps/api/main.py")

EXPECTED_CONTROL_IDS = tuple(
    [f"P2-{letter}" for letter in "ABCDEFGHIJ"]
    + [f"P2-{letter}" for letter in "KLMNOPQRS"]
)
EXPECTED_RUNTIME_STATUS = {
    "P2-A": "default_api",
    "P2-B": "default_api",
    "P2-C": "component_only",
    "P2-D": "component_only",
    "P2-E": "component_only",
    "P2-F": "component_only",
    "P2-G": "component_only",
    "P2-H": "default_api",
    "P2-I": "component_only",
    "P2-J": "component_only",
    "P2-K": "default_api",
    "P2-L": "default_api",
    "P2-M": "default_api",
    "P2-N": "evaluation_only",
    "P2-O": "evaluation_only",
    "P2-P": "evaluation_only",
    "P2-Q": "evaluation_only",
    "P2-R": "evaluation_only",
    "P2-S": "evaluation_only",
}
ALLOWED_RUNTIME_STATUS = frozenset({"default_api", "component_only", "evaluation_only"})
ALLOWED_GAP_SEVERITY = frozenset({"critical", "high", "medium", "low"})


class Phase2ExitRegistryError(RuntimeError):
    """Raised when the committed Phase 2 exit evidence is inconsistent."""


def load_registry(root: Path = REPOSITORY_ROOT) -> dict[str, Any]:
    return json.loads((root / REGISTRY_PATH).read_text(encoding="utf-8"))


def _package_version(root: Path) -> str:
    with (root / PYPROJECT_PATH).open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def _api_version(root: Path) -> str | None:
    text = (root / API_MAIN_PATH).read_text(encoding="utf-8")
    match = re.search(r"FastAPI\([^\n]*version=\"([^\"]+)\"", text)
    return None if match is None else match.group(1)


def validate_registry_data(data: dict[str, Any], root: Path = REPOSITORY_ROOT) -> list[str]:
    errors: list[str] = []

    if data.get("schema_version") != "aegis.phase2-control-evidence.v1":
        errors.append("unexpected schema_version")

    release_version = data.get("release_version")
    if not isinstance(release_version, str) or not release_version:
        errors.append("release_version must be a non-empty string")

    exit_state = data.get("phase2_exit")
    if not isinstance(exit_state, dict):
        errors.append("phase2_exit must be an object")
    else:
        if exit_state.get("decision") != "pass-for-deterministic-local-lab-objectives":
            errors.append("Phase 2 exit decision must remain explicit")
        if exit_state.get("phase3_entry") != "ready-with-open-integration-gaps":
            errors.append("Phase 3 entry state must remain explicit")
        if exit_state.get("production_readiness") is not False:
            errors.append("the registry must not claim production readiness")

    controls = data.get("controls")
    if not isinstance(controls, list):
        return errors + ["controls must be a list"]

    control_ids = [control.get("id") for control in controls if isinstance(control, dict)]
    if tuple(control_ids) != EXPECTED_CONTROL_IDS:
        errors.append(
            "control IDs must be the exact ordered Phase 2 set P2-A through P2-S"
        )
    if len(control_ids) != len(set(control_ids)):
        errors.append("control IDs must be unique")

    represented_threat_models: set[str] = set()
    for control in controls:
        if not isinstance(control, dict):
            errors.append("every control must be an object")
            continue
        control_id = control.get("id")
        runtime_status = control.get("runtime_status")
        if runtime_status not in ALLOWED_RUNTIME_STATUS:
            errors.append(f"{control_id}: invalid runtime_status")
        expected_status = EXPECTED_RUNTIME_STATUS.get(str(control_id))
        if expected_status is not None and runtime_status != expected_status:
            errors.append(
                f"{control_id}: runtime_status must be {expected_status} until runtime wiring changes"
            )

        required_text = ("title", "security_property", "vulnerable_path", "threat_model", "eval_module", "phase3_action")
        for field in required_text:
            if not isinstance(control.get(field), str) or not control[field].strip():
                errors.append(f"{control_id}: {field} must be a non-empty string")

        implementation_paths = control.get("implementation_paths")
        if not isinstance(implementation_paths, list) or not implementation_paths:
            errors.append(f"{control_id}: implementation_paths must be a non-empty list")
        else:
            for path in implementation_paths:
                if not isinstance(path, str) or not (root / path).is_file():
                    errors.append(f"{control_id}: missing implementation path {path!r}")

        vulnerable_path = control.get("vulnerable_path")
        if isinstance(vulnerable_path, str):
            if not vulnerable_path.startswith("aegis/vulnerable/"):
                errors.append(f"{control_id}: vulnerable baseline must stay under aegis/vulnerable/")
            if not (root / vulnerable_path).is_file():
                errors.append(f"{control_id}: missing vulnerable path {vulnerable_path}")

        threat_model = control.get("threat_model")
        if isinstance(threat_model, str):
            represented_threat_models.add(threat_model)
            if not (root / threat_model).is_file():
                errors.append(f"{control_id}: missing threat model {threat_model}")

        eval_module = control.get("eval_module")
        if isinstance(eval_module, str):
            module_path = Path(*eval_module.split(".")).with_suffix(".py")
            if not (root / module_path).is_file():
                errors.append(f"{control_id}: missing eval module {eval_module}")

    actual_phase2_threat_models = {
        str(path.relative_to(root)).replace("\\", "/")
        for path in (root / "docs/threat-model").glob("p2*.md")
    }
    if represented_threat_models != actual_phase2_threat_models:
        missing = sorted(actual_phase2_threat_models - represented_threat_models)
        extra = sorted(represented_threat_models - actual_phase2_threat_models)
        errors.append(
            f"threat-model registry drift: unregistered={missing}, missing_files={extra}"
        )

    gaps = data.get("phase3_gaps")
    if not isinstance(gaps, list) or not gaps:
        errors.append("phase3_gaps must be a non-empty list")
    else:
        gap_ids: list[str] = []
        for gap in gaps:
            if not isinstance(gap, dict):
                errors.append("every Phase 3 gap must be an object")
                continue
            gap_id = gap.get("id")
            if isinstance(gap_id, str):
                gap_ids.append(gap_id)
            else:
                errors.append("every Phase 3 gap must have a string id")
            if gap.get("status") != "open":
                errors.append(f"{gap_id}: exit gate contains only open Phase 3 gaps")
            if gap.get("severity") not in ALLOWED_GAP_SEVERITY:
                errors.append(f"{gap_id}: invalid severity")
            for field in ("title", "risk"):
                if not isinstance(gap.get(field), str) or not gap[field].strip():
                    errors.append(f"{gap_id}: {field} must be a non-empty string")
            for field in ("acceptance_criteria", "evidence_required"):
                value = gap.get(field)
                if not isinstance(value, list) or not value or not all(isinstance(item, str) and item.strip() for item in value):
                    errors.append(f"{gap_id}: {field} must be a non-empty string list")
        if len(gap_ids) != len(set(gap_ids)):
            errors.append("Phase 3 gap IDs must be unique")
        if "P3-G01" not in gap_ids or "P3-G02" not in gap_ids:
            errors.append("critical runtime-integration and write-exclusivity gaps must be tracked")

    return errors


def validate_repository(root: Path = REPOSITORY_ROOT) -> list[str]:
    errors: list[str] = []
    data = load_registry(root)
    errors.extend(validate_registry_data(data, root))

    release_version = data.get("release_version")
    package_version = _package_version(root)
    api_version = _api_version(root)
    if release_version != package_version:
        errors.append(
            f"release version drift: registry={release_version!r}, package={package_version!r}"
        )
    if api_version != package_version:
        errors.append(
            f"release version drift: FastAPI={api_version!r}, package={package_version!r}"
        )

    for required_doc in (EXIT_REVIEW_PATH, GAP_REGISTER_PATH):
        if not (root / required_doc).is_file():
            errors.append(f"missing Phase 2 exit artifact {required_doc}")

    ci_text = (root / CI_PATH).read_text(encoding="utf-8")
    if "python -m aegis.security.phase2_exit" not in ci_text:
        errors.append("CI must run the Phase 2 exit control/evidence registry gate")
    for control in data.get("controls", []):
        if isinstance(control, dict) and isinstance(control.get("eval_module"), str):
            command = f"python -m {control['eval_module']}"
            if command not in ci_text:
                errors.append(f"CI missing deterministic evaluation: {command}")

    return errors


def summary(data: dict[str, Any]) -> dict[str, Any]:
    statuses = Counter(control["runtime_status"] for control in data["controls"])
    severities = Counter(gap["severity"] for gap in data["phase3_gaps"])
    return {
        "schema_version": data["schema_version"],
        "release_version": data["release_version"],
        "phase2_exit": data["phase2_exit"]["decision"],
        "phase3_entry": data["phase2_exit"]["phase3_entry"],
        "controls": len(data["controls"]),
        "runtime_status_counts": dict(sorted(statuses.items())),
        "open_phase3_gaps": len(data["phase3_gaps"]),
        "gap_severity_counts": dict(sorted(severities.items())),
        "production_readiness": data["phase2_exit"]["production_readiness"],
    }


def main() -> int:
    errors = validate_repository(REPOSITORY_ROOT)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary(load_registry(REPOSITORY_ROOT)), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
