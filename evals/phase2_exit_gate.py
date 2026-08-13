import hashlib
import json
from collections import Counter
from pathlib import Path

from aegis.mcp_gateway.models import ToolName
from aegis.security.default_surfaces import (
    DEFAULT_AGENT_TOOL_NAMES,
    DEFAULT_EXTERNAL_SURFACE_POLICY,
    DEFAULT_SURFACE_RULES,
    P3C_POLICY_VERSION,
    DefaultSurfacePolicyError,
)
from aegis.security.phase2_controls import PHASE2_CONTROLS, PHASE3_GAPS, DeploymentStatus, expected_phase2_milestones
from apps.api.main import app

ROOT = Path(__file__).resolve().parents[1]

_P3C_LAB_IMPLEMENTATIONS = {
    "outbound_network": "aegis/vulnerable/ssrf.py",
    "artifact_ingestion": "aegis/vulnerable/artifact_handling.py",
    "browser_navigation": "aegis/vulnerable/browser_prompt_injection.py",
}


def build_p3c_surface_posture_report() -> dict[str, object]:
    api_paths = tuple(sorted({route.path for route in app.routes}))
    tool_names = tuple(sorted(tool.value for tool in ToolName))

    tool_contract_ok = True
    route_contract_ok = True
    try:
        DEFAULT_EXTERNAL_SURFACE_POLICY.assert_tool_catalog(tool_names)
    except DefaultSurfacePolicyError:
        tool_contract_ok = False
    try:
        DEFAULT_EXTERNAL_SURFACE_POLICY.assert_api_paths(api_paths)
    except DefaultSurfacePolicyError:
        route_contract_ok = False

    adversarial: list[dict[str, object]] = []
    for rule in DEFAULT_SURFACE_RULES:
        route_exposed = any(
            marker in path.casefold()
            for path in api_paths
            for marker in rule.api_path_markers
        )
        tool_exposed = any(
            marker in name.casefold()
            for name in tool_names
            for marker in rule.tool_name_markers
        )
        lab_path = _P3C_LAB_IMPLEMENTATIONS[rule.surface.value]
        implicit_baseline_success = (ROOT / lab_path).is_file()
        hardened_success = rule.default_enabled or route_exposed or tool_exposed
        adversarial.append(
            {
                "surface": rule.surface.value,
                "implicit_baseline_success": implicit_baseline_success,
                "hardened_success": hardened_success,
                "default_enabled": rule.default_enabled,
                "route_exposed": route_exposed,
                "tool_exposed": tool_exposed,
                "lab_implementation_present": implicit_baseline_success,
            }
        )

    benign = [
        {
            "tool": name,
            "safe_completion": name in tool_names,
        }
        for name in ("search_knowledge_base", "get_my_assets")
    ]
    baseline_asr_num = sum(bool(item["implicit_baseline_success"]) for item in adversarial)
    hardened_asr_num = sum(bool(item["hardened_success"]) for item in adversarial)
    hardened_fpr_num = sum(not bool(item["safe_completion"]) for item in benign)
    safe_task_num = sum(bool(item["safe_completion"]) for item in benign)

    dataset_payload = json.dumps(
        {
            "external_surfaces": [item["surface"] for item in adversarial],
            "benign_default_tools": [item["tool"] for item in benign],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    passed = (
        baseline_asr_num == 3
        and hardened_asr_num == 0
        and hardened_fpr_num == 0
        and safe_task_num == 2
        and tool_contract_ok
        and route_contract_ok
        and tuple(sorted(tool_names)) == tuple(sorted(DEFAULT_AGENT_TOOL_NAMES))
    )
    return {
        "evaluation": "P3-C explicit non-default external surface posture",
        "policy_version": P3C_POLICY_VERSION,
        "dataset_sha256": hashlib.sha256(dataset_payload).hexdigest(),
        "baseline_definition": "implicit exposure baseline treats any available lab implementation as default-reachable",
        "adversarial": adversarial,
        "benign": benign,
        "metrics": {
            "implicit_baseline_asr": [baseline_asr_num, 3],
            "hardened_asr": [hardened_asr_num, 3],
            "hardened_fpr": [hardened_fpr_num, 2],
            "hardened_safe_task_rate": [safe_task_num, 2],
        },
        "default_tool_contract_ok": tool_contract_ok,
        "default_route_contract_ok": route_contract_ok,
        "default_api_route_count": len(api_paths),
        "default_tool_count": len(tool_names),
        "real_network_requests": False,
        "real_artifacts_processed": False,
        "real_browser_navigation": False,
        "passed": passed,
    }


def build_report() -> dict[str, object]:
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    ids = tuple(item.milestone for item in PHASE2_CONTROLS)
    missing_docs = [item.milestone for item in PHASE2_CONTROLS if not (ROOT / item.threat_model).is_file()]
    missing_evals = [item.milestone for item in PHASE2_CONTROLS if not ROOT.joinpath(*item.eval_module.split(".")).with_suffix(".py").is_file()]
    missing_ci = [item.milestone for item in PHASE2_CONTROLS if item.eval_command not in ci]
    missing_runtime = [f"{item.milestone}:{path}" for item in PHASE2_CONTROLS for path in item.runtime_evidence if not (ROOT / path).is_file()]
    unknown_gaps = sorted({gap for item in PHASE2_CONTROLS for gap in item.phase3_gaps if gap not in PHASE3_GAPS})
    ungoverned_non_default = [
        item.milestone
        for item in PHASE2_CONTROLS
        if item.deployment_status is not DeploymentStatus.DEFAULT_API
        and not item.phase3_gaps
        and not item.runtime_evidence
    ]
    checks = {
        "milestones_complete_and_ordered": ids == expected_phase2_milestones(),
        "threat_models_present": not missing_docs,
        "evaluations_present": not missing_evals,
        "ci_runs_every_phase2_evaluation": not missing_ci,
        "runtime_evidence_paths_present": not missing_runtime,
        "gap_references_known": not unknown_gaps,
        "every_non_default_control_has_gap_or_runtime_posture": not ungoverned_non_default,
    }
    payload = "\n".join(f"{item.milestone}|{item.threat_model}|{item.eval_module}|{item.deployment_status.value}|{','.join(item.phase3_gaps)}" for item in PHASE2_CONTROLS)
    return {
        "evaluation": "Phase 2 exit control/evidence gate",
        "phase2_control_count": len(PHASE2_CONTROLS),
        "deployment_status_counts": dict(sorted(Counter(item.deployment_status.value for item in PHASE2_CONTROLS).items())),
        "phase3_gap_count": len(PHASE3_GAPS),
        "registry_hash_sha256": hashlib.sha256(payload.encode()).hexdigest(),
        "checks": checks,
        "failures": {"missing_docs": missing_docs, "missing_evals": missing_evals, "missing_ci": missing_ci, "missing_runtime": missing_runtime, "unknown_gaps": unknown_gaps, "ungoverned_non_default": ungoverned_non_default},
        "phase2_exit_gate_passed": all(checks.values()),
        "scope_note": "Evidence-complete does not mean every control is default-runtime or production-ready.",
    }


def main() -> int:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["phase2_exit_gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
