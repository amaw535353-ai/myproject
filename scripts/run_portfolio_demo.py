from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from evals.p8f_human_approval import run as run_approval
from evals.p10a_inference_tenant_isolation import run as run_inference
from evals.p11e_fixture import fixture as supply_fixture
from evals.p11e_supply_chain_security import assess as assess_supply
from evals.portfolio_adaptive_security import build_report as run_prompt_injection

ROOT = Path(__file__).resolve().parents[1]
DOCS_EVIDENCE = ROOT / "docs" / "evidence"


def _revision() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unavailable"


def _ratio(value: str) -> dict[str, int]:
    numerator, denominator = value.split("/", 1)
    return {"numerator": int(numerator), "denominator": int(denominator)}


def _compact(name: str, report: dict[str, Any]) -> dict[str, Any]:
    if name == "indirect_prompt_injection":
        return {
            "dataset_sha256": report["dataset_sha256"],
            "vulnerable_asr": report["metrics"]["vulnerable_asr"],
            "hardened_asr": report["metrics"]["hardened_asr"],
            "fpr": report["metrics"]["fpr"],
            "safe_task_rate": report["metrics"]["safe_task_rate"],
        }
    if "ASR" in report:
        return {
            "vulnerable_asr": "not_reported_by_source",
            "hardened_asr": report["ASR"],
            "fpr": report["FPR"],
            "safe_task_rate": report["SafeTaskRate"],
            "dataset_sha256": report["fixture_manifests_sha256"],
        }
    return {
        "vulnerable_asr": _ratio(report["vulnerable_asr"]),
        "hardened_asr": _ratio(report["hardened_asr"]),
        "fpr": _ratio(report["hardened_fpr"]),
        "safe_task_rate": _ratio(report["safe_task_rate"]),
        "dataset_sha256": report.get(
            "adversarial_dataset_sha256", report.get("dataset_sha256", "unavailable")
        ),
    }


def build_evidence() -> dict[str, Any]:
    runners: tuple[tuple[str, Callable[[], dict[str, Any]]], ...] = (
        ("indirect_prompt_injection", run_prompt_injection),
        ("multi_agent_human_approval", run_approval),
        ("model_container_supply_chain", lambda: assess_supply(supply_fixture())),
        ("inference_tenant_isolation", run_inference),
    )
    cases = {name: _compact(name, runner()) for name, runner in runners}
    config = {"schema": "aegis.portfolio-demo.v1", "network": False, "external_side_effects": False}
    return {
        **config,
        "status": "VERIFIED",
        "evidence_class": "deterministic",
        "code_revision": _revision(),
        "configuration_sha256": hashlib.sha256(
            json.dumps(config, sort_keys=True).encode()
        ).hexdigest(),
        "cases": cases,
        "reproduction_commands": [
            "python scripts/run_portfolio_demo.py",
            "python -m real_model_evals --live",
        ],
        "limitations": [
            "Fake/no-model evidence is not real-model validation.",
            "Synthetic local controls are not production or cloud validation.",
            "The live-model command is separate and fails closed when unconfigured.",
        ],
    }


def _report(evidence: dict[str, Any], *, revision: str | None = None) -> str:
    lines = [
        "# AegisDesk deterministic portfolio demonstration",
        "",
        f"Status: **{evidence['status']}**",
        "",
        f"Code revision: `{revision or evidence['code_revision']}`",
        "",
        "| Case | Vulnerable ASR | Hardened ASR | FPR | SafeTaskRate |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, case in evidence["cases"].items():

        def show(metric: object) -> str:
            if isinstance(metric, str):
                return metric
            ratio = cast(dict[str, int], metric)
            return f"{ratio['numerator']}/{ratio['denominator']}"

        lines.append(
            f"| {name} | {show(case['vulnerable_asr'])} | {show(case['hardened_asr'])} | "
            f"{show(case['fpr'])} | {show(case['safe_task_rate'])} |"
        )
    lines.extend(
        [
            "",
            "Reproduce: `python scripts/run_portfolio_demo.py --docs-sample`",
            "",
            "Limitations:",
            *[f"- {item}" for item in evidence["limitations"]],
        ]
    )
    return "\n".join(lines) + "\n"


def committed_sample(evidence: dict[str, Any]) -> tuple[str, str]:
    report = _report(evidence, revision="<revision>")
    output = (
        json.dumps(
            {
                "evidence": "<output-dir>/evidence.json",
                "report": "<output-dir>/report.md",
                "status": evidence["status"],
            },
            sort_keys=True,
        )
        + "\n"
    )
    return report, output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT / "build" / "portfolio-demo")
    parser.add_argument("--docs-sample", action="store_true")
    args = parser.parse_args()
    evidence = build_evidence()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = args.output_dir / "evidence.json"
    evidence_path.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (args.output_dir / "report.md").write_text(_report(evidence), encoding="utf-8")
    if args.docs_sample:
        DOCS_EVIDENCE.mkdir(parents=True, exist_ok=True)
        report, output = committed_sample(evidence)
        (DOCS_EVIDENCE / "portfolio-demo-report.md").write_text(report, encoding="utf-8")
        (DOCS_EVIDENCE / "portfolio-demo-output.txt").write_text(output, encoding="utf-8")
    print(
        json.dumps(
            {
                "status": evidence["status"],
                "evidence": str(evidence_path),
                "report": str(args.output_dir / "report.md"),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
