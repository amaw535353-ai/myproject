from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass, replace
from typing import Any

from aegis.model_supply_chain.package_provenance import (
    ModelPackageComponentRole,
    VerifiedModelPackage,
)
from aegis.model_supply_chain.runtime_isolation import (
    ModelRuntimePlan,
    ModelRuntimeRequest,
    RestrictedModelRuntimeBoundary,
    RuntimeAdmissionRejected,
    RuntimeComponentPlan,
)
from aegis.vulnerable.model_runtime_isolation import VulnerableHostRuntimePlanner


_PACKAGE_ID = "helpdesk-runtime-package"
_MODEL_ID = "helpdesk-model"
_REVISION = "r4"
_RUNTIME_ID = "helpdesk-inference"
_PUBLISHER = "aegis-release-publisher"


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    scenario: str


ADVERSARIAL_ATTEMPTS = (
    Attempt("P5E-A1", "pickle_parser"),
    Attempt("P5E-A2", "dynamic_module"),
    Attempt("P5E-A3", "remote_code"),
    Attempt("P5E-A4", "native_extension"),
    Attempt("P5E-A5", "custom_operator"),
    Attempt("P5E-A6", "network_capability"),
    Attempt("P5E-A7", "subprocess_capability"),
    Attempt("P5E-A8", "host_filesystem_write"),
    Attempt("P5E-A9", "environment_passthrough"),
    Attempt("P5E-A10", "unsandboxed_mode"),
    Attempt("P5E-A11", "backend_injection"),
    Attempt("P5E-A12", "component_role_confusion"),
    Attempt("P5E-A13", "component_injection"),
    Attempt("P5E-A14", "resource_limit_escape"),
    Attempt("P5E-A15", "unverified_package_handle"),
)
BENIGN_ATTEMPTS = (
    Attempt("P5E-B1", "safetensors_sandbox"),
    Attempt("P5E-B2", "onnx_sandbox"),
    Attempt("P5E-B3", "bounded_low_resource_sandbox"),
)


def verified_package() -> VerifiedModelPackage:
    ids = ("model", "config", "tokenizer", "adapter", "quant", "shard")
    roles = (
        ModelPackageComponentRole.PRIMARY_MODEL.value,
        ModelPackageComponentRole.CONFIG.value,
        ModelPackageComponentRole.TOKENIZER.value,
        ModelPackageComponentRole.ADAPTER.value,
        ModelPackageComponentRole.QUANTIZATION_METADATA.value,
        ModelPackageComponentRole.EXTERNAL_DATA.value,
    )
    return VerifiedModelPackage(
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        package_publisher_id=_PUBLISHER,
        component_artifact_ids=ids,
        component_roles=roles,
        component_publishers=("aegis-model-publisher",) * len(ids),
    )


def runtime_request() -> ModelRuntimeRequest:
    return ModelRuntimeRequest(
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        runtime_id=_RUNTIME_ID,
    )


def safe_plan() -> ModelRuntimePlan:
    return ModelRuntimePlan(
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        runtime_id=_RUNTIME_ID,
        backend="sandboxed_tensor_runtime",
        components=(
            RuntimeComponentPlan(
                "model", ModelPackageComponentRole.PRIMARY_MODEL, "safetensors_reader"
            ),
            RuntimeComponentPlan(
                "config", ModelPackageComponentRole.CONFIG, "json_reader"
            ),
            RuntimeComponentPlan(
                "tokenizer", ModelPackageComponentRole.TOKENIZER, "json_reader"
            ),
            RuntimeComponentPlan(
                "adapter", ModelPackageComponentRole.ADAPTER, "safetensors_reader"
            ),
            RuntimeComponentPlan(
                "quant",
                ModelPackageComponentRole.QUANTIZATION_METADATA,
                "json_reader",
            ),
            RuntimeComponentPlan(
                "shard", ModelPackageComponentRole.EXTERNAL_DATA, "opaque_tensor_data"
            ),
        ),
    )


def _replace_component(
    plan: ModelRuntimePlan, artifact_id: str, **changes: Any
) -> ModelRuntimePlan:
    items = tuple(
        replace(item, **changes) if item.artifact_id == artifact_id else item
        for item in plan.components
    )
    return replace(plan, components=items)


def attack_cases() -> tuple[dict[str, Any], ...]:
    base = safe_plan()
    package = verified_package()
    return (
        {
            "attempt": ADVERSARIAL_ATTEMPTS[0],
            "package": package,
            "plan": _replace_component(base, "model", parser="pickle_loader"),
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[1],
            "package": package,
            "plan": _replace_component(
                base, "model", dynamic_module="repo.custom_model"
            ),
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[2],
            "package": package,
            "plan": _replace_component(base, "model", requires_remote_code=True),
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[3],
            "package": package,
            "plan": _replace_component(base, "model", native_extensions=True),
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[4],
            "package": package,
            "plan": _replace_component(base, "model", custom_ops=True),
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[5],
            "package": package,
            "plan": replace(
                base,
                capabilities=replace(base.capabilities, network_access=True),
            ),
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[6],
            "package": package,
            "plan": replace(
                base,
                capabilities=replace(base.capabilities, subprocess=True),
            ),
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[7],
            "package": package,
            "plan": replace(
                base,
                capabilities=replace(
                    base.capabilities, host_filesystem_write=True
                ),
            ),
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[8],
            "package": package,
            "plan": replace(
                base,
                capabilities=replace(
                    base.capabilities, environment_passthrough=True
                ),
            ),
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[9],
            "package": package,
            "plan": replace(base, isolation_mode="host-process"),
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[10],
            "package": package,
            "plan": replace(base, backend="python-subprocess-backend"),
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[11],
            "package": package,
            "plan": _replace_component(
                base,
                "config",
                role=ModelPackageComponentRole.TOKENIZER,
            ),
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[12],
            "package": package,
            "plan": replace(
                base,
                components=base.components
                + (
                    RuntimeComponentPlan(
                        "injected-plugin",
                        ModelPackageComponentRole.CONFIG,
                        "json_reader",
                    ),
                ),
            ),
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[13],
            "package": package,
            "plan": replace(base, memory_limit_mb=16384),
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[14],
            "package": replace(package, transitive_components_verified=False),
            "plan": base,
        },
    )


def benign_cases() -> tuple[dict[str, Any], ...]:
    base = safe_plan()
    onnx = _replace_component(base, "model", parser="onnx_reader")
    onnx = replace(onnx, backend="sandboxed_onnxruntime")
    low = replace(
        base,
        memory_limit_mb=512,
        cpu_time_limit_seconds=5,
        thread_limit=1,
    )
    package = verified_package()
    return (
        {"attempt": BENIGN_ATTEMPTS[0], "package": package, "plan": base},
        {"attempt": BENIGN_ATTEMPTS[1], "package": package, "plan": onnx},
        {"attempt": BENIGN_ATTEMPTS[2], "package": package, "plan": low},
    )


def dataset_hash() -> str:
    payload = json.dumps(
        {
            "adversarial": [asdict(item) for item in ADVERSARIAL_ATTEMPTS],
            "benign": [asdict(item) for item in BENIGN_ATTEMPTS],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def fixture_hash() -> str:
    package = asdict(verified_package())
    plan = asdict(safe_plan())
    payload = json.dumps(
        {"package": package, "plan": plan},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


P5E_DATASET_SHA256 = dataset_hash()
P5E_FIXTURE_SHA256 = fixture_hash()


def build_report() -> dict[str, Any]:
    vulnerable = VulnerableHostRuntimePlanner()
    hardened = RestrictedModelRuntimeBoundary()
    request = runtime_request()

    attack_rows: list[dict[str, Any]] = []
    vulnerable_successes = 0
    hardened_successes = 0
    for case in attack_cases():
        vulnerable.prepare(package=case["package"], plan=case["plan"])
        vulnerable_successes += 1
        reason = None
        try:
            hardened.admit(
                request=request,
                package=case["package"],
                plan=case["plan"],
            )
            hardened_successes += 1
        except RuntimeAdmissionRejected as exc:
            reason = exc.reason.value
        attack_rows.append(
            {
                "attempt_id": case["attempt"].attempt_id,
                "scenario": case["attempt"].scenario,
                "vulnerable_accepted": True,
                "hardened_accepted": reason is None,
                "hardened_reject_reason": reason,
            }
        )

    benign_rows: list[dict[str, Any]] = []
    benign_false_positives = 0
    safe_tasks = 0
    for case in benign_cases():
        try:
            handle = hardened.admit(
                request=request,
                package=case["package"],
                plan=case["plan"],
            )
        except RuntimeAdmissionRejected as exc:
            benign_false_positives += 1
            benign_rows.append(
                {
                    "attempt_id": case["attempt"].attempt_id,
                    "scenario": case["attempt"].scenario,
                    "accepted": False,
                    "reason": exc.reason.value,
                }
            )
        else:
            safe_tasks += 1
            benign_rows.append(
                {
                    "attempt_id": case["attempt"].attempt_id,
                    "scenario": case["attempt"].scenario,
                    "accepted": True,
                    "sandbox_required": handle.sandbox_required,
                    "model_executed": handle.model_executed,
                    "network_operations": handle.network_operations,
                }
            )

    return {
        "milestone": "P5-E",
        "policy_version": "model-runtime-isolation-remote-code-denial-v1",
        "dataset_sha256": P5E_DATASET_SHA256,
        "fixture_sha256": P5E_FIXTURE_SHA256,
        "metrics": {
            "adversarial_cases": len(ADVERSARIAL_ATTEMPTS),
            "vulnerable_asr": f"{vulnerable_successes}/{len(ADVERSARIAL_ATTEMPTS)}",
            "hardened_asr": f"{hardened_successes}/{len(ADVERSARIAL_ATTEMPTS)}",
            "hardened_fpr": f"{benign_false_positives}/{len(BENIGN_ATTEMPTS)}",
            "safe_task_rate": f"{safe_tasks}/{len(BENIGN_ATTEMPTS)}",
        },
        "attack_results": attack_rows,
        "benign_results": benign_rows,
        "evidence_hygiene": {
            "real_model_parsing": False,
            "real_model_execution": False,
            "real_sandbox_processes": False,
            "network_operations": 0,
            "subprocess_operations": 0,
            "host_filesystem_writes": 0,
            "fixture_payloads_inert": True,
        },
        "claim_boundary": {
            "runtime_plan_admission": True,
            "role_specific_parser_allowlist": True,
            "backend_allowlist": True,
            "remote_code_denial": True,
            "dynamic_extension_denial": True,
            "host_capability_denial": True,
            "resource_limit_admission": True,
            "real_parser_memory_safety": False,
            "kernel_sandbox_enforcement": False,
            "real_inference_isolation": False,
            "custom_operator_scanning": False,
            "production_container_policy": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()
    report = build_report()
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    metrics = report["metrics"]
    return 0 if (
        metrics["vulnerable_asr"] == "15/15"
        and metrics["hardened_asr"] == "0/15"
        and metrics["hardened_fpr"] == "0/3"
        and metrics["safe_task_rate"] == "3/3"
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
