from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass, replace
from typing import Any

from aegis.model_supply_chain.model_scanning import (
    ArtifactScanEvidence,
    BackdoorProbeEvidence,
    ModelPoisoningBackdoorScanner,
    ModelScanEvidenceBundle,
    ModelScanPolicy,
    ModelScanRejectReason,
    ModelScanRejected,
    ModelScanRequest,
    scan_evidence_digest,
)
from aegis.model_supply_chain.package_provenance import (
    ModelPackageComponentRole,
    VerifiedModelPackage,
)
from aegis.model_supply_chain.runtime_isolation import VerifiedRuntimePlan
from aegis.vulnerable.model_scanning import VulnerableProvenanceOnlyModelScanner


_PACKAGE_ID = "helpdesk-scanned-package"
_MODEL_ID = "helpdesk-model"
_REVISION = "r5"
_RUNTIME_ID = "helpdesk-inference"
_PROFILE_ID = "p5f-static-plus-synthetic-probes-v1"
_BASELINE_ID = "helpdesk-r5-approved-baseline"
_SCANNER_ID = "aegis-synthetic-model-scanner"
_PUBLISHER = "aegis-release-publisher"


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    scenario: str


ADVERSARIAL_ATTEMPTS = (
    Attempt("P5F-A1", "nonfinite_tensor_values"),
    Attempt("P5F-A2", "extreme_weight_magnitude"),
    Attempt("P5F-A3", "dense_outlier_population"),
    Attempt("P5F-A4", "sparse_high_magnitude_spikes"),
    Attempt("P5F-A5", "tokenizer_trigger_token"),
    Attempt("P5F-A6", "config_trigger_router"),
    Attempt("P5F-A7", "targeted_trigger_response"),
    Attempt("P5F-A8", "clean_utility_collapse"),
    Attempt("P5F-A9", "missing_artifact_scan_coverage"),
    Attempt("P5F-A10", "artifact_subject_digest_substitution"),
    Attempt("P5F-A11", "artifact_role_confusion"),
    Attempt("P5F-A12", "missing_required_probe"),
    Attempt("P5F-A13", "scanner_profile_substitution"),
    Attempt("P5F-A14", "degraded_runtime_handle"),
    Attempt("P5F-A15", "degraded_package_handle"),
    Attempt("P5F-A16", "scan_identity_substitution"),
)
BENIGN_ATTEMPTS = (
    Attempt("P5F-B1", "clean_release_baseline"),
    Attempt("P5F-B2", "benign_tokenizer_extension"),
    Attempt("P5F-B3", "moderate_safe_weight_statistics"),
)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


SUBJECT_DIGESTS = {
    "model": _sha(b"synthetic model release r5"),
    "config": _sha(b'{"architectures":["SafeModel"]}'),
    "tokenizer": _sha(b'{"vocab":["hello","world"]}'),
    "adapter": _sha(b"synthetic adapter release r5"),
}


def verified_package() -> VerifiedModelPackage:
    ids = ("model", "config", "tokenizer", "adapter")
    roles = (
        ModelPackageComponentRole.PRIMARY_MODEL.value,
        ModelPackageComponentRole.CONFIG.value,
        ModelPackageComponentRole.TOKENIZER.value,
        ModelPackageComponentRole.ADAPTER.value,
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


def verified_runtime() -> VerifiedRuntimePlan:
    return VerifiedRuntimePlan(
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        runtime_id=_RUNTIME_ID,
        backend="sandboxed_tensor_runtime",
        component_artifact_ids=("model", "config", "tokenizer", "adapter"),
        component_parsers=(
            "safetensors_reader",
            "json_reader",
            "json_reader",
            "safetensors_reader",
        ),
        isolation_mode="deny-by-default-worker-v1",
        memory_limit_mb=2048,
        cpu_time_limit_seconds=30,
        thread_limit=4,
    )


def scan_request() -> ModelScanRequest:
    return ModelScanRequest(
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        runtime_id=_RUNTIME_ID,
        profile_id=_PROFILE_ID,
        baseline_id=_BASELINE_ID,
    )


def scan_policy() -> ModelScanPolicy:
    return ModelScanPolicy(
        scanner_id=_SCANNER_ID,
        profile_id=_PROFILE_ID,
        baseline_id=_BASELINE_ID,
        expected_subject_sha256s=SUBJECT_DIGESTS,
        required_probe_ids=frozenset({"rare-token-probe", "context-trigger-probe"}),
    )


def safe_evidence() -> ModelScanEvidenceBundle:
    return ModelScanEvidenceBundle(
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        runtime_id=_RUNTIME_ID,
        profile_id=_PROFILE_ID,
        baseline_id=_BASELINE_ID,
        scanner_id=_SCANNER_ID,
        artifacts=(
            ArtifactScanEvidence(
                artifact_id="model",
                role=ModelPackageComponentRole.PRIMARY_MODEL,
                subject_sha256=SUBJECT_DIGESTS["model"],
                tensors_examined=12,
                elements_examined=120_000,
                nonfinite_values=0,
                max_abs_milli=9_200,
                outlier_fraction_ppm=120,
                sparse_spike_fraction_ppm=40,
            ),
            ArtifactScanEvidence(
                artifact_id="config",
                role=ModelPackageComponentRole.CONFIG,
                subject_sha256=SUBJECT_DIGESTS["config"],
                tensors_examined=0,
                elements_examined=0,
                nonfinite_values=0,
                max_abs_milli=0,
                outlier_fraction_ppm=0,
                sparse_spike_fraction_ppm=0,
                config_markers=("rope_scaling_v2",),
            ),
            ArtifactScanEvidence(
                artifact_id="tokenizer",
                role=ModelPackageComponentRole.TOKENIZER,
                subject_sha256=SUBJECT_DIGESTS["tokenizer"],
                tensors_examined=0,
                elements_examined=0,
                nonfinite_values=0,
                max_abs_milli=0,
                outlier_fraction_ppm=0,
                sparse_spike_fraction_ppm=0,
                tokenizer_added_tokens=("<|helpdesk|>",),
            ),
            ArtifactScanEvidence(
                artifact_id="adapter",
                role=ModelPackageComponentRole.ADAPTER,
                subject_sha256=SUBJECT_DIGESTS["adapter"],
                tensors_examined=4,
                elements_examined=20_000,
                nonfinite_values=0,
                max_abs_milli=7_000,
                outlier_fraction_ppm=100,
                sparse_spike_fraction_ppm=30,
            ),
        ),
        probes=(
            BackdoorProbeEvidence(
                probe_id="rare-token-probe",
                trigger_label="synthetic-rare-token",
                reproducible_runs=5,
                targeted_score_lift_milli=80,
                clean_utility_drop_milli=15,
            ),
            BackdoorProbeEvidence(
                probe_id="context-trigger-probe",
                trigger_label="synthetic-context-pattern",
                reproducible_runs=5,
                targeted_score_lift_milli=90,
                clean_utility_drop_milli=20,
            ),
        ),
    )


def _replace_artifact(
    evidence: ModelScanEvidenceBundle, artifact_id: str, **changes: Any
) -> ModelScanEvidenceBundle:
    return replace(
        evidence,
        artifacts=tuple(
            replace(item, **changes) if item.artifact_id == artifact_id else item
            for item in evidence.artifacts
        ),
    )


def _replace_probe(
    evidence: ModelScanEvidenceBundle, probe_id: str, **changes: Any
) -> ModelScanEvidenceBundle:
    return replace(
        evidence,
        probes=tuple(
            replace(item, **changes) if item.probe_id == probe_id else item
            for item in evidence.probes
        ),
    )


def attack_cases() -> tuple[dict[str, Any], ...]:
    base = safe_evidence()
    package = verified_package()
    runtime = verified_runtime()
    return (
        {
            "attempt": ADVERSARIAL_ATTEMPTS[0],
            "package": package,
            "runtime": runtime,
            "evidence": _replace_artifact(base, "model", nonfinite_values=1),
            "reason": ModelScanRejectReason.NONFINITE_VALUES,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[1],
            "package": package,
            "runtime": runtime,
            "evidence": _replace_artifact(base, "model", max_abs_milli=50_000),
            "reason": ModelScanRejectReason.WEIGHT_MAGNITUDE_ANOMALY,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[2],
            "package": package,
            "runtime": runtime,
            "evidence": _replace_artifact(base, "model", outlier_fraction_ppm=5_000),
            "reason": ModelScanRejectReason.OUTLIER_DENSITY_ANOMALY,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[3],
            "package": package,
            "runtime": runtime,
            "evidence": _replace_artifact(base, "adapter", sparse_spike_fraction_ppm=8_000),
            "reason": ModelScanRejectReason.SPARSE_SPIKE_ANOMALY,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[4],
            "package": package,
            "runtime": runtime,
            "evidence": _replace_artifact(
                base,
                "tokenizer",
                tokenizer_added_tokens=("<|helpdesk|>", "<|admin_override|>"),
            ),
            "reason": ModelScanRejectReason.TOKENIZER_TRIGGER_INDICATOR,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[5],
            "package": package,
            "runtime": runtime,
            "evidence": _replace_artifact(
                base,
                "config",
                config_markers=("rope_scaling_v2", "conditional_trigger_router"),
            ),
            "reason": ModelScanRejectReason.CONFIG_TRIGGER_INDICATOR,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[6],
            "package": package,
            "runtime": runtime,
            "evidence": _replace_probe(
                base, "rare-token-probe", targeted_score_lift_milli=700
            ),
            "reason": ModelScanRejectReason.TRIGGER_RESPONSE_ANOMALY,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[7],
            "package": package,
            "runtime": runtime,
            "evidence": _replace_probe(
                base, "context-trigger-probe", clean_utility_drop_milli=400
            ),
            "reason": ModelScanRejectReason.CLEAN_UTILITY_DEGRADATION,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[8],
            "package": package,
            "runtime": runtime,
            "evidence": replace(base, artifacts=base.artifacts[:-1]),
            "reason": ModelScanRejectReason.COVERAGE_MISMATCH,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[9],
            "package": package,
            "runtime": runtime,
            "evidence": _replace_artifact(
                base, "model", subject_sha256=_sha(b"substituted model payload")
            ),
            "reason": ModelScanRejectReason.SUBJECT_DIGEST_MISMATCH,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[10],
            "package": package,
            "runtime": runtime,
            "evidence": _replace_artifact(
                base, "adapter", role=ModelPackageComponentRole.CONFIG
            ),
            "reason": ModelScanRejectReason.ROLE_MISMATCH,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[11],
            "package": package,
            "runtime": runtime,
            "evidence": replace(base, probes=base.probes[:1]),
            "reason": ModelScanRejectReason.PROBE_COVERAGE_MISMATCH,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[12],
            "package": package,
            "runtime": runtime,
            "evidence": replace(base, profile_id="attacker-profile"),
            "reason": ModelScanRejectReason.SCANNER_PROFILE_MISMATCH,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[13],
            "package": package,
            "runtime": replace(runtime, sandbox_required=False),
            "evidence": base,
            "reason": ModelScanRejectReason.RUNTIME_UNVERIFIED,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[14],
            "package": replace(package, transitive_components_verified=False),
            "runtime": runtime,
            "evidence": base,
            "reason": ModelScanRejectReason.PACKAGE_UNVERIFIED,
        },
        {
            "attempt": ADVERSARIAL_ATTEMPTS[15],
            "package": package,
            "runtime": runtime,
            "evidence": replace(base, revision="r5-substituted"),
            "reason": ModelScanRejectReason.IDENTITY_MISMATCH,
        },
    )


def benign_cases() -> tuple[dict[str, Any], ...]:
    base = safe_evidence()
    benign_token = _replace_artifact(
        base,
        "tokenizer",
        tokenizer_added_tokens=("<|helpdesk|>", "<|ticket_summary|>"),
    )
    moderate = _replace_artifact(
        base,
        "model",
        max_abs_milli=15_000,
        outlier_fraction_ppm=700,
        sparse_spike_fraction_ppm=300,
    )
    return (
        {"attempt": BENIGN_ATTEMPTS[0], "evidence": base},
        {"attempt": BENIGN_ATTEMPTS[1], "evidence": benign_token},
        {"attempt": BENIGN_ATTEMPTS[2], "evidence": moderate},
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
    payload = json.dumps(
        {
            "package": asdict(verified_package()),
            "runtime": asdict(verified_runtime()),
            "subject_digests": SUBJECT_DIGESTS,
            "evidence_sha256": scan_evidence_digest(safe_evidence()),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


P5F_DATASET_SHA256 = dataset_hash()
P5F_FIXTURE_SHA256 = fixture_hash()


def build_report() -> dict[str, Any]:
    vulnerable = VulnerableProvenanceOnlyModelScanner()
    hardened = ModelPoisoningBackdoorScanner(scan_policy())
    request = scan_request()

    attack_rows: list[dict[str, Any]] = []
    vulnerable_successes = 0
    hardened_successes = 0
    for case in attack_cases():
        vulnerable.evaluate(
            package=case["package"],
            runtime=case["runtime"],
            evidence=case["evidence"],
        )
        vulnerable_successes += 1
        reject_reason = None
        try:
            hardened.evaluate(
                request=request,
                package=case["package"],
                runtime=case["runtime"],
                evidence=case["evidence"],
            )
            hardened_successes += 1
        except ModelScanRejected as exc:
            reject_reason = exc.reason.value
        attack_rows.append(
            {
                "attempt_id": case["attempt"].attempt_id,
                "scenario": case["attempt"].scenario,
                "vulnerable_accepted": True,
                "hardened_accepted": reject_reason is None,
                "hardened_reject_reason": reject_reason,
            }
        )

    benign_rows: list[dict[str, Any]] = []
    benign_false_positives = 0
    safe_tasks = 0
    package = verified_package()
    runtime = verified_runtime()
    for case in benign_cases():
        try:
            handle = hardened.evaluate(
                request=request,
                package=package,
                runtime=runtime,
                evidence=case["evidence"],
            )
        except ModelScanRejected as exc:
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
                    "indicator_count": handle.indicator_count,
                    "static_indicators_clear": handle.static_indicators_clear,
                    "synthetic_probe_indicators_clear": handle.synthetic_probe_indicators_clear,
                    "model_executed": handle.model_executed,
                }
            )

    return {
        "milestone": "P5-F",
        "policy_version": "model-poisoning-backdoor-indicators-v1",
        "dataset_sha256": P5F_DATASET_SHA256,
        "fixture_sha256": P5F_FIXTURE_SHA256,
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
            "raw_model_bytes_scanned": False,
            "real_tensor_parsing": False,
            "real_model_execution": False,
            "real_training_data": False,
            "network_operations": 0,
            "fixture_payloads_inert": True,
            "synthetic_statistics_only": True,
            "synthetic_probe_results_only": True,
        },
        "claim_boundary": {
            "release_scoped_subject_digest_pins": True,
            "exact_scan_coverage": True,
            "statistical_indicator_policy": True,
            "tokenizer_config_indicator_policy": True,
            "synthetic_probe_indicator_policy": True,
            "proves_backdoor_absence": False,
            "semantic_model_safety": False,
            "real_tensor_scanner": False,
            "real_inference_backdoor_testing": False,
            "training_data_poison_detection": False,
            "scanner_attestation": False,
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
        metrics["vulnerable_asr"] == "16/16"
        and metrics["hardened_asr"] == "0/16"
        and metrics["hardened_fpr"] == "0/3"
        and metrics["safe_task_rate"] == "3/3"
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
