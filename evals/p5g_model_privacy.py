from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass, replace
from typing import Any

from aegis.model_supply_chain.model_scanning import VerifiedModelScan
from aegis.model_supply_chain.privacy_controls import (
    ModelPrivacyGateway,
    PrivacyControlPolicy,
    PrivacyControlRejected,
    PrivacyInferenceRequest,
    PrivacyResponseEvidence,
)
from aegis.model_supply_chain.runtime_isolation import VerifiedRuntimePlan
from aegis.vulnerable.model_privacy import VulnerableUnlimitedModelOracle


_PACKAGE_ID = "helpdesk-privacy-package"
_MODEL_ID = "helpdesk-model"
_REVISION = "r6"
_RUNTIME_ID = "helpdesk-inference"
_SCAN_DIGEST = hashlib.sha256(b"p5g-approved-p5f-scan").hexdigest()
_PRINCIPAL = "customer-support-app"
_SESSION = "privacy-session"


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    scenario: str


ADVERSARIAL_ATTEMPTS = (
    Attempt("P5G-A1", "raw_logits_request"),
    Attempt("P5G-A2", "token_probabilities_returned"),
    Attempt("P5G-A3", "embeddings_request"),
    Attempt("P5G-A4", "hidden_states_returned"),
    Attempt("P5G-A5", "excessive_top_k"),
    Attempt("P5G-A6", "high_precision_confidence"),
    Attempt("P5G-A7", "disallowed_output_mode"),
    Attempt("P5G-A8", "training_canary_leak"),
    Attempt("P5G-A9", "memorization_overlap"),
    Attempt("P5G-A10", "membership_inference_signal"),
    Attempt("P5G-A11", "model_extraction_signal"),
    Attempt("P5G-A12", "session_query_budget_exhaustion"),
    Attempt("P5G-A13", "repeated_query_fingerprint_budget"),
    Attempt("P5G-A14", "scan_digest_substitution"),
    Attempt("P5G-A15", "degraded_scan_handle"),
    Attempt("P5G-A16", "degraded_runtime_handle"),
)

BENIGN_ATTEMPTS = (
    Attempt("P5G-B1", "answer_only_minimized"),
    Attempt("P5G-B2", "single_top_label"),
    Attempt("P5G-B3", "coarse_confidence"),
)


def verified_runtime() -> VerifiedRuntimePlan:
    return VerifiedRuntimePlan(
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        runtime_id=_RUNTIME_ID,
        backend="sandboxed_tensor_runtime",
        component_artifact_ids=("model", "config", "tokenizer"),
        component_parsers=("safetensors_reader", "json_reader", "json_reader"),
        isolation_mode="deny-by-default-worker-v1",
        memory_limit_mb=1024,
        cpu_time_limit_seconds=15,
        thread_limit=2,
    )


def verified_scan() -> VerifiedModelScan:
    return VerifiedModelScan(
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        runtime_id=_RUNTIME_ID,
        profile_id="release-scan-profile-v1",
        baseline_id="helpdesk-clean-baseline-v1",
        scanner_id="aegis-synthetic-scanner",
        artifact_ids=("config", "model", "tokenizer"),
        probe_ids=("rare-token-probe", "targeted-label-probe"),
        evidence_sha256=_SCAN_DIGEST,
    )


def privacy_policy() -> PrivacyControlPolicy:
    return PrivacyControlPolicy(expected_scan_evidence_sha256=_SCAN_DIGEST)


def safe_request(*, query_id: str = "q-safe-1", fingerprint: str = "fp-safe-0001") -> PrivacyInferenceRequest:
    return PrivacyInferenceRequest(
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        runtime_id=_RUNTIME_ID,
        scan_evidence_sha256=_SCAN_DIGEST,
        principal_id=_PRINCIPAL,
        session_id=_SESSION,
        query_id=query_id,
        query_fingerprint=fingerprint,
    )


def safe_evidence() -> PrivacyResponseEvidence:
    return PrivacyResponseEvidence(
        output_text="Reset the ticket password through the approved support flow.",
        output_tokens=11,
        memorization_overlap_ppm=20_000,
        membership_advantage_milli=30,
        extraction_similarity_milli=40,
    )


def _prefill_requests(count: int, *, repeated_fingerprint: str | None = None) -> tuple[PrivacyInferenceRequest, ...]:
    rows = []
    for index in range(count):
        rows.append(
            safe_request(
                query_id=f"q-prefill-{index}",
                fingerprint=repeated_fingerprint or f"fp-prefill-{index:04d}",
            )
        )
    return tuple(rows)


def attack_cases() -> tuple[dict[str, Any], ...]:
    base_request = safe_request()
    base_evidence = safe_evidence()
    runtime = verified_runtime()
    scan = verified_scan()
    other_digest = hashlib.sha256(b"substituted-p5f-scan").hexdigest()
    return (
        {"attempt": ADVERSARIAL_ATTEMPTS[0], "request": replace(base_request, expose_logits=True), "runtime": runtime, "scan": scan, "evidence": base_evidence, "prefill": ()},
        {"attempt": ADVERSARIAL_ATTEMPTS[1], "request": base_request, "runtime": runtime, "scan": scan, "evidence": replace(base_evidence, returned_token_probabilities=True), "prefill": ()},
        {"attempt": ADVERSARIAL_ATTEMPTS[2], "request": replace(base_request, expose_embeddings=True), "runtime": runtime, "scan": scan, "evidence": base_evidence, "prefill": ()},
        {"attempt": ADVERSARIAL_ATTEMPTS[3], "request": base_request, "runtime": runtime, "scan": scan, "evidence": replace(base_evidence, returned_hidden_states=True), "prefill": ()},
        {"attempt": ADVERSARIAL_ATTEMPTS[4], "request": replace(base_request, output_mode="top_label", requested_top_k=5), "runtime": runtime, "scan": scan, "evidence": replace(base_evidence, returned_top_k=5), "prefill": ()},
        {"attempt": ADVERSARIAL_ATTEMPTS[5], "request": replace(base_request, output_mode="coarse_confidence", requested_top_k=1, requested_confidence_decimals=4), "runtime": runtime, "scan": scan, "evidence": replace(base_evidence, returned_top_k=1, returned_confidence_decimals=4), "prefill": ()},
        {"attempt": ADVERSARIAL_ATTEMPTS[6], "request": replace(base_request, output_mode="full_distribution"), "runtime": runtime, "scan": scan, "evidence": base_evidence, "prefill": ()},
        {"attempt": ADVERSARIAL_ATTEMPTS[7], "request": base_request, "runtime": runtime, "scan": scan, "evidence": replace(base_evidence, output_text="Internal marker: AEGIS-CANARY-7F3A"), "prefill": ()},
        {"attempt": ADVERSARIAL_ATTEMPTS[8], "request": base_request, "runtime": runtime, "scan": scan, "evidence": replace(base_evidence, memorization_overlap_ppm=450_000), "prefill": ()},
        {"attempt": ADVERSARIAL_ATTEMPTS[9], "request": base_request, "runtime": runtime, "scan": scan, "evidence": replace(base_evidence, membership_advantage_milli=600), "prefill": ()},
        {"attempt": ADVERSARIAL_ATTEMPTS[10], "request": base_request, "runtime": runtime, "scan": scan, "evidence": replace(base_evidence, extraction_similarity_milli=800), "prefill": ()},
        {"attempt": ADVERSARIAL_ATTEMPTS[11], "request": safe_request(query_id="q-budget-over", fingerprint="fp-budget-over"), "runtime": runtime, "scan": scan, "evidence": base_evidence, "prefill": _prefill_requests(4)},
        {"attempt": ADVERSARIAL_ATTEMPTS[12], "request": safe_request(query_id="q-repeat-over", fingerprint="fp-repeat-0001"), "runtime": runtime, "scan": scan, "evidence": base_evidence, "prefill": _prefill_requests(2, repeated_fingerprint="fp-repeat-0001")},
        {"attempt": ADVERSARIAL_ATTEMPTS[13], "request": replace(base_request, scan_evidence_sha256=other_digest), "runtime": runtime, "scan": scan, "evidence": base_evidence, "prefill": ()},
        {"attempt": ADVERSARIAL_ATTEMPTS[14], "request": base_request, "runtime": runtime, "scan": replace(scan, static_indicators_clear=False, indicator_count=1), "evidence": base_evidence, "prefill": ()},
        {"attempt": ADVERSARIAL_ATTEMPTS[15], "request": base_request, "runtime": replace(runtime, network_access=True), "scan": scan, "evidence": base_evidence, "prefill": ()},
    )


def benign_cases() -> tuple[dict[str, Any], ...]:
    runtime = verified_runtime()
    scan = verified_scan()
    base_evidence = safe_evidence()
    return (
        {
            "attempt": BENIGN_ATTEMPTS[0],
            "request": safe_request(query_id="q-benign-1", fingerprint="fp-benign-0001"),
            "runtime": runtime,
            "scan": scan,
            "evidence": base_evidence,
        },
        {
            "attempt": BENIGN_ATTEMPTS[1],
            "request": replace(
                safe_request(query_id="q-benign-2", fingerprint="fp-benign-0002"),
                output_mode="top_label",
                requested_top_k=1,
            ),
            "runtime": runtime,
            "scan": scan,
            "evidence": replace(base_evidence, output_text="approved", returned_top_k=1),
        },
        {
            "attempt": BENIGN_ATTEMPTS[2],
            "request": replace(
                safe_request(query_id="q-benign-3", fingerprint="fp-benign-0003"),
                output_mode="coarse_confidence",
                requested_top_k=1,
                requested_confidence_decimals=1,
            ),
            "runtime": runtime,
            "scan": scan,
            "evidence": replace(
                base_evidence,
                output_text="approved (0.9)",
                returned_top_k=1,
                returned_confidence_decimals=1,
            ),
        },
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
    policy = privacy_policy()
    payload = json.dumps(
        {
            "runtime": asdict(verified_runtime()),
            "scan": asdict(verified_scan()),
            "request": asdict(safe_request()),
            "evidence": asdict(safe_evidence()),
            "policy": {
                "expected_scan_evidence_sha256": policy.expected_scan_evidence_sha256,
                "allowed_output_modes": sorted(policy.allowed_output_modes),
                "max_top_k": policy.max_top_k,
                "max_confidence_decimals": policy.max_confidence_decimals,
                "max_output_tokens": policy.max_output_tokens,
                "max_queries_per_session": policy.max_queries_per_session,
                "max_repeated_fingerprint_queries": policy.max_repeated_fingerprint_queries,
                "forbidden_canary_fragments": list(policy.forbidden_canary_fragments),
                "max_memorization_overlap_ppm": policy.max_memorization_overlap_ppm,
                "max_membership_advantage_milli": policy.max_membership_advantage_milli,
                "max_extraction_similarity_milli": policy.max_extraction_similarity_milli,
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


P5G_DATASET_SHA256 = dataset_hash()
P5G_FIXTURE_SHA256 = fixture_hash()


def build_report() -> dict[str, Any]:
    vulnerable = VulnerableUnlimitedModelOracle()
    policy = privacy_policy()

    attack_rows: list[dict[str, Any]] = []
    vulnerable_successes = 0
    hardened_successes = 0
    for case in attack_cases():
        vulnerable.release(
            request=case["request"],
            runtime=case["runtime"],
            scan=case["scan"],
            evidence=case["evidence"],
        )
        vulnerable_successes += 1

        hardened = ModelPrivacyGateway(policy)
        for prefill_request in case["prefill"]:
            hardened.release(
                request=prefill_request,
                runtime=verified_runtime(),
                scan=verified_scan(),
                evidence=safe_evidence(),
            )

        reason = None
        try:
            hardened.release(
                request=case["request"],
                runtime=case["runtime"],
                scan=case["scan"],
                evidence=case["evidence"],
            )
            hardened_successes += 1
        except PrivacyControlRejected as exc:
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
    false_positives = 0
    safe_tasks = 0
    for case in benign_cases():
        hardened = ModelPrivacyGateway(policy)
        try:
            handle = hardened.release(
                request=case["request"],
                runtime=case["runtime"],
                scan=case["scan"],
                evidence=case["evidence"],
            )
        except PrivacyControlRejected as exc:
            false_positives += 1
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
                    "output_minimized": handle.output_minimized,
                    "sensitive_channels_denied": handle.sensitive_channels_denied,
                    "real_model_inference": handle.real_model_inference,
                }
            )

    return {
        "milestone": "P5-G",
        "policy_version": "model-privacy-extraction-membership-controls-v1",
        "dataset_sha256": P5G_DATASET_SHA256,
        "fixture_sha256": P5G_FIXTURE_SHA256,
        "metrics": {
            "adversarial_cases": len(ADVERSARIAL_ATTEMPTS),
            "vulnerable_asr": f"{vulnerable_successes}/{len(ADVERSARIAL_ATTEMPTS)}",
            "hardened_asr": f"{hardened_successes}/{len(ADVERSARIAL_ATTEMPTS)}",
            "hardened_fpr": f"{false_positives}/{len(BENIGN_ATTEMPTS)}",
            "safe_task_rate": f"{safe_tasks}/{len(BENIGN_ATTEMPTS)}",
        },
        "attack_results": attack_rows,
        "benign_results": benign_rows,
        "evidence_hygiene": {
            "real_model_inference": False,
            "real_membership_attack": False,
            "real_model_extraction": False,
            "real_training_corpus": False,
            "network_operations": 0,
            "synthetic_response_evidence": True,
        },
        "claim_boundary": {
            "session_query_budget": True,
            "repeated_query_budget": True,
            "output_detail_minimization": True,
            "logit_probability_embedding_hidden_state_denial": True,
            "canary_leakage_gate": True,
            "synthetic_memorization_indicator_gate": True,
            "synthetic_membership_indicator_gate": True,
            "synthetic_extraction_indicator_gate": True,
            "differential_privacy_guarantee": False,
            "real_membership_inference_resistance": False,
            "real_model_extraction_resistance": False,
            "production_rate_limit_enforcement": False,
            "side_channel_protection": False,
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
