from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.model_supply_chain import (
    ModelArtifactManifest,
    ModelArtifactRejected,
    ModelArtifactRequest,
    ModelArtifactTrustPolicy,
    RestrictedModelArtifactLoader,
    canonical_manifest_bytes,
    sha256_hex,
)
from aegis.vulnerable.model_artifact_loading import VulnerableModelArtifactLoader


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_TRUSTED_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))
_UNTRUSTED_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("22" * 32))
_TRUSTED_PUBLIC_KEY = _TRUSTED_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
_TRUSTED_PUBLISHER = "aegis-lab-publisher"
_UNTRUSTED_PUBLISHER = "attacker-lab-publisher"
_TRUSTED_SOURCE = "registry://aegis-lab/models/"
_UNTRUSTED_SOURCE = "registry://untrusted-lab/models/"

_SAFE_SAFETENSORS = b"AEGIS-INERT-SAFETENSORS-V1\nweights=data-only-fixture\n"
_TAMPERED_SAFETENSORS = _SAFE_SAFETENSORS + b"tamper\n"
_SAFE_ONNX = b"AEGIS-INERT-ONNX-V1\ngraph=data-only-fixture\n"
_UNSAFE_PICKLE_LIKE = b"\x80\x04AEGIS-INERT-PICKLE-LIKE-FIXTURE-NOT-EXECUTED"
_OTHER_MODEL = b"AEGIS-INERT-SAFETENSORS-V1\nweights=other-model\n"


@dataclass(frozen=True)
class AdversarialAttempt:
    attempt_id: str
    scenario: Literal[
        "payload_tamper_after_manifest_signing",
        "untrusted_publisher_substitution",
        "signed_unsafe_serialization",
        "trusted_cross_model_substitution",
    ]


@dataclass(frozen=True)
class BenignAttempt:
    attempt_id: str
    scenario: Literal["trusted_safetensors_artifact", "trusted_onnx_artifact"]


ADVERSARIAL_ATTEMPTS = (
    AdversarialAttempt("P5A-A1", "payload_tamper_after_manifest_signing"),
    AdversarialAttempt("P5A-A2", "untrusted_publisher_substitution"),
    AdversarialAttempt("P5A-A3", "signed_unsafe_serialization"),
    AdversarialAttempt("P5A-A4", "trusted_cross_model_substitution"),
)
BENIGN_ATTEMPTS = (
    BenignAttempt("P5A-B1", "trusted_safetensors_artifact"),
    BenignAttempt("P5A-B2", "trusted_onnx_artifact"),
)


def _dataset_hash() -> str:
    canonical = json.dumps(
        {
            "adversarial": [asdict(item) for item in ADVERSARIAL_ATTEMPTS],
            "benign": [asdict(item) for item in BENIGN_ATTEMPTS],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _fixture_hash() -> str:
    digest = hashlib.sha256()
    for payload in (
        _SAFE_SAFETENSORS,
        _TAMPERED_SAFETENSORS,
        _SAFE_ONNX,
        _UNSAFE_PICKLE_LIKE,
        _OTHER_MODEL,
        _TRUSTED_PUBLIC_KEY,
    ):
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _git_commit() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"
    return completed.stdout.strip()


def _package_version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "unavailable"


def _percent(numerator: int, denominator: int) -> float:
    return 0.0 if denominator == 0 else (numerator / denominator) * 100.0


def _manifest(
    *,
    payload: bytes,
    artifact_id: str,
    model_id: str,
    revision: str,
    publisher_id: str = _TRUSTED_PUBLISHER,
    source: str | None = None,
    artifact_format: str = "safetensors",
) -> ModelArtifactManifest:
    if source is None:
        source = f"{_TRUSTED_SOURCE}{model_id}/{revision}/{artifact_id}"
    return ModelArtifactManifest(
        artifact_id=artifact_id,
        model_id=model_id,
        revision=revision,
        publisher_id=publisher_id,
        source=source,
        artifact_format=artifact_format,
        sha256=sha256_hex(payload),
        size_bytes=len(payload),
    )


def _signature(manifest: ModelArtifactManifest, *, trusted: bool = True) -> bytes:
    key = _TRUSTED_PRIVATE_KEY if trusted else _UNTRUSTED_PRIVATE_KEY
    return key.sign(canonical_manifest_bytes(manifest))


def _policy() -> ModelArtifactTrustPolicy:
    return ModelArtifactTrustPolicy(
        trusted_publishers={_TRUSTED_PUBLISHER: _TRUSTED_PUBLIC_KEY},
        trusted_source_prefixes={_TRUSTED_PUBLISHER: (_TRUSTED_SOURCE,)},
        allowed_formats=frozenset({"safetensors", "onnx"}),
        max_artifact_bytes=4096,
    )


def _attack_cases() -> tuple[dict[str, Any], ...]:
    requested = ModelArtifactRequest("artifact-main", "helpdesk-model", "r1")
    signed_good = _manifest(
        payload=_SAFE_SAFETENSORS,
        artifact_id=requested.artifact_id,
        model_id=requested.model_id,
        revision=requested.revision,
    )

    untrusted = _manifest(
        payload=_SAFE_SAFETENSORS,
        artifact_id=requested.artifact_id,
        model_id=requested.model_id,
        revision=requested.revision,
        publisher_id=_UNTRUSTED_PUBLISHER,
        source=f"{_UNTRUSTED_SOURCE}{requested.model_id}/{requested.revision}/{requested.artifact_id}",
    )

    unsafe_request = ModelArtifactRequest("artifact-pickle", "legacy-model", "r1")
    unsafe = _manifest(
        payload=_UNSAFE_PICKLE_LIKE,
        artifact_id=unsafe_request.artifact_id,
        model_id=unsafe_request.model_id,
        revision=unsafe_request.revision,
        artifact_format="pickle",
    )

    other_manifest = _manifest(
        payload=_OTHER_MODEL,
        artifact_id="artifact-other",
        model_id="other-model",
        revision="r9",
    )

    return (
        {
            "attempt_id": "P5A-A1",
            "scenario": "payload_tamper_after_manifest_signing",
            "request": requested,
            "manifest": signed_good,
            "signature": _signature(signed_good),
            "payload": _TAMPERED_SAFETENSORS,
        },
        {
            "attempt_id": "P5A-A2",
            "scenario": "untrusted_publisher_substitution",
            "request": requested,
            "manifest": untrusted,
            "signature": _signature(untrusted, trusted=False),
            "payload": _SAFE_SAFETENSORS,
        },
        {
            "attempt_id": "P5A-A3",
            "scenario": "signed_unsafe_serialization",
            "request": unsafe_request,
            "manifest": unsafe,
            "signature": _signature(unsafe),
            "payload": _UNSAFE_PICKLE_LIKE,
        },
        {
            "attempt_id": "P5A-A4",
            "scenario": "trusted_cross_model_substitution",
            "request": requested,
            "manifest": other_manifest,
            "signature": _signature(other_manifest),
            "payload": _OTHER_MODEL,
        },
    )


def _benign_cases() -> tuple[dict[str, Any], ...]:
    safe_request = ModelArtifactRequest("artifact-safe", "helpdesk-model", "r1")
    safe_manifest = _manifest(
        payload=_SAFE_SAFETENSORS,
        artifact_id=safe_request.artifact_id,
        model_id=safe_request.model_id,
        revision=safe_request.revision,
    )
    onnx_request = ModelArtifactRequest("artifact-onnx", "routing-model", "r2")
    onnx_manifest = _manifest(
        payload=_SAFE_ONNX,
        artifact_id=onnx_request.artifact_id,
        model_id=onnx_request.model_id,
        revision=onnx_request.revision,
        artifact_format="onnx",
    )
    return (
        {
            "attempt_id": "P5A-B1",
            "scenario": "trusted_safetensors_artifact",
            "request": safe_request,
            "manifest": safe_manifest,
            "signature": _signature(safe_manifest),
            "payload": _SAFE_SAFETENSORS,
        },
        {
            "attempt_id": "P5A-B2",
            "scenario": "trusted_onnx_artifact",
            "request": onnx_request,
            "manifest": onnx_manifest,
            "signature": _signature(onnx_manifest),
            "payload": _SAFE_ONNX,
        },
    )


def _run_variant(variant: Literal["vulnerable", "hardened"]) -> dict[str, Any]:
    loader = VulnerableModelArtifactLoader() if variant == "vulnerable" else RestrictedModelArtifactLoader(_policy())
    adversarial_results: list[dict[str, Any]] = []
    benign_results: list[dict[str, Any]] = []

    for case in _attack_cases():
        accepted = False
        rejection_reason = None
        try:
            loader.load(
                request=case["request"],
                manifest=case["manifest"],
                signature=case["signature"],
                payload=case["payload"],
            )
            accepted = True
        except ModelArtifactRejected as exc:
            rejection_reason = exc.reason.value
        adversarial_results.append(
            {
                "attempt_id": case["attempt_id"],
                "scenario": case["scenario"],
                "valid": True,
                "success": accepted,
                "accepted": accepted,
                "rejection_reason": rejection_reason,
                "payload_executed": False,
            }
        )

    for case in _benign_cases():
        blocked = False
        safe_completion = False
        try:
            handle = loader.load(
                request=case["request"],
                manifest=case["manifest"],
                signature=case["signature"],
                payload=case["payload"],
            )
            if variant == "vulnerable":
                safe_completion = True
            else:
                safe_completion = (
                    handle.deserialized is False
                    and handle.code_execution_capable is False
                    and handle.network_operations == 0
                    and handle.sha256 == sha256_hex(case["payload"])
                )
        except ModelArtifactRejected:
            blocked = True
        benign_results.append(
            {
                "attempt_id": case["attempt_id"],
                "scenario": case["scenario"],
                "valid": True,
                "incorrectly_blocked": blocked,
                "safe_completion": safe_completion,
                "payload_executed": False,
            }
        )

    valid_attacks = len(adversarial_results)
    successful = sum(1 for item in adversarial_results if item["success"])
    valid_benign = len(benign_results)
    false_positives = sum(1 for item in benign_results if item["incorrectly_blocked"])
    safe = sum(1 for item in benign_results if item["safe_completion"])

    return {
        "policy_version": (
            "declaration-trusting-model-artifact-loader-v1"
            if variant == "vulnerable"
            else "model-artifact-provenance-safe-loading-v1"
        ),
        "metrics": {
            "asr": {
                "successful_policy_violations": successful,
                "valid_adversarial_attempts": valid_attacks,
                "percent": _percent(successful, valid_attacks),
            },
            "fpr": {
                "benign_requests_incorrectly_blocked": false_positives,
                "valid_benign_requests": valid_benign,
                "percent": _percent(false_positives, valid_benign),
            },
            "safe_task_rate": {
                "authorized_tasks_completed_safely": safe,
                "authorized_tasks_attempted": valid_benign,
                "percent": _percent(safe, valid_benign),
            },
        },
        "adversarial_attempts": adversarial_results,
        "benign_attempts": benign_results,
    }


def build_report() -> dict[str, Any]:
    return {
        "evaluation": "P5-A model artifact provenance and safe loading boundary",
        "definitions": {
            "valid_adversarial_attempt": "A fixed inert local model-artifact fixture is presented with a modeled supply-chain provenance or identity violation.",
            "successful_policy_violation": "The loader accepts a tampered, untrusted-publisher, unsafe-serialization, or wrong-model artifact before provenance and policy validation.",
            "false_positive": "A valid trusted signed data-only model artifact is rejected.",
            "safe_completion": "The trusted artifact is provenance-verified and returned only as a non-deserialized, non-code-executing handle.",
        },
        "attempt_budget_per_variant": {
            "adversarial": len(ADVERSARIAL_ATTEMPTS),
            "benign": len(BENIGN_ATTEMPTS),
        },
        "eval_dataset_hash_sha256": _dataset_hash(),
        "fixture_hash_sha256": _fixture_hash(),
        "code_commit": _git_commit(),
        "model": {
            "provider": "none",
            "model_id": "none",
            "reason": "P5-A evaluates inert artifact provenance and loader policy without running a model",
        },
        "evidence_hygiene": {
            "network_operations": 0,
            "real_model_downloads": False,
            "real_registry_credentials": False,
            "arbitrary_serialized_payload_executed": False,
            "fixture_payloads_inert": True,
            "production_signing_key_claim": False,
        },
        "claim_boundary": {
            "artifact_identity_binding": True,
            "sha256_payload_binding": True,
            "ed25519_manifest_signature_verification": True,
            "trusted_publisher_policy": True,
            "trusted_source_policy": True,
            "unsafe_serialization_rejected": True,
            "real_safetensors_parser_claim": False,
            "real_onnx_parser_claim": False,
            "sandboxed_model_execution_claim": False,
            "production_model_registry_claim": False,
            "production_key_custody_claim": False,
        },
        "versions": {
            "aegisdesk": _package_version("aegisdesk"),
            "cryptography": _package_version("cryptography"),
        },
        "variants": {
            "vulnerable": _run_variant("vulnerable"),
            "hardened": _run_variant("hardened"),
        },
    }


def _assert_expected_security_delta(report: dict[str, Any]) -> None:
    vulnerable = report["variants"]["vulnerable"]["metrics"]
    hardened = report["variants"]["hardened"]["metrics"]
    expected = (
        vulnerable["asr"]["successful_policy_violations"] == 4
        and vulnerable["asr"]["valid_adversarial_attempts"] == 4
        and hardened["asr"]["successful_policy_violations"] == 0
        and hardened["asr"]["valid_adversarial_attempts"] == 4
        and hardened["fpr"]["benign_requests_incorrectly_blocked"] == 0
        and hardened["fpr"]["valid_benign_requests"] == 2
        and hardened["safe_task_rate"]["authorized_tasks_completed_safely"] == 2
        and hardened["safe_task_rate"]["authorized_tasks_attempted"] == 2
        and report["evidence_hygiene"]["network_operations"] == 0
        and report["evidence_hygiene"]["arbitrary_serialized_payload_executed"] is False
    )
    if not expected:
        raise SystemExit("P5-A security delta did not match the expected invariant")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    report = build_report()
    _assert_expected_security_delta(report)
    rendered = json.dumps(report, indent=2, sort_keys=True)
    print(rendered)
    if args.output is not None:
        args.output.write_text(rendered + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
