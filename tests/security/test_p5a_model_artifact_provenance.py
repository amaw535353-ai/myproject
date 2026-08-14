from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.model_supply_chain import (
    ModelArtifactManifest,
    ModelArtifactRejected,
    ModelArtifactRejectReason,
    ModelArtifactRequest,
    ModelArtifactTrustPolicy,
    RestrictedModelArtifactLoader,
    canonical_manifest_bytes,
    sha256_hex,
)
from evals.p5a_model_artifact_provenance import build_report


_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("33" * 32))
_PUBLIC = _PRIVATE.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def _loader() -> RestrictedModelArtifactLoader:
    return RestrictedModelArtifactLoader(
        ModelArtifactTrustPolicy(
            trusted_publishers={"trusted": _PUBLIC},
            trusted_source_prefixes={"trusted": ("registry://trusted/",)},
            allowed_formats=frozenset({"safetensors", "onnx"}),
            max_artifact_bytes=1024,
        )
    )


def _signed_manifest(
    payload: bytes,
    *,
    artifact_id: str = "artifact-a",
    model_id: str = "model-a",
    revision: str = "r1",
    artifact_format: str = "safetensors",
) -> tuple[ModelArtifactManifest, bytes]:
    manifest = ModelArtifactManifest(
        artifact_id=artifact_id,
        model_id=model_id,
        revision=revision,
        publisher_id="trusted",
        source=f"registry://trusted/{model_id}/{revision}/{artifact_id}",
        artifact_format=artifact_format,
        sha256=sha256_hex(payload),
        size_bytes=len(payload),
    )
    return manifest, _PRIVATE.sign(canonical_manifest_bytes(manifest))


def test_p5a_tampered_payload_is_rejected_before_handoff() -> None:
    payload = b"inert-model-bytes"
    manifest, signature = _signed_manifest(payload)
    with pytest.raises(ModelArtifactRejected) as exc_info:
        _loader().load(
            request=ModelArtifactRequest("artifact-a", "model-a", "r1"),
            manifest=manifest,
            signature=signature,
            payload=payload + b"tamper",
        )
    assert exc_info.value.reason in {
        ModelArtifactRejectReason.SIZE_MISMATCH,
        ModelArtifactRejectReason.DIGEST_MISMATCH,
    }


def test_p5a_valid_signature_does_not_authorize_pickle_format() -> None:
    payload = b"inert-pickle-like-bytes-never-executed"
    manifest, signature = _signed_manifest(payload, artifact_format="pickle")
    with pytest.raises(ModelArtifactRejected) as exc_info:
        _loader().load(
            request=ModelArtifactRequest("artifact-a", "model-a", "r1"),
            manifest=manifest,
            signature=signature,
            payload=payload,
        )
    assert exc_info.value.reason == ModelArtifactRejectReason.FORMAT_UNSAFE


def test_p5a_cross_model_substitution_is_rejected() -> None:
    payload = b"other-inert-model"
    manifest, signature = _signed_manifest(
        payload,
        artifact_id="artifact-b",
        model_id="model-b",
        revision="r9",
    )
    with pytest.raises(ModelArtifactRejected) as exc_info:
        _loader().load(
            request=ModelArtifactRequest("artifact-a", "model-a", "r1"),
            manifest=manifest,
            signature=signature,
            payload=payload,
        )
    assert exc_info.value.reason == ModelArtifactRejectReason.IDENTITY_MISMATCH


def test_p5a_verified_handle_is_non_deserializing_and_network_free() -> None:
    payload = b"trusted-inert-model"
    manifest, signature = _signed_manifest(payload)
    handle = _loader().load(
        request=ModelArtifactRequest("artifact-a", "model-a", "r1"),
        manifest=manifest,
        signature=signature,
        payload=payload,
    )
    assert handle.deserialized is False
    assert handle.code_execution_capable is False
    assert handle.network_operations == 0
    assert handle.sha256 == sha256_hex(payload)


def test_p5a_evaluation_metrics_and_dataset_hash_are_pinned() -> None:
    report = build_report()
    assert report["eval_dataset_hash_sha256"] == "2845ac0e110c703d2c42fa1d668ddcd709b8a468562bebb1bd04a99e0898cf39"
    vulnerable = report["variants"]["vulnerable"]["metrics"]
    hardened = report["variants"]["hardened"]["metrics"]
    assert vulnerable["asr"]["successful_policy_violations"] == 4
    assert vulnerable["asr"]["valid_adversarial_attempts"] == 4
    assert hardened["asr"]["successful_policy_violations"] == 0
    assert hardened["asr"]["valid_adversarial_attempts"] == 4
    assert hardened["fpr"]["benign_requests_incorrectly_blocked"] == 0
    assert hardened["safe_task_rate"]["authorized_tasks_completed_safely"] == 2
    assert report["evidence_hygiene"]["arbitrary_serialized_payload_executed"] is False
    assert report["claim_boundary"]["production_model_registry_claim"] is False


def test_p5a_hardened_module_does_not_import_vulnerable_baseline() -> None:
    source = (
        Path(__file__).resolve().parents[2]
        / "aegis"
        / "model_supply_chain"
        / "provenance.py"
    ).read_text(encoding="utf-8")
    assert "aegis.vulnerable" not in source
    assert "pickle.load" not in source
    assert "torch.load" not in source
