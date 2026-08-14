from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, replace
from importlib.metadata import PackageNotFoundError, version
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.model_supply_chain.key_lifecycle import (
    BoundProvenanceSignature,
    KeyLifecyclePolicy,
    KeyLifecycleRejected,
    LifecycleModelPackageTrustPolicy,
    LifecycleRestrictedModelPackageLoader,
    LifecycleSignedModelArtifact,
    SigningKeyRecord,
    SigningKeyState,
    SigningKeyUsage,
    canonical_bound_signature_bytes,
)
from aegis.model_supply_chain.package_provenance import (
    ModelPackageComponent,
    ModelPackageComponentRole,
    ModelPackageManifest,
    ModelPackageRequest,
    canonical_package_manifest_bytes,
)
from aegis.model_supply_chain.provenance import (
    ModelArtifactManifest,
    canonical_manifest_bytes,
    sha256_hex,
)
from aegis.vulnerable.key_lifecycle import VulnerableKeyLifecyclePackageLoader


NOW = 1_800_000_000
ISSUER = "aegis-provenance-ca"
SHADOW_ISSUER = "shadow-provenance-ca"
ARTIFACT_PUBLISHER = "aegis-model-publisher"
PACKAGE_PUBLISHER = "aegis-package-publisher"
SOURCE_PREFIX = "registry://aegis-lab/releases/"
MODEL_ID = "helpdesk-model"
PACKAGE_ID = "helpdesk-model-package"
REVISION = "r4"
PRIMARY = b"AEGIS-P5D-INERT-MODEL\n"
TOKENIZER = b'{"tokenizer":"aegis-p5d-inert"}\n'
PRIMARY_V2 = b"AEGIS-P5D-INERT-MODEL-V2\n"

_KEY_SEEDS = {
    "artifact-active-a": "51",
    "artifact-active-b": "52",
    "artifact-expired": "53",
    "artifact-future": "54",
    "artifact-revoked": "55",
    "artifact-retired": "56",
    "package-active-a": "61",
    "package-active-b": "62",
    "package-revoked": "63",
    "package-retired": "64",
    "package-shadow": "65",
    "package-artifact-usage": "66",
    "package-spare": "67",
    "unknown-package-key": "68",
}
_PRIVATE_KEYS = {
    key_id: Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed * 32))
    for key_id, seed in _KEY_SEEDS.items()
}
_PUBLIC_KEYS = {
    key_id: private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    for key_id, private in _PRIVATE_KEYS.items()
}


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    scenario: Literal[
        "expired_artifact_key",
        "revoked_artifact_key",
        "retired_artifact_key",
        "future_artifact_key",
        "revoked_package_key",
        "retired_package_key",
        "unknown_package_key",
        "untrusted_issuer",
        "package_usage_confusion",
        "publisher_binding_mismatch",
        "key_id_substitution",
        "subject_binding_mismatch",
    ]


@dataclass(frozen=True)
class BenignAttempt:
    attempt_id: str
    scenario: Literal[
        "active_generation_a",
        "rotation_overlap_generation_b",
        "successor_release_content",
    ]


ADVERSARIAL_ATTEMPTS = (
    Attempt("P5D-A1", "expired_artifact_key"),
    Attempt("P5D-A2", "revoked_artifact_key"),
    Attempt("P5D-A3", "retired_artifact_key"),
    Attempt("P5D-A4", "future_artifact_key"),
    Attempt("P5D-A5", "revoked_package_key"),
    Attempt("P5D-A6", "retired_package_key"),
    Attempt("P5D-A7", "unknown_package_key"),
    Attempt("P5D-A8", "untrusted_issuer"),
    Attempt("P5D-A9", "package_usage_confusion"),
    Attempt("P5D-A10", "publisher_binding_mismatch"),
    Attempt("P5D-A11", "key_id_substitution"),
    Attempt("P5D-A12", "subject_binding_mismatch"),
)
BENIGN_ATTEMPTS = (
    BenignAttempt("P5D-B1", "active_generation_a"),
    BenignAttempt("P5D-B2", "rotation_overlap_generation_b"),
    BenignAttempt("P5D-B3", "successor_release_content"),
)


def _record(
    key_id: str,
    *,
    publisher_id: str,
    usage: SigningKeyUsage,
    issuer_id: str = ISSUER,
    valid_from: int = NOW - 10_000,
    valid_until: int = NOW + 10_000,
    state: SigningKeyState = SigningKeyState.ACTIVE,
    retired_at: int | None = None,
    revoked_at: int | None = None,
    successor_key_id: str | None = None,
) -> SigningKeyRecord:
    return SigningKeyRecord(
        key_id=key_id,
        issuer_id=issuer_id,
        publisher_id=publisher_id,
        public_key=_PUBLIC_KEYS[key_id],
        usages=frozenset({usage}),
        valid_from=valid_from,
        valid_until=valid_until,
        state=state,
        retired_at=retired_at,
        revoked_at=revoked_at,
        successor_key_id=successor_key_id,
    )


def _keyring() -> dict[str, SigningKeyRecord]:
    return {
        "artifact-active-a": _record(
            "artifact-active-a",
            publisher_id=ARTIFACT_PUBLISHER,
            usage=SigningKeyUsage.MODEL_ARTIFACT,
            successor_key_id="artifact-active-b",
        ),
        "artifact-active-b": _record(
            "artifact-active-b",
            publisher_id=ARTIFACT_PUBLISHER,
            usage=SigningKeyUsage.MODEL_ARTIFACT,
        ),
        "artifact-expired": _record(
            "artifact-expired",
            publisher_id=ARTIFACT_PUBLISHER,
            usage=SigningKeyUsage.MODEL_ARTIFACT,
            valid_from=NOW - 10_000,
            valid_until=NOW - 50,
        ),
        "artifact-future": _record(
            "artifact-future",
            publisher_id=ARTIFACT_PUBLISHER,
            usage=SigningKeyUsage.MODEL_ARTIFACT,
            valid_from=NOW + 100,
            valid_until=NOW + 20_000,
        ),
        "artifact-revoked": _record(
            "artifact-revoked",
            publisher_id=ARTIFACT_PUBLISHER,
            usage=SigningKeyUsage.MODEL_ARTIFACT,
            state=SigningKeyState.REVOKED,
            revoked_at=NOW - 50,
        ),
        "artifact-retired": _record(
            "artifact-retired",
            publisher_id=ARTIFACT_PUBLISHER,
            usage=SigningKeyUsage.MODEL_ARTIFACT,
            state=SigningKeyState.RETIRED,
            retired_at=NOW - 50,
            successor_key_id="artifact-active-b",
        ),
        "package-active-a": _record(
            "package-active-a",
            publisher_id=PACKAGE_PUBLISHER,
            usage=SigningKeyUsage.MODEL_PACKAGE,
            successor_key_id="package-active-b",
        ),
        "package-active-b": _record(
            "package-active-b",
            publisher_id=PACKAGE_PUBLISHER,
            usage=SigningKeyUsage.MODEL_PACKAGE,
        ),
        "package-revoked": _record(
            "package-revoked",
            publisher_id=PACKAGE_PUBLISHER,
            usage=SigningKeyUsage.MODEL_PACKAGE,
            state=SigningKeyState.REVOKED,
            revoked_at=NOW - 50,
        ),
        "package-retired": _record(
            "package-retired",
            publisher_id=PACKAGE_PUBLISHER,
            usage=SigningKeyUsage.MODEL_PACKAGE,
            state=SigningKeyState.RETIRED,
            retired_at=NOW - 50,
            successor_key_id="package-active-b",
        ),
        "package-shadow": _record(
            "package-shadow",
            publisher_id=PACKAGE_PUBLISHER,
            usage=SigningKeyUsage.MODEL_PACKAGE,
            issuer_id=SHADOW_ISSUER,
        ),
        "package-artifact-usage": _record(
            "package-artifact-usage",
            publisher_id=PACKAGE_PUBLISHER,
            usage=SigningKeyUsage.MODEL_ARTIFACT,
        ),
        "package-spare": _record(
            "package-spare",
            publisher_id=PACKAGE_PUBLISHER,
            usage=SigningKeyUsage.MODEL_PACKAGE,
        ),
    }


def _policy() -> LifecycleModelPackageTrustPolicy:
    return LifecycleModelPackageTrustPolicy(
        key_lifecycle=KeyLifecyclePolicy(
            keys=_keyring(),
            trusted_issuers=frozenset({ISSUER}),
            evaluation_time=NOW,
        ),
        trusted_source_prefixes={ARTIFACT_PUBLISHER: (SOURCE_PREFIX,)},
        role_publishers={
            role: frozenset({ARTIFACT_PUBLISHER})
            for role in ModelPackageComponentRole
        },
        allowed_formats=frozenset({"safetensors", "json"}),
        max_artifact_bytes=4096,
    )


def _sign_bound(
    *,
    subject: bytes,
    key_id: str,
    publisher_id: str,
    usage: SigningKeyUsage,
    signed_at: int,
    issuer_id: str = ISSUER,
) -> BoundProvenanceSignature:
    draft = BoundProvenanceSignature(
        key_id=key_id,
        issuer_id=issuer_id,
        publisher_id=publisher_id,
        usage=usage,
        signed_at=signed_at,
        subject_sha256=hashlib.sha256(subject).hexdigest(),
        signature=b"",
        legacy_signature=_PRIVATE_KEYS[key_id].sign(subject),
    )
    return replace(
        draft,
        signature=_PRIVATE_KEYS[key_id].sign(canonical_bound_signature_bytes(draft)),
    )


def _artifact(
    artifact_id: str,
    payload: bytes,
    artifact_format: str,
    key_id: str,
    *,
    signed_at: int,
) -> LifecycleSignedModelArtifact:
    manifest = ModelArtifactManifest(
        artifact_id=artifact_id,
        model_id=MODEL_ID,
        revision=REVISION,
        publisher_id=ARTIFACT_PUBLISHER,
        source=f"{SOURCE_PREFIX}{MODEL_ID}/{REVISION}/{artifact_id}",
        artifact_format=artifact_format,
        sha256=sha256_hex(payload),
        size_bytes=len(payload),
    )
    return LifecycleSignedModelArtifact(
        manifest=manifest,
        signature=_sign_bound(
            subject=canonical_manifest_bytes(manifest),
            key_id=key_id,
            publisher_id=ARTIFACT_PUBLISHER,
            usage=SigningKeyUsage.MODEL_ARTIFACT,
            signed_at=signed_at,
        ),
        payload=payload,
    )


def _bundle(
    *,
    artifact_key_id: str = "artifact-active-b",
    package_key_id: str = "package-active-b",
    artifact_signed_at: int = NOW - 10,
    package_signed_at: int = NOW - 10,
    primary_payload: bytes = PRIMARY,
    package_issuer: str = ISSUER,
) -> tuple[
    ModelPackageRequest,
    ModelPackageManifest,
    BoundProvenanceSignature,
    dict[str, LifecycleSignedModelArtifact],
]:
    artifacts = {
        "model": _artifact(
            "model",
            primary_payload,
            "safetensors",
            artifact_key_id,
            signed_at=artifact_signed_at,
        ),
        "tokenizer": _artifact(
            "tokenizer",
            TOKENIZER,
            "json",
            artifact_key_id,
            signed_at=artifact_signed_at,
        ),
    }
    components = (
        ModelPackageComponent(
            artifact_id="model",
            role=ModelPackageComponentRole.PRIMARY_MODEL,
            artifact_format="safetensors",
            publisher_id=ARTIFACT_PUBLISHER,
            sha256=artifacts["model"].manifest.sha256,
            size_bytes=artifacts["model"].manifest.size_bytes,
        ),
        ModelPackageComponent(
            artifact_id="tokenizer",
            role=ModelPackageComponentRole.TOKENIZER,
            artifact_format="json",
            publisher_id=ARTIFACT_PUBLISHER,
            sha256=artifacts["tokenizer"].manifest.sha256,
            size_bytes=artifacts["tokenizer"].manifest.size_bytes,
            depends_on=("model",),
        ),
    )
    manifest = ModelPackageManifest(
        package_id=PACKAGE_ID,
        model_id=MODEL_ID,
        revision=REVISION,
        publisher_id=PACKAGE_PUBLISHER,
        components=components,
    )
    package_signature = _sign_bound(
        subject=canonical_package_manifest_bytes(manifest),
        key_id=package_key_id,
        publisher_id=PACKAGE_PUBLISHER,
        usage=SigningKeyUsage.MODEL_PACKAGE,
        signed_at=package_signed_at,
        issuer_id=package_issuer,
    )
    return (
        ModelPackageRequest(PACKAGE_ID, MODEL_ID, REVISION),
        manifest,
        package_signature,
        artifacts,
    )


def _attack_case(scenario: str):
    if scenario == "expired_artifact_key":
        return _bundle(artifact_key_id="artifact-expired", artifact_signed_at=NOW - 100)
    if scenario == "revoked_artifact_key":
        return _bundle(artifact_key_id="artifact-revoked", artifact_signed_at=NOW - 100)
    if scenario == "retired_artifact_key":
        return _bundle(artifact_key_id="artifact-retired", artifact_signed_at=NOW - 100)
    if scenario == "future_artifact_key":
        return _bundle(artifact_key_id="artifact-future", artifact_signed_at=NOW)
    if scenario == "revoked_package_key":
        return _bundle(package_key_id="package-revoked", package_signed_at=NOW - 100)
    if scenario == "retired_package_key":
        return _bundle(package_key_id="package-retired", package_signed_at=NOW - 100)
    if scenario == "unknown_package_key":
        request, manifest, _, artifacts = _bundle()
        signature = _sign_bound(
            subject=canonical_package_manifest_bytes(manifest),
            key_id="unknown-package-key",
            publisher_id=PACKAGE_PUBLISHER,
            usage=SigningKeyUsage.MODEL_PACKAGE,
            signed_at=NOW - 10,
        )
        return request, manifest, signature, artifacts
    if scenario == "untrusted_issuer":
        return _bundle(
            package_key_id="package-shadow",
            package_issuer=SHADOW_ISSUER,
        )
    if scenario == "package_usage_confusion":
        request, manifest, _, artifacts = _bundle()
        signature = _sign_bound(
            subject=canonical_package_manifest_bytes(manifest),
            key_id="package-artifact-usage",
            publisher_id=PACKAGE_PUBLISHER,
            usage=SigningKeyUsage.MODEL_PACKAGE,
            signed_at=NOW - 10,
        )
        return request, manifest, signature, artifacts
    if scenario == "publisher_binding_mismatch":
        request, manifest, _, artifacts = _bundle()
        signature = _sign_bound(
            subject=canonical_package_manifest_bytes(manifest),
            key_id="package-active-b",
            publisher_id="other-publisher",
            usage=SigningKeyUsage.MODEL_PACKAGE,
            signed_at=NOW - 10,
        )
        return request, manifest, signature, artifacts
    if scenario == "key_id_substitution":
        request, manifest, signature, artifacts = _bundle(
            package_key_id="package-active-b"
        )
        return request, manifest, replace(signature, key_id="package-spare"), artifacts
    if scenario == "subject_binding_mismatch":
        request, manifest, signature, artifacts = _bundle()
        return (
            request,
            manifest,
            replace(
                signature,
                subject_sha256=hashlib.sha256(b"different-release").hexdigest(),
            ),
            artifacts,
        )
    raise ValueError(scenario)


def _benign_case(scenario: str):
    if scenario == "active_generation_a":
        return _bundle(
            artifact_key_id="artifact-active-a",
            package_key_id="package-active-a",
        )
    if scenario == "rotation_overlap_generation_b":
        return _bundle(
            artifact_key_id="artifact-active-b",
            package_key_id="package-active-b",
        )
    if scenario == "successor_release_content":
        return _bundle(
            artifact_key_id="artifact-active-b",
            package_key_id="package-active-b",
            primary_payload=PRIMARY_V2,
        )
    raise ValueError(scenario)


def dataset_sha256() -> str:
    payload = json.dumps(
        {
            "adversarial": [asdict(item) for item in ADVERSARIAL_ATTEMPTS],
            "benign": [asdict(item) for item in BENIGN_ATTEMPTS],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def fixture_sha256() -> str:
    digest = hashlib.sha256()
    for payload in (PRIMARY, TOKENIZER, PRIMARY_V2):
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    for key_id in sorted(_PUBLIC_KEYS):
        value = key_id.encode("utf-8") + b"\0" + _PUBLIC_KEYS[key_id]
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def _package_version() -> str:
    try:
        return version("aegisdesk")
    except PackageNotFoundError:
        return "unavailable"


def run_evaluation() -> dict[str, Any]:
    vulnerable = VulnerableKeyLifecyclePackageLoader()
    hardened = LifecycleRestrictedModelPackageLoader(_policy())
    attack_results: list[dict[str, Any]] = []
    vulnerable_successes = 0
    hardened_successes = 0

    for attempt in ADVERSARIAL_ATTEMPTS:
        request, manifest, package_signature, artifacts = _attack_case(attempt.scenario)
        try:
            vulnerable.load(
                request=request,
                manifest=manifest,
                package_signature=package_signature,
                artifacts=artifacts,
            )
            vulnerable_accepted = True
            vulnerable_successes += 1
        except Exception:
            vulnerable_accepted = False

        try:
            hardened.load(
                request=request,
                manifest=manifest,
                package_signature=package_signature,
                artifacts=artifacts,
            )
            hardened_accepted = True
            hardened_successes += 1
            reject_reason = None
        except KeyLifecycleRejected as exc:
            hardened_accepted = False
            reject_reason = exc.reason.value

        attack_results.append(
            {
                "attempt_id": attempt.attempt_id,
                "scenario": attempt.scenario,
                "vulnerable_accepted": vulnerable_accepted,
                "hardened_accepted": hardened_accepted,
                "hardened_reject_reason": reject_reason,
            }
        )

    benign_results: list[dict[str, Any]] = []
    hardened_false_positives = 0
    safe_successes = 0
    for attempt in BENIGN_ATTEMPTS:
        request, manifest, package_signature, artifacts = _benign_case(attempt.scenario)
        try:
            handle = hardened.load(
                request=request,
                manifest=manifest,
                package_signature=package_signature,
                artifacts=artifacts,
            )
            accepted = True
            safe_successes += 1
            package_key_id = handle.package_key_id
        except KeyLifecycleRejected:
            accepted = False
            hardened_false_positives += 1
            package_key_id = None

        benign_results.append(
            {
                "attempt_id": attempt.attempt_id,
                "scenario": attempt.scenario,
                "hardened_accepted": accepted,
                "package_key_id": package_key_id,
            }
        )

    report = {
        "milestone": "P5-D",
        "policy": "provenance signing-key lifecycle and revocation",
        "metrics": {
            "vulnerable_asr": f"{vulnerable_successes}/{len(ADVERSARIAL_ATTEMPTS)}",
            "hardened_asr": f"{hardened_successes}/{len(ADVERSARIAL_ATTEMPTS)}",
            "hardened_fpr": f"{hardened_false_positives}/{len(BENIGN_ATTEMPTS)}",
            "safe_task_rate": f"{safe_successes}/{len(BENIGN_ATTEMPTS)}",
        },
        "dataset_sha256": dataset_sha256(),
        "fixture_sha256": fixture_sha256(),
        "package_version": _package_version(),
        "attacks": attack_results,
        "benign": benign_results,
        "evidence_hygiene": {
            "network_operations": 0,
            "real_model_downloads": False,
            "production_signing_keys": False,
            "hsm_or_kms_integration": False,
            "transparency_log_claim": False,
            "fixture_payloads_inert": True,
            "arbitrary_serialized_payload_executed": False,
        },
        "claim_boundary": {
            "issuer_and_key_id_binding": True,
            "signature_metadata_binding": True,
            "validity_window_enforcement": True,
            "current_expiry_enforcement": True,
            "explicit_revocation": True,
            "controlled_rotation_retirement": True,
            "usage_scoped_keys": True,
            "nested_p5b_package_provenance": True,
            "production_kms_hsm": False,
            "certificate_chain_validation": False,
            "online_revocation_service": False,
            "transparency_log_verification": False,
        },
    }

    if report["metrics"] != {
        "vulnerable_asr": "12/12",
        "hardened_asr": "0/12",
        "hardened_fpr": "0/3",
        "safe_task_rate": "3/3",
    }:
        raise AssertionError(report["metrics"])
    return report


def main() -> None:
    print(json.dumps(run_evaluation(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
