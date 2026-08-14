from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass, replace
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.model_supply_chain.package_provenance import (
    ModelPackageComponent,
    ModelPackageComponentRole,
    ModelPackageManifest,
    ModelPackageTrustPolicy,
    RestrictedModelPackageLoader,
    SignedModelArtifact,
    canonical_package_manifest_bytes,
)
from aegis.model_supply_chain.provenance import (
    ModelArtifactManifest,
    ModelArtifactTrustPolicy,
    canonical_manifest_bytes,
    sha256_hex,
)
from aegis.model_supply_chain.registry_acquisition import (
    ImmutableModelRegistryAcquirer,
    RegistryAcquisitionPolicy,
    RegistryAcquisitionRejected,
    RegistryFetchResult,
    RegistryReleaseCache,
    RegistryReleaseEnvelope,
    RegistryReleasePin,
    RegistryReleasePointer,
    registry_release_digest,
)
from aegis.vulnerable.model_registry_acquisition import VulnerableMutableRegistryAcquirer


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_ARTIFACT_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("31" * 32))
_PACKAGE_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("41" * 32))
_ARTIFACT_PUBLIC_KEY = _ARTIFACT_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
_PACKAGE_PUBLIC_KEY = _PACKAGE_PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
_ARTIFACT_PUBLISHER = "aegis-model-publisher"
_PACKAGE_PUBLISHER = "aegis-release-publisher"
_REGISTRY_ID = "aegis-model-registry"
_TRUSTED_SOURCE_PREFIX = "registry://aegis-model-registry/immutable/"
_TRUSTED_MIRROR_PREFIX = "registry://aegis-model-mirror/immutable/"
_EVIL_SOURCE_PREFIX = "registry://attacker-registry/"
_CHANNEL = "production"
_TAG = "stable"
_MODEL_ID = "helpdesk-model"
_PACKAGE_ID = "helpdesk-model-package"
_REVISION = "r3"

_PRIMARY = b"AEGIS-P5C-INERT-MODEL\n"
_TOKENIZER = b'{"tokenizer":"aegis-inert"}\n'
_ADAPTER = b"AEGIS-P5C-INERT-ADAPTER\n"
_PRIMARY_V2 = b"AEGIS-P5C-INERT-MODEL-V2\n"


@dataclass(frozen=True)
class AdversarialAttempt:
    attempt_id: str
    scenario: Literal[
        "mutable_tag_drift",
        "channel_unpinned",
        "untrusted_registry",
        "untrusted_resolved_source",
        "untrusted_redirect",
        "release_digest_mismatch",
        "cache_substitution",
        "release_package_identity_substitution",
    ]


@dataclass(frozen=True)
class BenignAttempt:
    attempt_id: str
    scenario: Literal[
        "exact_digest_pinned_release",
        "trusted_redirect_release",
        "warm_verified_cache",
    ]


ADVERSARIAL_ATTEMPTS = (
    AdversarialAttempt("P5C-A1", "mutable_tag_drift"),
    AdversarialAttempt("P5C-A2", "channel_unpinned"),
    AdversarialAttempt("P5C-A3", "untrusted_registry"),
    AdversarialAttempt("P5C-A4", "untrusted_resolved_source"),
    AdversarialAttempt("P5C-A5", "untrusted_redirect"),
    AdversarialAttempt("P5C-A6", "release_digest_mismatch"),
    AdversarialAttempt("P5C-A7", "cache_substitution"),
    AdversarialAttempt("P5C-A8", "release_package_identity_substitution"),
)
BENIGN_ATTEMPTS = (
    BenignAttempt("P5C-B1", "exact_digest_pinned_release"),
    BenignAttempt("P5C-B2", "trusted_redirect_release"),
    BenignAttempt("P5C-B3", "warm_verified_cache"),
)


class SyntheticRegistryTransport:
    def __init__(self, pointer: RegistryReleasePointer, fetched: RegistryFetchResult) -> None:
        self.pointer = pointer
        self.fetched = fetched
        self.resolve_calls = 0
        self.fetch_calls = 0

    def resolve(self, *, registry_id: str, channel: str, tag: str) -> RegistryReleasePointer:
        self.resolve_calls += 1
        return self.pointer

    def fetch_by_digest(self, *, registry_id: str, source: str, release_digest: str) -> RegistryFetchResult:
        self.fetch_calls += 1
        return self.fetched


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
        _PRIMARY,
        _TOKENIZER,
        _ADAPTER,
        _PRIMARY_V2,
        _ARTIFACT_PUBLIC_KEY,
        _PACKAGE_PUBLIC_KEY,
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


def _artifact_bundle(artifact_id: str, payload: bytes, artifact_format: str) -> SignedModelArtifact:
    manifest = ModelArtifactManifest(
        artifact_id=artifact_id,
        model_id=_MODEL_ID,
        revision=_REVISION,
        publisher_id=_ARTIFACT_PUBLISHER,
        source=f"{_TRUSTED_SOURCE_PREFIX}{_MODEL_ID}/{_REVISION}/{artifact_id}",
        artifact_format=artifact_format,
        sha256=sha256_hex(payload),
        size_bytes=len(payload),
    )
    return SignedModelArtifact(
        manifest=manifest,
        signature=_ARTIFACT_PRIVATE_KEY.sign(canonical_manifest_bytes(manifest)),
        payload=payload,
    )


def _release_envelope(
    *,
    package_id: str = _PACKAGE_ID,
    model_id: str = _MODEL_ID,
    revision: str = _REVISION,
    primary_payload: bytes = _PRIMARY,
) -> RegistryReleaseEnvelope:
    artifacts = {
        "model": _artifact_bundle("model", primary_payload, "safetensors"),
        "tokenizer": _artifact_bundle("tokenizer", _TOKENIZER, "json"),
        "adapter": _artifact_bundle("adapter", _ADAPTER, "safetensors"),
    }
    if model_id != _MODEL_ID or revision != _REVISION:
        rewritten: dict[str, SignedModelArtifact] = {}
        for artifact_id, bundle in artifacts.items():
            manifest = replace(bundle.manifest, model_id=model_id, revision=revision)
            rewritten[artifact_id] = SignedModelArtifact(
                manifest=manifest,
                signature=_ARTIFACT_PRIVATE_KEY.sign(canonical_manifest_bytes(manifest)),
                payload=bundle.payload,
            )
        artifacts = rewritten

    components = (
        ModelPackageComponent(
            artifact_id="model",
            role=ModelPackageComponentRole.PRIMARY_MODEL,
            artifact_format="safetensors",
            publisher_id=_ARTIFACT_PUBLISHER,
            sha256=artifacts["model"].manifest.sha256,
            size_bytes=artifacts["model"].manifest.size_bytes,
        ),
        ModelPackageComponent(
            artifact_id="tokenizer",
            role=ModelPackageComponentRole.TOKENIZER,
            artifact_format="json",
            publisher_id=_ARTIFACT_PUBLISHER,
            sha256=artifacts["tokenizer"].manifest.sha256,
            size_bytes=artifacts["tokenizer"].manifest.size_bytes,
            depends_on=("model",),
        ),
        ModelPackageComponent(
            artifact_id="adapter",
            role=ModelPackageComponentRole.ADAPTER,
            artifact_format="safetensors",
            publisher_id=_ARTIFACT_PUBLISHER,
            sha256=artifacts["adapter"].manifest.sha256,
            size_bytes=artifacts["adapter"].manifest.size_bytes,
            depends_on=("model",),
        ),
    )
    package_manifest = ModelPackageManifest(
        package_id=package_id,
        model_id=model_id,
        revision=revision,
        publisher_id=_PACKAGE_PUBLISHER,
        components=components,
    )
    return RegistryReleaseEnvelope(
        registry_id=_REGISTRY_ID,
        channel=_CHANNEL,
        tag=_TAG,
        package_manifest=package_manifest,
        package_signature=_PACKAGE_PRIVATE_KEY.sign(canonical_package_manifest_bytes(package_manifest)),
        artifacts=artifacts,
    )


def _package_loader() -> RestrictedModelPackageLoader:
    artifact_policy = ModelArtifactTrustPolicy(
        trusted_publishers={_ARTIFACT_PUBLISHER: _ARTIFACT_PUBLIC_KEY},
        trusted_source_prefixes={_ARTIFACT_PUBLISHER: (_TRUSTED_SOURCE_PREFIX,)},
        allowed_formats=frozenset({"safetensors", "json"}),
        max_artifact_bytes=4096,
    )
    all_roles = {
        role: frozenset({_ARTIFACT_PUBLISHER}) for role in ModelPackageComponentRole
    }
    return RestrictedModelPackageLoader(
        ModelPackageTrustPolicy(
            package_publishers={_PACKAGE_PUBLISHER: _PACKAGE_PUBLIC_KEY},
            artifact_policy=artifact_policy,
            role_publishers=all_roles,
        )
    )


def _policy(
    release_digest: str,
    *,
    registry_id: str = _REGISTRY_ID,
    channel: str = _CHANNEL,
    tag: str = _TAG,
    include_pin: bool = True,
    allow_redirects: bool = False,
) -> RegistryAcquisitionPolicy:
    pins = {(registry_id, channel, tag): release_digest} if include_pin else {}
    return RegistryAcquisitionPolicy(
        trusted_registry_sources={_REGISTRY_ID: (_TRUSTED_SOURCE_PREFIX,)},
        channel_pins=pins,
        allow_redirects=allow_redirects,
        trusted_redirect_sources={
            _REGISTRY_ID: (_TRUSTED_SOURCE_PREFIX, _TRUSTED_MIRROR_PREFIX)
        },
    )


def _pin(
    release_digest: str,
    *,
    registry_id: str = _REGISTRY_ID,
    channel: str = _CHANNEL,
    tag: str = _TAG,
    package_id: str = _PACKAGE_ID,
    model_id: str = _MODEL_ID,
    revision: str = _REVISION,
) -> RegistryReleasePin:
    return RegistryReleasePin(
        registry_id=registry_id,
        channel=channel,
        tag=tag,
        release_digest=release_digest,
        package_id=package_id,
        model_id=model_id,
        revision=revision,
    )


def _pointer(release_digest: str, *, source: str | None = None, registry_id: str = _REGISTRY_ID, channel: str = _CHANNEL) -> RegistryReleasePointer:
    return RegistryReleasePointer(
        registry_id=registry_id,
        channel=channel,
        tag=_TAG,
        release_digest=release_digest,
        source=source or f"{_TRUSTED_SOURCE_PREFIX}{release_digest}",
    )


def _fetched(envelope: RegistryReleaseEnvelope, release_digest: str, *, final_source: str | None = None, redirects: tuple[str, ...] = ()) -> RegistryFetchResult:
    return RegistryFetchResult(
        envelope=envelope,
        final_source=final_source or f"{_TRUSTED_SOURCE_PREFIX}{release_digest}",
        redirects=redirects,
    )


def _attack_cases() -> tuple[dict[str, Any], ...]:
    good = _release_envelope()
    good_digest = registry_release_digest(good)
    newer = _release_envelope(primary_payload=_PRIMARY_V2)
    newer_digest = registry_release_digest(newer)
    wrong_identity = _release_envelope(
        package_id="other-package",
        model_id="other-model",
        revision="r9",
    )
    wrong_identity_digest = registry_release_digest(wrong_identity)

    cache = RegistryReleaseCache()
    cache.put(good_digest, newer)

    return (
        {
            "attempt_id": "P5C-A1",
            "scenario": "mutable_tag_drift",
            "pin": _pin(good_digest),
            "policy": _policy(good_digest),
            "transport": SyntheticRegistryTransport(_pointer(newer_digest), _fetched(newer, newer_digest)),
            "cache": None,
        },
        {
            "attempt_id": "P5C-A2",
            "scenario": "channel_unpinned",
            "pin": _pin(good_digest, channel="canary"),
            "policy": _policy(good_digest, include_pin=False),
            "transport": SyntheticRegistryTransport(_pointer(good_digest, channel="canary"), _fetched(good, good_digest)),
            "cache": None,
        },
        {
            "attempt_id": "P5C-A3",
            "scenario": "untrusted_registry",
            "pin": _pin(good_digest, registry_id="attacker-registry"),
            "policy": _policy(good_digest),
            "transport": SyntheticRegistryTransport(
                _pointer(good_digest, registry_id="attacker-registry", source=f"{_EVIL_SOURCE_PREFIX}{good_digest}"),
                _fetched(good, good_digest, final_source=f"{_EVIL_SOURCE_PREFIX}{good_digest}"),
            ),
            "cache": None,
        },
        {
            "attempt_id": "P5C-A4",
            "scenario": "untrusted_resolved_source",
            "pin": _pin(good_digest),
            "policy": _policy(good_digest),
            "transport": SyntheticRegistryTransport(
                _pointer(good_digest, source=f"{_EVIL_SOURCE_PREFIX}{good_digest}"),
                _fetched(good, good_digest, final_source=f"{_EVIL_SOURCE_PREFIX}{good_digest}"),
            ),
            "cache": None,
        },
        {
            "attempt_id": "P5C-A5",
            "scenario": "untrusted_redirect",
            "pin": _pin(good_digest),
            "policy": _policy(good_digest, allow_redirects=True),
            "transport": SyntheticRegistryTransport(
                _pointer(good_digest),
                _fetched(
                    good,
                    good_digest,
                    final_source=f"{_EVIL_SOURCE_PREFIX}{good_digest}",
                    redirects=(f"{_EVIL_SOURCE_PREFIX}redirect",),
                ),
            ),
            "cache": None,
        },
        {
            "attempt_id": "P5C-A6",
            "scenario": "release_digest_mismatch",
            "pin": _pin(good_digest),
            "policy": _policy(good_digest),
            "transport": SyntheticRegistryTransport(_pointer(good_digest), _fetched(newer, good_digest)),
            "cache": None,
        },
        {
            "attempt_id": "P5C-A7",
            "scenario": "cache_substitution",
            "pin": _pin(good_digest),
            "policy": _policy(good_digest),
            "transport": SyntheticRegistryTransport(_pointer(good_digest), _fetched(good, good_digest)),
            "cache": cache,
        },
        {
            "attempt_id": "P5C-A8",
            "scenario": "release_package_identity_substitution",
            "pin": _pin(wrong_identity_digest),
            "policy": _policy(wrong_identity_digest),
            "transport": SyntheticRegistryTransport(
                _pointer(wrong_identity_digest),
                _fetched(wrong_identity, wrong_identity_digest),
            ),
            "cache": None,
        },
    )


def _benign_cases() -> tuple[dict[str, Any], ...]:
    good = _release_envelope()
    digest = registry_release_digest(good)
    warm_cache = RegistryReleaseCache()
    warm_cache.put(digest, good)
    return (
        {
            "attempt_id": "P5C-B1",
            "scenario": "exact_digest_pinned_release",
            "pin": _pin(digest),
            "policy": _policy(digest),
            "transport": SyntheticRegistryTransport(_pointer(digest), _fetched(good, digest)),
            "cache": None,
        },
        {
            "attempt_id": "P5C-B2",
            "scenario": "trusted_redirect_release",
            "pin": _pin(digest),
            "policy": _policy(digest, allow_redirects=True),
            "transport": SyntheticRegistryTransport(
                _pointer(digest),
                _fetched(
                    good,
                    digest,
                    final_source=f"{_TRUSTED_MIRROR_PREFIX}{digest}",
                    redirects=(f"{_TRUSTED_MIRROR_PREFIX}hop",),
                ),
            ),
            "cache": None,
        },
        {
            "attempt_id": "P5C-B3",
            "scenario": "warm_verified_cache",
            "pin": _pin(digest),
            "policy": _policy(digest),
            "transport": SyntheticRegistryTransport(_pointer(digest), _fetched(good, digest)),
            "cache": warm_cache,
        },
    )


def _run_variant(variant: Literal["vulnerable", "hardened"]) -> dict[str, Any]:
    adversarial_results: list[dict[str, Any]] = []
    benign_results: list[dict[str, Any]] = []

    for case in _attack_cases():
        accepted = False
        rejection_reason = None
        try:
            if variant == "vulnerable":
                VulnerableMutableRegistryAcquirer(case["cache"]).acquire(
                    pin=case["pin"],
                    transport=case["transport"],
                )
            else:
                ImmutableModelRegistryAcquirer(
                    policy=case["policy"],
                    package_loader=_package_loader(),
                    cache=case["cache"],
                ).acquire(pin=case["pin"], transport=case["transport"])
            accepted = True
        except RegistryAcquisitionRejected as exc:
            rejection_reason = exc.reason.value
        adversarial_results.append(
            {
                "attempt_id": case["attempt_id"],
                "scenario": case["scenario"],
                "valid": True,
                "success": accepted,
                "accepted": accepted,
                "rejection_reason": rejection_reason,
                "code_executed": False,
            }
        )

    for case in _benign_cases():
        blocked = False
        safe_completion = False
        fetch_calls = None
        try:
            if variant == "vulnerable":
                VulnerableMutableRegistryAcquirer(case["cache"]).acquire(
                    pin=case["pin"],
                    transport=case["transport"],
                )
                safe_completion = True
            else:
                result = ImmutableModelRegistryAcquirer(
                    policy=case["policy"],
                    package_loader=_package_loader(),
                    cache=case["cache"],
                ).acquire(pin=case["pin"], transport=case["transport"])
                safe_completion = (
                    result.digest_addressed
                    and result.mutable_tag_pin_verified
                    and result.cache_verified
                    and result.code_execution_capable is False
                    and result.package.package_id == case["pin"].package_id
                )
                fetch_calls = case["transport"].fetch_calls
                if case["scenario"] == "warm_verified_cache":
                    safe_completion = safe_completion and fetch_calls == 0
        except RegistryAcquisitionRejected:
            blocked = True
        benign_results.append(
            {
                "attempt_id": case["attempt_id"],
                "scenario": case["scenario"],
                "valid": True,
                "incorrectly_blocked": blocked,
                "safe_completion": safe_completion,
                "fetch_calls": fetch_calls,
                "code_executed": False,
            }
        )

    valid_attacks = len(adversarial_results)
    successful = sum(1 for item in adversarial_results if item["success"])
    valid_benign = len(benign_results)
    false_positives = sum(1 for item in benign_results if item["incorrectly_blocked"])
    safe = sum(1 for item in benign_results if item["safe_completion"])
    return {
        "policy_version": (
            "mutable-tag-trusting-registry-acquisition-v1"
            if variant == "vulnerable"
            else "immutable-model-registry-acquisition-v1"
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
        "evaluation": "P5-C immutable model-registry acquisition and release pinning",
        "definitions": {
            "valid_adversarial_attempt": "A fixed local synthetic registry response violates immutable release, source, redirect, cache, channel, or package-identity policy.",
            "successful_policy_violation": "The acquisition path accepts a release despite the modeled registry trust or release-pinning violation.",
            "false_positive": "A trusted exact-pinned release, trusted redirect, or verified warm-cache acquisition is rejected.",
            "safe_completion": "The exact release digest and package identity are verified before the already-hardened P5-B package boundary receives the release.",
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
            "reason": "P5-C evaluates synthetic local registry acquisition without downloading or executing a model",
        },
        "evidence_hygiene": {
            "real_network_operations": 0,
            "real_model_registry_contacted": False,
            "real_model_downloads": False,
            "real_registry_credentials": False,
            "arbitrary_model_code_executed": False,
            "fixtures_inert": True,
        },
        "claim_boundary": {
            "digest_addressed_release_acquisition": True,
            "mutable_tag_drift_detection": True,
            "trusted_source_and_redirect_policy": True,
            "cache_substitution_detection": True,
            "release_channel_pinning": True,
            "nested_p5b_package_verification": True,
            "production_registry_transport_claim": False,
            "production_cache_integrity_claim": False,
            "production_release_signing_claim": False,
            "secure_real_network_stack_claim": False,
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
        vulnerable["asr"]["successful_policy_violations"] == 8
        and vulnerable["asr"]["valid_adversarial_attempts"] == 8
        and hardened["asr"]["successful_policy_violations"] == 0
        and hardened["asr"]["valid_adversarial_attempts"] == 8
        and hardened["fpr"]["benign_requests_incorrectly_blocked"] == 0
        and hardened["fpr"]["valid_benign_requests"] == 3
        and hardened["safe_task_rate"]["authorized_tasks_completed_safely"] == 3
        and hardened["safe_task_rate"]["authorized_tasks_attempted"] == 3
    )
    if not expected:
        raise SystemExit("P5-C security delta did not match the expected invariant")


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
