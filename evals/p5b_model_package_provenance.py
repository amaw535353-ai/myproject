from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from dataclasses import dataclass, replace
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.model_supply_chain.package_provenance import (
    ModelPackageComponent,
    ModelPackageComponentRole as Role,
    ModelPackageManifest,
    ModelPackageRejected,
    ModelPackageRequest,
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
from aegis.vulnerable.model_package_loading import VulnerableModelPackageLoader


_ROOT = Path(__file__).resolve().parents[1]
_KEYS = {
    "package": Ed25519PrivateKey.from_private_bytes(bytes.fromhex("31" * 32)),
    "core": Ed25519PrivateKey.from_private_bytes(bytes.fromhex("41" * 32)),
    "adapter": Ed25519PrivateKey.from_private_bytes(bytes.fromhex("42" * 32)),
    "other": Ed25519PrivateKey.from_private_bytes(bytes.fromhex("43" * 32)),
}
_PUBLISHERS = {
    "package": "aegis-package-publisher",
    "core": "aegis-core-model-publisher",
    "adapter": "aegis-adapter-publisher",
    "other": "aegis-other-trusted-publisher",
}
_SOURCES = {
    "core": "registry://aegis-lab/core/",
    "adapter": "registry://aegis-lab/adapters/",
    "other": "registry://aegis-lab/other/",
}
_PACKAGE_ID, _MODEL_ID, _REVISION = "helpdesk-stack", "helpdesk-model", "r2"
_PAYLOADS = {
    "weights": b"AEGIS-INERT-SAFETENSORS-V1\nweights=helpdesk-r2\n",
    "config": b'{"architectures":["AegisSynthetic"],"remote_code":false}\n',
    "tokenizer": b'{"type":"synthetic-bpe","vocab_size":128}\n',
    "adapter": b"AEGIS-INERT-SAFETENSORS-V1\nadapter=helpdesk-tone\n",
    "quantization": b'{"scheme":"synthetic-int8","bits":8}\n',
    "shard": b"AEGIS-INERT-SAFETENSORS-V1\nexternal-data-shard=0\n",
    "rogue": b"print('INERT FIXTURE: NEVER EXECUTED')\n",
}
_TAMPERED_CONFIG = _PAYLOADS["config"] + b"tampered=true\n"
_REPLACEMENT_CONFIG = b'{"architectures":["AegisSyntheticV2"],"remote_code":false}\n'


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    scenario: str


ADVERSARIAL_ATTEMPTS = (
    Attempt("P5B-A1", "missing_required_component"),
    Attempt("P5B-A2", "unexpected_component_injection"),
    Attempt("P5B-A3", "adapter_role_publisher_bypass"),
    Attempt("P5B-A4", "remote_code_requirement"),
    Attempt("P5B-A5", "tampered_transitive_component"),
    Attempt("P5B-A6", "cyclic_dependency_graph"),
    Attempt("P5B-A7", "forged_package_signature"),
    Attempt("P5B-A8", "package_identity_substitution"),
    Attempt("P5B-A9", "same_publisher_component_substitution"),
)
BENIGN_ATTEMPTS = (
    Attempt("P5B-B1", "trusted_core_package"),
    Attempt("P5B-B2", "trusted_package_with_adapter"),
    Attempt("P5B-B3", "trusted_quantized_package_with_external_shard"),
)


def _pub(key: str) -> bytes:
    return _KEYS[key].public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _dataset_hash() -> str:
    body = {
        "adversarial": [item.__dict__ for item in ADVERSARIAL_ATTEMPTS],
        "benign": [item.__dict__ for item in BENIGN_ATTEMPTS],
    }
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _fixture_hash() -> str:
    digest = hashlib.sha256()
    for name, payload in sorted(_PAYLOADS.items()):
        digest.update(name.encode())
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    for payload in (_TAMPERED_CONFIG, _REPLACEMENT_CONFIG):
        digest.update(payload)
    for key in ("package", "core", "adapter", "other"):
        digest.update(_pub(key))
    return digest.hexdigest()


def _git_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unavailable"


def _version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "unavailable"


def _percent(n: int, d: int) -> float:
    return 0.0 if d == 0 else (n / d) * 100.0


def _component(
    artifact_id: str,
    role: Role,
    artifact_format: str,
    *,
    publisher: str | None = None,
    payload: bytes | None = None,
    depends_on: tuple[str, ...] = (),
    remote_code: bool = False,
) -> ModelPackageComponent:
    publisher = publisher or ("adapter" if role is Role.ADAPTER else "core")
    payload = _PAYLOADS[artifact_id] if payload is None else payload
    return ModelPackageComponent(
        artifact_id=artifact_id,
        role=role,
        artifact_format=artifact_format,
        publisher_id=_PUBLISHERS[publisher],
        sha256=sha256_hex(payload),
        size_bytes=len(payload),
        depends_on=depends_on,
        requires_remote_code=remote_code,
    )


def _core() -> tuple[ModelPackageComponent, ...]:
    return (
        _component("config", Role.CONFIG, "json"),
        _component("weights", Role.PRIMARY_MODEL, "safetensors", depends_on=("config",)),
        _component("tokenizer", Role.TOKENIZER, "json", depends_on=("config",)),
    )


def _manifest(
    components: tuple[ModelPackageComponent, ...],
    *,
    remote_code: bool = False,
) -> ModelPackageManifest:
    return ModelPackageManifest(
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        publisher_id=_PUBLISHERS["package"],
        components=components,
        requires_remote_code=remote_code,
    )


def _package_sig(manifest: ModelPackageManifest, *, key: str = "package") -> bytes:
    return _KEYS[key].sign(canonical_package_manifest_bytes(manifest))


def _bundle(
    artifact_id: str,
    payload: bytes,
    artifact_format: str,
    *,
    publisher: str = "core",
) -> SignedModelArtifact:
    manifest = ModelArtifactManifest(
        artifact_id=artifact_id,
        model_id=_MODEL_ID,
        revision=_REVISION,
        publisher_id=_PUBLISHERS[publisher],
        source=f"{_SOURCES[publisher]}{_MODEL_ID}/{_REVISION}/{artifact_id}",
        artifact_format=artifact_format,
        sha256=sha256_hex(payload),
        size_bytes=len(payload),
    )
    return SignedModelArtifact(
        manifest=manifest,
        signature=_KEYS[publisher].sign(canonical_manifest_bytes(manifest)),
        payload=payload,
    )


def _artifacts(
    components: tuple[ModelPackageComponent, ...],
    *,
    adapter_publisher: str = "adapter",
) -> dict[str, SignedModelArtifact]:
    formats = {
        "weights": "safetensors",
        "config": "json",
        "tokenizer": "json",
        "adapter": "safetensors",
        "quantization": "json",
        "shard": "safetensors",
    }
    result = {}
    for item in components:
        publisher = adapter_publisher if item.artifact_id == "adapter" else "core"
        result[item.artifact_id] = _bundle(
            item.artifact_id,
            _PAYLOADS[item.artifact_id],
            formats[item.artifact_id],
            publisher=publisher,
        )
    return result


def _policy() -> ModelPackageTrustPolicy:
    artifact_policy = ModelArtifactTrustPolicy(
        trusted_publishers={
            _PUBLISHERS["core"]: _pub("core"),
            _PUBLISHERS["adapter"]: _pub("adapter"),
            _PUBLISHERS["other"]: _pub("other"),
        },
        trusted_source_prefixes={
            _PUBLISHERS["core"]: (_SOURCES["core"],),
            _PUBLISHERS["adapter"]: (_SOURCES["adapter"],),
            _PUBLISHERS["other"]: (_SOURCES["other"],),
        },
        allowed_formats=frozenset({"safetensors", "onnx", "json"}),
        max_artifact_bytes=4096,
    )
    return ModelPackageTrustPolicy(
        package_publishers={_PUBLISHERS["package"]: _pub("package")},
        artifact_policy=artifact_policy,
        role_publishers={
            Role.PRIMARY_MODEL: frozenset({_PUBLISHERS["core"]}),
            Role.CONFIG: frozenset({_PUBLISHERS["core"]}),
            Role.TOKENIZER: frozenset({_PUBLISHERS["core"]}),
            Role.ADAPTER: frozenset({_PUBLISHERS["adapter"]}),
            Role.QUANTIZATION_METADATA: frozenset({_PUBLISHERS["core"]}),
            Role.EXTERNAL_DATA: frozenset({_PUBLISHERS["core"]}),
        },
        allow_remote_code=False,
    )


def _attack_cases() -> tuple[dict[str, Any], ...]:
    request = ModelPackageRequest(_PACKAGE_ID, _MODEL_ID, _REVISION)
    core = _core()
    core_manifest, core_artifacts = _manifest(core), _artifacts(core)

    missing = dict(core_artifacts)
    missing.pop("tokenizer")

    injected = dict(core_artifacts)
    injected["rogue-code"] = _bundle(
        "rogue-code", _PAYLOADS["rogue"], "json", publisher="other"
    )

    adapter_components = core + (
        _component(
            "adapter",
            Role.ADAPTER,
            "safetensors",
            publisher="other",
            depends_on=("weights",),
        ),
    )
    adapter_manifest = _manifest(adapter_components)
    adapter_artifacts = _artifacts(adapter_components, adapter_publisher="other")

    remote_components = tuple(
        replace(item, requires_remote_code=True)
        if item.artifact_id == "config"
        else item
        for item in core
    )
    remote_manifest = _manifest(remote_components)

    tampered = dict(core_artifacts)
    config = tampered["config"]
    tampered["config"] = SignedModelArtifact(
        config.manifest, config.signature, _TAMPERED_CONFIG
    )

    cyclic = (
        _component("config", Role.CONFIG, "json", depends_on=("tokenizer",)),
        _component("weights", Role.PRIMARY_MODEL, "safetensors", depends_on=("config",)),
        _component("tokenizer", Role.TOKENIZER, "json", depends_on=("config",)),
    )
    cyclic_manifest = _manifest(cyclic)

    substituted = dict(core_artifacts)
    substituted["config"] = _bundle("config", _REPLACEMENT_CONFIG, "json")

    def case(
        attempt_id: str,
        scenario: str,
        manifest: ModelPackageManifest,
        artifacts: dict[str, SignedModelArtifact],
        *,
        signature: bytes | None = None,
        request_override: ModelPackageRequest | None = None,
    ) -> dict[str, Any]:
        return {
            "attempt_id": attempt_id,
            "scenario": scenario,
            "request": request_override or request,
            "manifest": manifest,
            "signature": signature if signature is not None else _package_sig(manifest),
            "artifacts": artifacts,
        }

    return (
        case("P5B-A1", "missing_required_component", core_manifest, missing),
        case("P5B-A2", "unexpected_component_injection", core_manifest, injected),
        case("P5B-A3", "adapter_role_publisher_bypass", adapter_manifest, adapter_artifacts),
        case("P5B-A4", "remote_code_requirement", remote_manifest, _artifacts(remote_components)),
        case("P5B-A5", "tampered_transitive_component", core_manifest, tampered),
        case("P5B-A6", "cyclic_dependency_graph", cyclic_manifest, _artifacts(cyclic)),
        case(
            "P5B-A7",
            "forged_package_signature",
            core_manifest,
            core_artifacts,
            signature=_package_sig(core_manifest, key="other"),
        ),
        case(
            "P5B-A8",
            "package_identity_substitution",
            core_manifest,
            core_artifacts,
            request_override=ModelPackageRequest("other-package", _MODEL_ID, _REVISION),
        ),
        case(
            "P5B-A9",
            "same_publisher_component_substitution",
            core_manifest,
            substituted,
        ),
    )


def _benign_cases() -> tuple[dict[str, Any], ...]:
    request = ModelPackageRequest(_PACKAGE_ID, _MODEL_ID, _REVISION)
    component_sets = (
        ("P5B-B1", "trusted_core_package", _core()),
        (
            "P5B-B2",
            "trusted_package_with_adapter",
            _core()
            + (_component("adapter", Role.ADAPTER, "safetensors", depends_on=("weights",)),),
        ),
        (
            "P5B-B3",
            "trusted_quantized_package_with_external_shard",
            _core()
            + (
                _component(
                    "quantization",
                    Role.QUANTIZATION_METADATA,
                    "json",
                    depends_on=("weights",),
                ),
                _component(
                    "shard",
                    Role.EXTERNAL_DATA,
                    "safetensors",
                    depends_on=("weights",),
                ),
            ),
        ),
    )
    cases = []
    for attempt_id, scenario, components in component_sets:
        manifest = _manifest(components)
        cases.append(
            {
                "attempt_id": attempt_id,
                "scenario": scenario,
                "request": request,
                "manifest": manifest,
                "signature": _package_sig(manifest),
                "artifacts": _artifacts(components),
            }
        )
    return tuple(cases)


def _run_variant(variant: Literal["vulnerable", "hardened"]) -> dict[str, Any]:
    loader = (
        VulnerableModelPackageLoader()
        if variant == "vulnerable"
        else RestrictedModelPackageLoader(_policy())
    )
    attacks, benign = [], []
    for case in _attack_cases():
        accepted, reason, component, nested = False, None, None, None
        try:
            loader.load(
                request=case["request"],
                manifest=case["manifest"],
                package_signature=case["signature"],
                artifacts=case["artifacts"],
            )
            accepted = True
        except ModelPackageRejected as exc:
            reason, component, nested = (
                exc.reason.value,
                exc.component_id,
                exc.nested_reason,
            )
        except ValueError as exc:
            reason = type(exc).__name__
        attacks.append(
            {
                "attempt_id": case["attempt_id"],
                "scenario": case["scenario"],
                "valid": True,
                "success": accepted,
                "accepted": accepted,
                "rejection_reason": reason,
                "component_id": component,
                "nested_reason": nested,
                "payload_executed": False,
                "network_operations": 0,
            }
        )

    for case in _benign_cases():
        blocked, safe = False, False
        try:
            handle = loader.load(
                request=case["request"],
                manifest=case["manifest"],
                package_signature=case["signature"],
                artifacts=case["artifacts"],
            )
            safe = (
                handle.code_executed is False
                if variant == "vulnerable"
                else handle.package_signature_verified
                and handle.transitive_components_verified
                and handle.dependency_graph_verified
                and handle.remote_code_required is False
                and handle.deserialized is False
                and handle.code_execution_capable is False
                and handle.network_operations == 0
                and set(handle.component_artifact_ids) == set(case["artifacts"])
            )
        except (ModelPackageRejected, ValueError):
            blocked = True
        benign.append(
            {
                "attempt_id": case["attempt_id"],
                "scenario": case["scenario"],
                "valid": True,
                "incorrectly_blocked": blocked,
                "safe_completion": safe,
                "payload_executed": False,
                "network_operations": 0,
            }
        )

    successes = sum(item["success"] for item in attacks)
    false_positives = sum(item["incorrectly_blocked"] for item in benign)
    safe_tasks = sum(item["safe_completion"] for item in benign)
    return {
        "policy_version": (
            "primary-only-model-package-loader-v1"
            if variant == "vulnerable"
            else "transitive-model-package-provenance-v1"
        ),
        "metrics": {
            "asr": {
                "successful_policy_violations": successes,
                "valid_adversarial_attempts": len(attacks),
                "percent": _percent(successes, len(attacks)),
            },
            "fpr": {
                "benign_requests_incorrectly_blocked": false_positives,
                "valid_benign_requests": len(benign),
                "percent": _percent(false_positives, len(benign)),
            },
            "safe_task_rate": {
                "authorized_tasks_completed_safely": safe_tasks,
                "authorized_tasks_attempted": len(benign),
                "percent": _percent(safe_tasks, len(benign)),
            },
        },
        "adversarial_attempts": attacks,
        "benign_attempts": benign,
    }


def build_report() -> dict[str, Any]:
    return {
        "evaluation": "P5-B transitive model-package and adapter provenance",
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
            "reason": "P5-B evaluates inert package provenance without running a model",
        },
        "evidence_hygiene": {
            "network_operations": 0,
            "real_model_downloads": False,
            "real_registry_credentials": False,
            "arbitrary_serialized_payload_executed": False,
            "remote_model_code_executed": False,
            "fixture_payloads_inert": True,
            "production_signing_key_claim": False,
        },
        "claim_boundary": {
            "signed_package_closure": True,
            "package_pinned_component_digests": True,
            "transitive_artifact_provenance": True,
            "role_specific_publisher_policy": True,
            "dependency_cycle_rejection": True,
            "remote_code_requirement_rejected": True,
            "adapter_composition_policy": True,
            "real_model_parser_claim": False,
            "remote_registry_acquisition_claim": False,
            "sandboxed_inference_claim": False,
            "model_behavior_safety_claim": False,
            "production_key_custody_claim": False,
        },
        "versions": {
            "aegisdesk": _version("aegisdesk"),
            "cryptography": _version("cryptography"),
        },
        "variants": {
            "vulnerable": _run_variant("vulnerable"),
            "hardened": _run_variant("hardened"),
        },
    }


def _assert_expected_security_delta(report: dict[str, Any]) -> None:
    vulnerable = report["variants"]["vulnerable"]["metrics"]
    hardened = report["variants"]["hardened"]["metrics"]
    if not (
        vulnerable["asr"]["successful_policy_violations"] == 9
        and vulnerable["asr"]["valid_adversarial_attempts"] == 9
        and hardened["asr"]["successful_policy_violations"] == 0
        and hardened["asr"]["valid_adversarial_attempts"] == 9
        and hardened["fpr"]["benign_requests_incorrectly_blocked"] == 0
        and hardened["fpr"]["valid_benign_requests"] == 3
        and hardened["safe_task_rate"]["authorized_tasks_completed_safely"] == 3
        and hardened["safe_task_rate"]["authorized_tasks_attempted"] == 3
    ):
        raise SystemExit("P5-B security delta did not match the expected invariant")


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
