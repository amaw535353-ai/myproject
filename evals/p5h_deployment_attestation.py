from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass, replace
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.model_supply_chain.deployment_attestation import (
    DeploymentAttestationPolicy,
    DeploymentAttestationRejected,
    DeploymentAttestationRequest,
    DeploymentAttestationStatement,
    DeploymentAttestationVerifier,
    DeploymentEnvironmentEvidence,
    SignedDeploymentAttestation,
    canonical_deployment_attestation_bytes,
    canonical_privacy_policy_bytes,
    privacy_policy_digest,
)
from aegis.model_supply_chain.model_scanning import VerifiedModelScan
from aegis.model_supply_chain.package_provenance import VerifiedModelPackage
from aegis.model_supply_chain.privacy_controls import PrivacyControlPolicy
from aegis.model_supply_chain.registry_acquisition import VerifiedRegistryRelease
from aegis.model_supply_chain.runtime_isolation import VerifiedRuntimePlan
from aegis.vulnerable.deployment_attestation import VulnerableDeploymentLauncher


_PACKAGE_ID = "helpdesk-deployment-package"
_MODEL_ID = "helpdesk-model"
_REVISION = "r6"
_RUNTIME_ID = "helpdesk-inference"
_DEPLOYMENT_ID = "helpdesk-prod"
_REGISTRY_ID = "aegis-model-registry"
_CHANNEL = "production"
_TAG = "stable"
_ENVIRONMENT_ID = "prod-cluster-a"
_ORCHESTRATOR = "kubernetes-hardened"
_BACKEND = "sandboxed_tensor_runtime"
_EVALUATED_AT = 1_800_000_120

_RELEASE_DIGEST = hashlib.sha256(b"p5h-release-r6").hexdigest()
_SCAN_DIGEST = hashlib.sha256(b"p5h-scan-evidence-r6").hexdigest()
_IMAGE_DIGEST = hashlib.sha256(b"aegis-inference-image-0.53.0").hexdigest()
_RUNTIME_MEASUREMENT = hashlib.sha256(b"aegis-runtime-measurement-v1").hexdigest()
_ALT_DIGEST = hashlib.sha256(b"attacker-substitution").hexdigest()

_ATTESTOR_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("51" * 32))
_ROTATED_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("61" * 32))
_ATTACKER_PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("71" * 32))


def _public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


@dataclass(frozen=True)
class Attempt:
    attempt_id: str
    scenario: str


ADVERSARIAL_ATTEMPTS = (
    Attempt("P5H-A1", "release_digest_substitution"),
    Attempt("P5H-A2", "scan_digest_substitution"),
    Attempt("P5H-A3", "privacy_policy_substitution"),
    Attempt("P5H-A4", "deployment_identity_substitution"),
    Attempt("P5H-A5", "image_digest_substitution"),
    Attempt("P5H-A6", "runtime_measurement_substitution"),
    Attempt("P5H-A7", "untrusted_orchestrator"),
    Attempt("P5H-A8", "sandbox_backend_substitution"),
    Attempt("P5H-A9", "privileged_environment"),
    Attempt("P5H-A10", "host_network_enabled"),
    Attempt("P5H-A11", "writable_root_filesystem"),
    Attempt("P5H-A12", "untrusted_attestor"),
    Attempt("P5H-A13", "forged_attestation_signature"),
    Attempt("P5H-A14", "expired_attestation"),
    Attempt("P5H-A15", "nonce_mismatch"),
    Attempt("P5H-A16", "degraded_verified_release"),
)
BENIGN_ATTEMPTS = (
    Attempt("P5H-B1", "trusted_primary_attestor"),
    Attempt("P5H-B2", "trusted_rotated_attestor"),
    Attempt("P5H-B3", "fresh_short_lived_attestation"),
)


def verified_package() -> VerifiedModelPackage:
    return VerifiedModelPackage(
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        package_publisher_id="aegis-release-publisher",
        component_artifact_ids=("model", "config", "tokenizer"),
        component_roles=("primary_model", "config", "tokenizer"),
        component_publishers=("aegis-model-publisher",) * 3,
    )


def verified_release() -> VerifiedRegistryRelease:
    return VerifiedRegistryRelease(
        registry_id=_REGISTRY_ID,
        channel=_CHANNEL,
        tag=_TAG,
        release_digest=_RELEASE_DIGEST,
        source="registry://aegis-model-registry/immutable/release",
        redirect_count=0,
        package=verified_package(),
    )


def verified_runtime() -> VerifiedRuntimePlan:
    return VerifiedRuntimePlan(
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        runtime_id=_RUNTIME_ID,
        backend=_BACKEND,
        component_artifact_ids=("model", "config", "tokenizer"),
        component_parsers=("safetensors_reader", "json_reader", "json_reader"),
        isolation_mode="deny-by-default-worker-v1",
        memory_limit_mb=2048,
        cpu_time_limit_seconds=30,
        thread_limit=4,
    )


def verified_scan() -> VerifiedModelScan:
    return VerifiedModelScan(
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        runtime_id=_RUNTIME_ID,
        profile_id="release-scan-v1",
        baseline_id="helpdesk-r6-baseline",
        scanner_id="aegis-static-probe-scanner",
        artifact_ids=("config", "model", "tokenizer"),
        probe_ids=("rare-token-trigger", "semantic-trigger"),
        evidence_sha256=_SCAN_DIGEST,
    )


def privacy_policy() -> PrivacyControlPolicy:
    return PrivacyControlPolicy(expected_scan_evidence_sha256=_SCAN_DIGEST)


def attestation_policy() -> DeploymentAttestationPolicy:
    return DeploymentAttestationPolicy(
        expected_release_digest=_RELEASE_DIGEST,
        expected_scan_evidence_sha256=_SCAN_DIGEST,
        expected_privacy_policy_sha256=privacy_policy_digest(privacy_policy()),
        trusted_attestors={
            "aegis-deploy-attestor-1": _public_bytes(_ATTESTOR_PRIVATE),
            "aegis-deploy-attestor-2": _public_bytes(_ROTATED_PRIVATE),
        },
        expected_image_digests={_ENVIRONMENT_ID: _IMAGE_DIGEST},
        expected_runtime_measurements={_ENVIRONMENT_ID: _RUNTIME_MEASUREMENT},
        allowed_orchestrators=frozenset({_ORCHESTRATOR}),
        allowed_sandbox_backends=frozenset({_BACKEND}),
        max_attestation_age_seconds=300,
    )


def safe_environment() -> DeploymentEnvironmentEvidence:
    return DeploymentEnvironmentEvidence(
        environment_id=_ENVIRONMENT_ID,
        orchestrator=_ORCHESTRATOR,
        image_digest=_IMAGE_DIGEST,
        runtime_measurement=_RUNTIME_MEASUREMENT,
        sandbox_backend=_BACKEND,
    )


def safe_request(
    *,
    nonce: str = "deploy-challenge-0001",
    privacy_digest: str | None = None,
) -> DeploymentAttestationRequest:
    return DeploymentAttestationRequest(
        deployment_id=_DEPLOYMENT_ID,
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        runtime_id=_RUNTIME_ID,
        registry_id=_REGISTRY_ID,
        channel=_CHANNEL,
        tag=_TAG,
        release_digest=_RELEASE_DIGEST,
        scan_evidence_sha256=_SCAN_DIGEST,
        privacy_policy_sha256=privacy_digest or privacy_policy_digest(privacy_policy()),
        environment_id=_ENVIRONMENT_ID,
        nonce=nonce,
        evaluated_at_epoch=_EVALUATED_AT,
    )


def safe_statement(
    *,
    attestor_id: str = "aegis-deploy-attestor-1",
    nonce: str = "deploy-challenge-0001",
    issued_at_epoch: int = _EVALUATED_AT - 30,
    expires_at_epoch: int = _EVALUATED_AT + 120,
    privacy_digest: str | None = None,
) -> DeploymentAttestationStatement:
    release = verified_release()
    runtime = verified_runtime()
    scan = verified_scan()
    return DeploymentAttestationStatement(
        deployment_id=_DEPLOYMENT_ID,
        package_id=_PACKAGE_ID,
        model_id=_MODEL_ID,
        revision=_REVISION,
        runtime_id=_RUNTIME_ID,
        registry_id=_REGISTRY_ID,
        channel=_CHANNEL,
        tag=_TAG,
        release_digest=_RELEASE_DIGEST,
        release_policy_version=release.policy_version,
        release_acquisition_mode=release.acquisition_mode,
        runtime_policy_version=runtime.policy_version,
        runtime_admission_mode=runtime.admission_mode,
        scan_evidence_sha256=_SCAN_DIGEST,
        scan_policy_version=scan.policy_version,
        scan_mode=scan.scan_mode,
        privacy_policy_sha256=privacy_digest or privacy_policy_digest(privacy_policy()),
        privacy_policy_version="model-privacy-extraction-membership-controls-v1",
        environment=safe_environment(),
        nonce=nonce,
        issued_at_epoch=issued_at_epoch,
        expires_at_epoch=expires_at_epoch,
        attestor_id=attestor_id,
    )


def sign_statement(
    statement: DeploymentAttestationStatement,
    *,
    private_key: Ed25519PrivateKey = _ATTESTOR_PRIVATE,
) -> SignedDeploymentAttestation:
    return SignedDeploymentAttestation(
        statement=statement,
        signature=private_key.sign(canonical_deployment_attestation_bytes(statement)),
    )


def safe_attestation(**kwargs: Any) -> SignedDeploymentAttestation:
    return sign_statement(safe_statement(**kwargs))


def attack_cases() -> tuple[dict[str, Any], ...]:
    safe_req = safe_request()
    safe_rel = verified_release()
    safe_run = verified_runtime()
    safe_scan = verified_scan()
    safe_privacy = privacy_policy()

    substituted_policy = replace(safe_privacy, max_output_tokens=1024)
    substituted_privacy_digest = privacy_policy_digest(substituted_policy)

    release_stmt = replace(safe_statement(), release_digest=_ALT_DIGEST)
    release_req = replace(safe_req, release_digest=_ALT_DIGEST)
    scan_stmt = replace(safe_statement(), scan_evidence_sha256=_ALT_DIGEST)
    scan_req = replace(safe_req, scan_evidence_sha256=_ALT_DIGEST)
    privacy_stmt = replace(safe_statement(), privacy_policy_sha256=substituted_privacy_digest)
    privacy_req = replace(safe_req, privacy_policy_sha256=substituted_privacy_digest)
    identity_stmt = replace(safe_statement(), model_id="attacker-model")
    identity_req = replace(safe_req, model_id="attacker-model")
    image_stmt = replace(
        safe_statement(),
        environment=replace(safe_environment(), image_digest=_ALT_DIGEST),
    )
    measurement_stmt = replace(
        safe_statement(),
        environment=replace(safe_environment(), runtime_measurement=_ALT_DIGEST),
    )
    orchestrator_stmt = replace(
        safe_statement(),
        environment=replace(safe_environment(), orchestrator="untrusted-compose"),
    )
    backend_stmt = replace(
        safe_statement(),
        environment=replace(safe_environment(), sandbox_backend="host-python"),
    )
    privileged_stmt = replace(
        safe_statement(),
        environment=replace(safe_environment(), privileged=True),
    )
    host_network_stmt = replace(
        safe_statement(),
        environment=replace(safe_environment(), host_network=True),
    )
    writable_stmt = replace(
        safe_statement(),
        environment=replace(safe_environment(), writable_root_filesystem=True),
    )
    untrusted_stmt = replace(safe_statement(), attestor_id="attacker-attestor")
    untrusted_attestation = sign_statement(untrusted_stmt, private_key=_ATTACKER_PRIVATE)
    forged = SignedDeploymentAttestation(statement=safe_statement(), signature=b"\x00" * 64)
    expired_stmt = safe_statement(
        issued_at_epoch=_EVALUATED_AT - 500,
        expires_at_epoch=_EVALUATED_AT - 200,
    )
    nonce_req = replace(safe_req, nonce="different-challenge")

    common = {
        "release": safe_rel,
        "runtime": safe_run,
        "scan": safe_scan,
        "privacy_policy": safe_privacy,
    }
    return (
        {"attempt": ADVERSARIAL_ATTEMPTS[0], "request": release_req, **common, "attestation": sign_statement(release_stmt)},
        {"attempt": ADVERSARIAL_ATTEMPTS[1], "request": scan_req, **common, "attestation": sign_statement(scan_stmt)},
        {"attempt": ADVERSARIAL_ATTEMPTS[2], "request": privacy_req, "release": safe_rel, "runtime": safe_run, "scan": safe_scan, "privacy_policy": substituted_policy, "attestation": sign_statement(privacy_stmt)},
        {"attempt": ADVERSARIAL_ATTEMPTS[3], "request": identity_req, **common, "attestation": sign_statement(identity_stmt)},
        {"attempt": ADVERSARIAL_ATTEMPTS[4], "request": safe_req, **common, "attestation": sign_statement(image_stmt)},
        {"attempt": ADVERSARIAL_ATTEMPTS[5], "request": safe_req, **common, "attestation": sign_statement(measurement_stmt)},
        {"attempt": ADVERSARIAL_ATTEMPTS[6], "request": safe_req, **common, "attestation": sign_statement(orchestrator_stmt)},
        {"attempt": ADVERSARIAL_ATTEMPTS[7], "request": safe_req, **common, "attestation": sign_statement(backend_stmt)},
        {"attempt": ADVERSARIAL_ATTEMPTS[8], "request": safe_req, **common, "attestation": sign_statement(privileged_stmt)},
        {"attempt": ADVERSARIAL_ATTEMPTS[9], "request": safe_req, **common, "attestation": sign_statement(host_network_stmt)},
        {"attempt": ADVERSARIAL_ATTEMPTS[10], "request": safe_req, **common, "attestation": sign_statement(writable_stmt)},
        {"attempt": ADVERSARIAL_ATTEMPTS[11], "request": safe_req, **common, "attestation": untrusted_attestation},
        {"attempt": ADVERSARIAL_ATTEMPTS[12], "request": safe_req, **common, "attestation": forged},
        {"attempt": ADVERSARIAL_ATTEMPTS[13], "request": safe_req, **common, "attestation": sign_statement(expired_stmt)},
        {"attempt": ADVERSARIAL_ATTEMPTS[14], "request": nonce_req, **common, "attestation": safe_attestation()},
        {"attempt": ADVERSARIAL_ATTEMPTS[15], "request": safe_req, "release": replace(safe_rel, cache_verified=False), "runtime": safe_run, "scan": safe_scan, "privacy_policy": safe_privacy, "attestation": safe_attestation()},
    )


def benign_cases() -> tuple[dict[str, Any], ...]:
    rotated_statement = safe_statement(
        attestor_id="aegis-deploy-attestor-2",
        nonce="deploy-challenge-0002",
    )
    return (
        {"attempt": BENIGN_ATTEMPTS[0], "request": safe_request(), "attestation": safe_attestation()},
        {"attempt": BENIGN_ATTEMPTS[1], "request": safe_request(nonce="deploy-challenge-0002"), "attestation": sign_statement(rotated_statement, private_key=_ROTATED_PRIVATE)},
        {"attempt": BENIGN_ATTEMPTS[2], "request": safe_request(nonce="deploy-challenge-0003"), "attestation": safe_attestation(nonce="deploy-challenge-0003", issued_at_epoch=_EVALUATED_AT - 5, expires_at_epoch=_EVALUATED_AT + 20)},
    )


def dataset_hash() -> str:
    payload = json.dumps(
        {
            "adversarial": [asdict(item) for item in ADVERSARIAL_ATTEMPTS],
            "benign": [asdict(item) for item in BENIGN_ATTEMPTS],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def fixture_hash() -> str:
    statement = safe_statement()
    attestation = safe_attestation()
    payload = (
        canonical_deployment_attestation_bytes(statement)
        + attestation.signature
        + canonical_privacy_policy_bytes(privacy_policy())
    )
    return hashlib.sha256(payload).hexdigest()


P5H_DATASET_SHA256 = dataset_hash()
P5H_FIXTURE_SHA256 = fixture_hash()


def build_report() -> dict[str, Any]:
    vulnerable = VulnerableDeploymentLauncher()
    hardened = DeploymentAttestationVerifier(attestation_policy())

    attack_rows: list[dict[str, Any]] = []
    vulnerable_successes = 0
    hardened_successes = 0
    for case in attack_cases():
        vulnerable.launch(attestation=case["attestation"])
        vulnerable_successes += 1
        reason = None
        try:
            hardened.verify(
                request=case["request"],
                release=case["release"],
                runtime=case["runtime"],
                scan=case["scan"],
                privacy_policy=case["privacy_policy"],
                attestation=case["attestation"],
            )
            hardened_successes += 1
        except DeploymentAttestationRejected as exc:
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
        try:
            handle = hardened.verify(
                request=case["request"],
                release=verified_release(),
                runtime=verified_runtime(),
                scan=verified_scan(),
                privacy_policy=privacy_policy(),
                attestation=case["attestation"],
            )
        except DeploymentAttestationRejected as exc:
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
                    "signature_verified": handle.attestor_signature_verified,
                    "environment_verified": handle.environment_policy_verified,
                    "hardware_backed_attestation": handle.hardware_backed_attestation,
                    "network_operations": handle.network_operations,
                }
            )

    return {
        "milestone": "P5-H",
        "policy_version": "deployment-provenance-attestation-v1",
        "dataset_sha256": P5H_DATASET_SHA256,
        "fixture_sha256": P5H_FIXTURE_SHA256,
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
            "real_remote_attestation": False,
            "hardware_root_of_trust": False,
            "transparency_service_calls": 0,
            "real_deployments_started": 0,
            "network_operations": 0,
            "synthetic_environment_measurements": True,
            "fixed_test_attestor_keys_only": True,
        },
        "claim_boundary": {
            "release_digest_binding": True,
            "runtime_policy_binding": True,
            "scan_evidence_binding": True,
            "privacy_policy_binding": True,
            "signed_environment_evidence": True,
            "least_privilege_environment_gate": True,
            "nonce_and_freshness_binding": True,
            "hardware_backed_attestation": False,
            "production_remote_attestation": False,
            "transparency_log_verification": False,
            "production_orchestrator_enforcement": False,
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
