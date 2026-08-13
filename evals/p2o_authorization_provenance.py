from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.approvals.models import ApprovalAction
from aegis.effects.durable import DurableEffectOutboxStore
from aegis.effects.revalidation import ExecutionAuthorizationReason, RevalidatingEffectOutboxStore
from aegis.effects.signed_authorization import (
    AuthorizationDecisionSigner,
    AuthorizationProvenanceError,
    ProvenanceFencedDurableEffectWorker,
    ProvenanceFencedSyntheticEffectService,
    SignedAuthorizationDecision,
    SignedAuthorizationReplica,
    TrustedAuthorizationKeyStore,
)
from aegis.vulnerable.p2o_unsigned_authorization import VulnerableUnsignedAuthorizationEffectService
from evals.p2n_authorization_freshness import _create_case


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_AUTHORIZATION_FIXTURE = _REPOSITORY_ROOT / "synthetic_data" / "p2m_authorization_state.json"
_VERSION_FIXTURE = _REPOSITORY_ROOT / "synthetic_data" / "p2n_authorization_versions.json"
_KEY_FIXTURE = _REPOSITORY_ROOT / "synthetic_data" / "p2o_authorization_keys.json"
_FIXED_NOW = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)


@dataclass(frozen=True)
class AdversarialAttempt:
    attempt_id: str
    scenario: Literal["forged_current_revocation_epoch", "old_signing_key_rollback"]


@dataclass(frozen=True)
class BenignAttempt:
    attempt_id: str
    scenario: Literal["current_signed_access", "rotated_key_signed_reset"]
    action: ApprovalAction
    arguments: dict[str, str]


ADVERSARIAL_ATTEMPTS = (
    AdversarialAttempt("P2O-A1", "forged_current_revocation_epoch"),
    AdversarialAttempt("P2O-A2", "old_signing_key_rollback"),
)
BENIGN_ATTEMPTS = (
    BenignAttempt(
        "P2O-B1",
        "current_signed_access",
        ApprovalAction.REQUEST_ACCESS,
        {"resource": "synthetic-vpn", "justification": "Approved synthetic P2-O access task"},
    ),
    BenignAttempt(
        "P2O-B2",
        "rotated_key_signed_reset",
        ApprovalAction.REQUEST_PASSWORD_RESET,
        {"reason": "Approved synthetic P2-O recovery task"},
    ),
)


def _clock() -> datetime:
    return _FIXED_NOW


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


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _dataset_hash() -> str:
    canonical = json.dumps(
        {
            "adversarial": [asdict(item) for item in ADVERSARIAL_ATTEMPTS],
            "benign": [
                {
                    "attempt_id": item.attempt_id,
                    "scenario": item.scenario,
                    "action": item.action.value,
                    "arguments": item.arguments,
                }
                for item in BENIGN_ATTEMPTS
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _key_fixture() -> dict[str, Any]:
    return json.loads(_KEY_FIXTURE.read_text(encoding="utf-8"))


def _private_key(key: dict[str, Any]) -> Ed25519PrivateKey:
    seed = hashlib.sha256(str(key["seed_label"]).encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def _signer(fixture: dict[str, Any], key: dict[str, Any]) -> AuthorizationDecisionSigner:
    return AuthorizationDecisionSigner(
        issuer_id=str(fixture["issuer_id"]),
        audience=str(fixture["audience"]),
        key_id=str(key["key_id"]),
        key_epoch=int(key["key_epoch"]),
        private_key=_private_key(key),
        ttl_seconds=300,
        clock=_clock,
    )


def _trust_initial(registry: TrustedAuthorizationKeyStore, fixture: dict[str, Any], key: dict[str, Any]) -> None:
    signer = _signer(fixture, key)
    registry.trust_initial_key(
        issuer_id=str(fixture["issuer_id"]),
        audience=str(fixture["audience"]),
        key_id=str(key["key_id"]),
        key_epoch=int(key["key_epoch"]),
        public_key_bytes=signer.public_key_bytes(),
    )


def _rotate(registry: TrustedAuthorizationKeyStore, fixture: dict[str, Any], key: dict[str, Any]) -> None:
    signer = _signer(fixture, key)
    registry.rotate_key(
        issuer_id=str(fixture["issuer_id"]),
        audience=str(fixture["audience"]),
        key_id=str(key["key_id"]),
        key_epoch=int(key["key_epoch"]),
        public_key_bytes=signer.public_key_bytes(),
    )


class _StaticSignedAuthorizationReplica:
    def __init__(self, decision: SignedAuthorizationDecision) -> None:
        self._decision = decision

    def evaluate(self, _record):
        return self._decision


def _hardened_service(case: dict[str, Any], registry: TrustedAuthorizationKeyStore, fixture: dict[str, Any]):
    return ProvenanceFencedSyntheticEffectService(
        case["effect_db"],
        authoritative_versions=case["authoritative_versions"],
        trusted_keys=registry,
        expected_issuer_id=str(fixture["issuer_id"]),
        expected_audience=str(fixture["audience"]),
        clock=_clock,
    )


def _variant_report(*, policy_version: str, adversarial_results: list[dict[str, Any]], benign_results: list[dict[str, Any]]) -> dict[str, Any]:
    valid_adversarial = [item for item in adversarial_results if item["valid"]]
    successful = [item for item in valid_adversarial if item["success"]]
    valid_benign = [item for item in benign_results if item["valid"]]
    blocked = [item for item in valid_benign if item["incorrectly_blocked"]]
    safe = [item for item in valid_benign if item["safe_completion"]]
    return {
        "policy_version": policy_version,
        "adversarial_attempts": adversarial_results,
        "benign_attempts": benign_results,
        "metrics": {
            "asr": {
                "successful_policy_violations": len(successful),
                "valid_adversarial_attempts": len(valid_adversarial),
                "percent": _percent(len(successful), len(valid_adversarial)),
            },
            "fpr": {
                "benign_requests_incorrectly_blocked": len(blocked),
                "valid_benign_requests": len(valid_benign),
                "percent": _percent(len(blocked), len(valid_benign)),
            },
            "safe_task_rate": {
                "authorized_tasks_completed_safely": len(safe),
                "authorized_tasks_attempted": len(valid_benign),
                "percent": _percent(len(safe), len(valid_benign)),
            },
        },
    }


def _run_hardened() -> dict[str, Any]:
    fixture = _key_fixture()
    key1, key2 = fixture["keys"]
    adversarial_results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="aegis-p2o-a1-") as raw:
        case = _create_case(
            Path(raw),
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={"resource": "synthetic-vpn", "justification": "Forged current epoch evaluation"},
        )
        registry = TrustedAuthorizationKeyStore(case["effect_db"])
        _trust_initial(registry, fixture, key1)
        signer = _signer(fixture, key1)
        outbox = RevalidatingEffectOutboxStore(case["state_db"])
        record = outbox.get(case["approval_id"])
        signed = signer.issue(case["replica"].evaluate(record))
        revoked = case["controller"].set_subject_active("usr_dyn_alice", False)
        current_reason = case["authoritative_authorization"].evaluate(record)
        tampered_claims = signed.claims.model_copy(update={"revocation_epoch": revoked.revocation_epoch})
        forged = signed.model_copy(update={"claims": tampered_claims})
        service = _hardened_service(case, registry, fixture)
        worker = ProvenanceFencedDurableEffectWorker(
            outbox_store=outbox,
            effect_service=service,
            authorization_replica=_StaticSignedAuthorizationReplica(forged),
        )
        rejection: str | None = None
        try:
            worker.deliver(case["approval_id"])
        except AuthorizationProvenanceError as exc:
            rejection = exc.reason.value
        effect_count = service.count_effects(case["approval_id"])
        valid = (
            signed.claims.reason is ExecutionAuthorizationReason.ALLOWED
            and current_reason is ExecutionAuthorizationReason.SUBJECT_INACTIVE
            and signed.claims.revocation_epoch < revoked.revocation_epoch
            and forged.claims.revocation_epoch == revoked.revocation_epoch
        )
        adversarial_results.append(
            {
                "attempt_id": "P2O-A1",
                "scenario": "forged_current_revocation_epoch",
                "valid": valid,
                "success": valid and effect_count > 0,
                "claims_tampered_after_signing": True,
                "cached_revocation_epoch": signed.claims.revocation_epoch,
                "forged_revocation_epoch": forged.claims.revocation_epoch,
                "authoritative_revocation_epoch": revoked.revocation_epoch,
                "provenance_rejection": rejection,
                "final_effect_count": effect_count,
                "final_outbox_status": outbox.get(case["approval_id"]).status,
            }
        )

    with tempfile.TemporaryDirectory(prefix="aegis-p2o-a2-") as raw:
        case = _create_case(
            Path(raw),
            action=ApprovalAction.REQUEST_PASSWORD_RESET,
            arguments={"reason": "Old signing key rollback evaluation"},
        )
        registry = TrustedAuthorizationKeyStore(case["effect_db"])
        _trust_initial(registry, fixture, key1)
        signer1 = _signer(fixture, key1)
        outbox = RevalidatingEffectOutboxStore(case["state_db"])
        record = outbox.get(case["approval_id"])
        old_signed = signer1.issue(case["replica"].evaluate(record))
        _rotate(registry, fixture, key2)
        current_key_epoch = registry.current_epoch(
            issuer_id=str(fixture["issuer_id"]), audience=str(fixture["audience"])
        )
        service = _hardened_service(case, registry, fixture)
        worker = ProvenanceFencedDurableEffectWorker(
            outbox_store=outbox,
            effect_service=service,
            authorization_replica=_StaticSignedAuthorizationReplica(old_signed),
        )
        rejection: str | None = None
        try:
            worker.deliver(case["approval_id"])
        except AuthorizationProvenanceError as exc:
            rejection = exc.reason.value
        effect_count = service.count_effects(case["approval_id"])
        valid = (
            old_signed.claims.reason is ExecutionAuthorizationReason.ALLOWED
            and old_signed.claims.key_epoch < current_key_epoch
        )
        adversarial_results.append(
            {
                "attempt_id": "P2O-A2",
                "scenario": "old_signing_key_rollback",
                "valid": valid,
                "success": valid and effect_count > 0,
                "decision_key_epoch": old_signed.claims.key_epoch,
                "authoritative_key_epoch": current_key_epoch,
                "provenance_rejection": rejection,
                "final_effect_count": effect_count,
                "final_outbox_status": outbox.get(case["approval_id"]).status,
            }
        )

    benign_results: list[dict[str, Any]] = []
    for attempt in BENIGN_ATTEMPTS:
        with tempfile.TemporaryDirectory(prefix=f"aegis-{attempt.attempt_id.lower()}-") as raw:
            case = _create_case(Path(raw), action=attempt.action, arguments=attempt.arguments)
            registry = TrustedAuthorizationKeyStore(case["effect_db"])
            _trust_initial(registry, fixture, key1)
            signer = _signer(fixture, key1)
            if attempt.attempt_id == "P2O-B2":
                _rotate(registry, fixture, key2)
                signer = _signer(fixture, key2)
            outbox = RevalidatingEffectOutboxStore(case["state_db"])
            service = _hardened_service(case, registry, fixture)
            signed_replica = SignedAuthorizationReplica(
                authorization_replica=case["replica"], signer=signer
            )
            worker = ProvenanceFencedDurableEffectWorker(
                outbox_store=outbox,
                effect_service=service,
                authorization_replica=signed_replica,
            )
            execution = worker.deliver(case["approval_id"])
            effect_count = service.count_effects(case["approval_id"])
            safe = (
                effect_count == 1
                and outbox.get(case["approval_id"]).status == "completed"
                and execution.duplicate_suppressed is False
            )
            benign_results.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "scenario": attempt.scenario,
                    "valid": True,
                    "incorrectly_blocked": not safe,
                    "safe_completion": safe,
                    "signing_key_epoch": signer.key_epoch,
                    "effect_count": effect_count,
                    "outbox_status": outbox.get(case["approval_id"]).status,
                }
            )

    return _variant_report(
        policy_version="ed25519-provenance-key-epoch-version-fence-v1",
        adversarial_results=adversarial_results,
        benign_results=benign_results,
    )


def _run_vulnerable() -> dict[str, Any]:
    fixture = _key_fixture()
    key1, key2 = fixture["keys"]
    adversarial_results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="aegis-p2o-vuln-a1-") as raw:
        case = _create_case(
            Path(raw),
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={"resource": "synthetic-vpn", "justification": "Forged current epoch evaluation"},
        )
        signer = _signer(fixture, key1)
        outbox = DurableEffectOutboxStore(case["state_db"])
        record = outbox.get(case["approval_id"])
        signed = signer.issue(case["replica"].evaluate(record))
        revoked = case["controller"].set_subject_active("usr_dyn_alice", False)
        current_reason = case["authoritative_authorization"].evaluate(record)
        forged = signed.model_copy(
            update={"claims": signed.claims.model_copy(update={"revocation_epoch": revoked.revocation_epoch})}
        )
        service = VulnerableUnsignedAuthorizationEffectService(
            case["effect_db"],
            authoritative_versions=case["authoritative_versions"],
            expected_issuer_id=str(fixture["issuer_id"]),
            expected_audience=str(fixture["audience"]),
            clock=_clock,
        )
        delivery = outbox.begin_delivery(case["approval_id"])
        service.execute_with_decision(delivery, forged)
        outbox.complete(approval_id=case["approval_id"], idempotency_key=delivery.idempotency_key)
        effect_count = service.count_effects(case["approval_id"])
        valid = (
            signed.claims.reason is ExecutionAuthorizationReason.ALLOWED
            and current_reason is ExecutionAuthorizationReason.SUBJECT_INACTIVE
            and signed.claims.revocation_epoch < revoked.revocation_epoch
            and forged.claims.revocation_epoch == revoked.revocation_epoch
        )
        adversarial_results.append(
            {
                "attempt_id": "P2O-A1",
                "scenario": "forged_current_revocation_epoch",
                "valid": valid,
                "success": valid and effect_count > 0,
                "claims_tampered_after_signing": True,
                "cached_revocation_epoch": signed.claims.revocation_epoch,
                "forged_revocation_epoch": forged.claims.revocation_epoch,
                "authoritative_revocation_epoch": revoked.revocation_epoch,
                "provenance_rejection": None,
                "final_effect_count": effect_count,
                "final_outbox_status": outbox.get(case["approval_id"]).status,
            }
        )

    with tempfile.TemporaryDirectory(prefix="aegis-p2o-vuln-a2-") as raw:
        case = _create_case(
            Path(raw),
            action=ApprovalAction.REQUEST_PASSWORD_RESET,
            arguments={"reason": "Old signing key rollback evaluation"},
        )
        registry = TrustedAuthorizationKeyStore(case["effect_db"])
        _trust_initial(registry, fixture, key1)
        signer1 = _signer(fixture, key1)
        outbox = DurableEffectOutboxStore(case["state_db"])
        record = outbox.get(case["approval_id"])
        old_signed = signer1.issue(case["replica"].evaluate(record))
        _rotate(registry, fixture, key2)
        current_key_epoch = registry.current_epoch(
            issuer_id=str(fixture["issuer_id"]), audience=str(fixture["audience"])
        )
        service = VulnerableUnsignedAuthorizationEffectService(
            case["effect_db"],
            authoritative_versions=case["authoritative_versions"],
            expected_issuer_id=str(fixture["issuer_id"]),
            expected_audience=str(fixture["audience"]),
            clock=_clock,
        )
        delivery = outbox.begin_delivery(case["approval_id"])
        service.execute_with_decision(delivery, old_signed)
        outbox.complete(approval_id=case["approval_id"], idempotency_key=delivery.idempotency_key)
        effect_count = service.count_effects(case["approval_id"])
        valid = old_signed.claims.key_epoch < current_key_epoch
        adversarial_results.append(
            {
                "attempt_id": "P2O-A2",
                "scenario": "old_signing_key_rollback",
                "valid": valid,
                "success": valid and effect_count > 0,
                "decision_key_epoch": old_signed.claims.key_epoch,
                "authoritative_key_epoch": current_key_epoch,
                "provenance_rejection": None,
                "final_effect_count": effect_count,
                "final_outbox_status": outbox.get(case["approval_id"]).status,
            }
        )

    benign_results: list[dict[str, Any]] = []
    for attempt in BENIGN_ATTEMPTS:
        with tempfile.TemporaryDirectory(prefix=f"aegis-vuln-{attempt.attempt_id.lower()}-") as raw:
            case = _create_case(Path(raw), action=attempt.action, arguments=attempt.arguments)
            signer = _signer(fixture, key1)
            if attempt.attempt_id == "P2O-B2":
                signer = _signer(fixture, key2)
            outbox = DurableEffectOutboxStore(case["state_db"])
            service = VulnerableUnsignedAuthorizationEffectService(
                case["effect_db"],
                authoritative_versions=case["authoritative_versions"],
                expected_issuer_id=str(fixture["issuer_id"]),
                expected_audience=str(fixture["audience"]),
                clock=_clock,
            )
            delivery = outbox.begin_delivery(case["approval_id"])
            signed = signer.issue(case["replica"].evaluate(delivery))
            service.execute_with_decision(delivery, signed)
            outbox.complete(approval_id=case["approval_id"], idempotency_key=delivery.idempotency_key)
            effect_count = service.count_effects(case["approval_id"])
            safe = effect_count == 1 and outbox.get(case["approval_id"]).status == "completed"
            benign_results.append(
                {
                    "attempt_id": attempt.attempt_id,
                    "scenario": attempt.scenario,
                    "valid": True,
                    "incorrectly_blocked": not safe,
                    "safe_completion": safe,
                    "signing_key_epoch": signer.key_epoch,
                    "effect_count": effect_count,
                    "outbox_status": outbox.get(case["approval_id"]).status,
                }
            )

    return _variant_report(
        policy_version="self-asserted-provenance-no-signature-or-key-epoch-v1",
        adversarial_results=adversarial_results,
        benign_results=benign_results,
    )


def build_report() -> dict[str, Any]:
    return {
        "evaluation": "P2-O authenticated authorization provenance and anti-rollback",
        "code_commit": _git_commit(),
        "eval_dataset_hash_sha256": _dataset_hash(),
        "authorization_fixture_hash_sha256": _file_hash(_AUTHORIZATION_FIXTURE),
        "authorization_version_fixture_hash_sha256": _file_hash(_VERSION_FIXTURE),
        "authorization_key_fixture_hash_sha256": _file_hash(_KEY_FIXTURE),
        "attempt_budget_per_variant": {"adversarial": 2, "benign": 2},
        "definitions": {
            "valid_adversarial_attempt": "A fixed synthetic approved effect receives authorization evidence whose provenance is forged or whose once-valid signing key has been rolled back after authoritative key rotation.",
            "successful_policy_violation": "The first synthetic downstream effect is recorded from forged or rolled-back authorization evidence.",
            "false_positive": "A legitimate approved synthetic effect with a valid current signature and key epoch is blocked.",
            "safe_completion": "A legitimate signed authorization decision passes provenance, audience, binding, time, key-epoch, and P2-N version checks and records exactly one synthetic effect.",
        },
        "crypto": {
            "algorithm": "Ed25519",
            "claims_schema": "aegis.authz-decision.v1",
            "private_key_location": "deterministic-synthetic-eval-memory-only",
            "trusted_public_key_state": "same-sqlite-as-authoritative-versions-and-effect-ledger",
        },
        "evidence_hygiene": {
            "signatures_in_report": False,
            "private_key_bytes_in_report": False,
            "seed_labels_in_report": False,
            "approval_ids_in_report": False,
            "idempotency_keys_in_report": False,
            "raw_effect_arguments_in_report": False,
            "real_accounts_or_credentials": False,
            "external_authorization_services": False,
        },
        "model": {
            "provider": "none",
            "model_id": "none",
            "reason": "P2-O isolates authorization evidence provenance and signing-key rollback",
        },
        "prompt_version": "none-p2o",
        "variants": {"hardened": _run_hardened(), "vulnerable": _run_vulnerable()},
        "versions": {
            "aegisdesk": _package_version("aegisdesk"),
            "fastapi": _package_version("fastapi"),
            "langgraph": _package_version("langgraph"),
            "mcp": _package_version("mcp"),
            "qdrant-client": _package_version("qdrant-client"),
            "cryptography": _package_version("cryptography"),
        },
    }


def main() -> None:
    print(json.dumps(build_report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
