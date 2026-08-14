from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.model_serving.abuse_response import (
    P5I_GENESIS_BATCH_SHA256,
    AbuseSignalType,
    AbuseTelemetryRejected,
    IncidentAction,
    ServingAbuseEvent,
    ServingAbusePolicy,
    ServingAbuseResponseEngine,
    ServingTelemetryBatch,
    SignedServingTelemetryBatch,
    canonical_serving_telemetry_batch_bytes,
    serving_telemetry_batch_digest,
)
from aegis.model_supply_chain.deployment_attestation import VerifiedDeploymentAttestation
from aegis.vulnerable.model_serving_abuse import VulnerableServingAbuseResponder


NOW = 1_800_000_000
DEPLOYMENT_ID = "helpdesk-prod-blue"
PACKAGE_ID = "helpdesk-runtime-package"
MODEL_ID = "helpdesk-model"
REVISION = "r4"
RUNTIME_ID = "helpdesk-inference"
ATTESTATION_SHA256 = hashlib.sha256(b"p5i-attested-deployment").hexdigest()
COLLECTOR_ID = "aegis-serving-collector"


def _private_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("utf-8")).digest())


COLLECTOR_PRIVATE_KEY = _private_key("aegis-p5i-collector")
ROGUE_PRIVATE_KEY = _private_key("aegis-p5i-rogue")


def _public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes_raw()


def verified_attestation() -> VerifiedDeploymentAttestation:
    return VerifiedDeploymentAttestation(
        deployment_id=DEPLOYMENT_ID,
        package_id=PACKAGE_ID,
        model_id=MODEL_ID,
        revision=REVISION,
        runtime_id=RUNTIME_ID,
        registry_id="aegis-registry",
        channel="stable",
        tag="prod",
        release_digest=hashlib.sha256(b"release").hexdigest(),
        scan_evidence_sha256=hashlib.sha256(b"scan").hexdigest(),
        privacy_policy_sha256=hashlib.sha256(b"privacy").hexdigest(),
        environment_id="prod-us-east-1",
        image_digest=hashlib.sha256(b"image").hexdigest(),
        runtime_measurement=hashlib.sha256(b"runtime-measurement").hexdigest(),
        sandbox_backend="sandboxed_tensor_runtime",
        attestor_id="aegis-deployment-attestor",
        nonce="nonce-p5h",
        issued_at_epoch=NOW - 30,
        expires_at_epoch=NOW + 270,
        statement_sha256=ATTESTATION_SHA256,
    )


def abuse_policy() -> ServingAbusePolicy:
    return ServingAbusePolicy(
        expected_attestation_statement_sha256=ATTESTATION_SHA256,
        trusted_collectors={COLLECTOR_ID: _public_bytes(COLLECTOR_PRIVATE_KEY)},
    )


def event(
    event_id: str,
    sequence: int,
    signal: AbuseSignalType = AbuseSignalType.NORMAL_QUERY,
    *,
    principal: str = "alice",
    session: str = "session-a",
    fingerprint: str | None = None,
    source: str = "privacy_gateway",
    occurrences: int = 1,
    score: int = 0,
    observed_at: int = NOW - 10,
) -> ServingAbuseEvent:
    return ServingAbuseEvent(
        event_id=event_id,
        sequence=sequence,
        observed_at_epoch=observed_at,
        principal_id=principal,
        session_id=session,
        query_fingerprint=fingerprint or f"fingerprint-{event_id}",
        signal_type=signal,
        source=source,
        occurrences=occurrences,
        observed_score_milli=score,
    )


def batch(
    batch_id: str,
    events: tuple[ServingAbuseEvent, ...],
    *,
    previous: str = P5I_GENESIS_BATCH_SHA256,
    collector_id: str = COLLECTOR_ID,
    deployment_id: str = DEPLOYMENT_ID,
    attestation_sha256: str = ATTESTATION_SHA256,
    complete: bool = True,
    window_start: int = NOW - 30,
    window_end: int = NOW - 5,
    first_sequence: int | None = None,
    last_sequence: int | None = None,
) -> ServingTelemetryBatch:
    first = first_sequence if first_sequence is not None else events[0].sequence
    last = last_sequence if last_sequence is not None else events[-1].sequence
    return ServingTelemetryBatch(
        deployment_id=deployment_id,
        package_id=PACKAGE_ID,
        model_id=MODEL_ID,
        revision=REVISION,
        runtime_id=RUNTIME_ID,
        attestation_statement_sha256=attestation_sha256,
        collector_id=collector_id,
        batch_id=batch_id,
        first_sequence=first,
        last_sequence=last,
        previous_batch_sha256=previous,
        window_start_epoch=window_start,
        window_end_epoch=window_end,
        complete=complete,
        events=events,
    )


def signed(
    value: ServingTelemetryBatch,
    *,
    key: Ed25519PrivateKey = COLLECTOR_PRIVATE_KEY,
) -> SignedServingTelemetryBatch:
    return SignedServingTelemetryBatch(
        batch=value,
        signature=key.sign(canonical_serving_telemetry_batch_bytes(value)),
    )


def _case(
    case_id: str,
    name: str,
    signed_batch: SignedServingTelemetryBatch,
    *,
    attestation: VerifiedDeploymentAttestation | None = None,
    prefill: tuple[SignedServingTelemetryBatch, ...] = (),
    minimum_action: IncidentAction | None = None,
    evaluated_at: int = NOW,
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "name": name,
        "signed_batch": signed_batch,
        "attestation": attestation or verified_attestation(),
        "prefill": prefill,
        "minimum_action": minimum_action,
        "evaluated_at": evaluated_at,
    }


_ACTION_ORDER = {
    IncidentAction.OBSERVE: 0,
    IncidentAction.THROTTLE: 1,
    IncidentAction.QUARANTINE: 2,
    IncidentAction.REVOKE_DEPLOYMENT: 3,
}


def attack_cases() -> tuple[dict[str, object], ...]:
    safe_one = signed(batch("prefill-1", (event("e-prefill", 1),)))
    replay = safe_one

    return (
        _case(
            "P5I-A1",
            "degraded deployment attestation",
            signed(batch("a1", (event("a1e", 1),))),
            attestation=replace(verified_attestation(), attestor_signature_verified=False),
        ),
        _case(
            "P5I-A2",
            "untrusted collector",
            signed(
                batch("a2", (event("a2e", 1),), collector_id="rogue-collector"),
                key=ROGUE_PRIVATE_KEY,
            ),
        ),
        _case(
            "P5I-A3",
            "signature substitution",
            SignedServingTelemetryBatch(
                batch=batch("a3", (event("a3e", 1),)),
                signature=b"\x00" * 64,
            ),
        ),
        _case(
            "P5I-A4",
            "deployment identity substitution",
            signed(batch("a4", (event("a4e", 1),), deployment_id="other-deployment")),
        ),
        _case(
            "P5I-A5",
            "attestation digest substitution",
            signed(
                batch(
                    "a5",
                    (event("a5e", 1),),
                    attestation_sha256=hashlib.sha256(b"other-attestation").hexdigest(),
                )
            ),
        ),
        _case(
            "P5I-A6",
            "incomplete telemetry window",
            signed(batch("a6", (event("a6e", 1),), complete=False)),
        ),
        _case(
            "P5I-A7",
            "stale telemetry batch",
            signed(
                batch(
                    "a7",
                    (event("a7e", 1, observed_at=NOW - 1000),),
                    window_start=NOW - 1100,
                    window_end=NOW - 1000,
                )
            ),
        ),
        _case(
            "P5I-A8",
            "future telemetry batch",
            signed(
                batch(
                    "a8",
                    (event("a8e", 1, observed_at=NOW + 100),),
                    window_start=NOW + 90,
                    window_end=NOW + 100,
                )
            ),
        ),
        _case(
            "P5I-A9",
            "untrusted telemetry source",
            signed(batch("a9", (event("a9e", 1, source="client-supplied"),))),
        ),
        _case(
            "P5I-A10",
            "duplicate event identifiers",
            signed(
                batch(
                    "a10",
                    (
                        event("dup", 1),
                        event("dup", 2, fingerprint="fingerprint-dup-2"),
                    ),
                )
            ),
        ),
        _case(
            "P5I-A11",
            "telemetry batch replay",
            replay,
            prefill=(replay,),
        ),
        _case(
            "P5I-A12",
            "sequence gap",
            signed(
                batch(
                    "a12",
                    (event("a12e", 2),),
                    first_sequence=2,
                    last_sequence=2,
                )
            ),
        ),
        _case(
            "P5I-A13",
            "telemetry chain fork",
            signed(
                batch(
                    "a13",
                    (event("a13e", 2),),
                    previous=P5I_GENESIS_BATCH_SHA256,
                )
            ),
            prefill=(safe_one,),
        ),
        _case(
            "P5I-A14",
            "privacy budget exhaustion burst",
            signed(
                batch(
                    "a14",
                    (
                        event(
                            "a14e",
                            1,
                            AbuseSignalType.SESSION_BUDGET_EXHAUSTION,
                            occurrences=2,
                        ),
                    ),
                )
            ),
            minimum_action=IncidentAction.THROTTLE,
        ),
        _case(
            "P5I-A15",
            "repeated sensitive-channel probing",
            signed(
                batch(
                    "a15",
                    (
                        event(
                            "a15e1",
                            1,
                            AbuseSignalType.SENSITIVE_CHANNEL_PROBE,
                            occurrences=2,
                        ),
                        event(
                            "a15e2",
                            2,
                            AbuseSignalType.REPEATED_QUERY_PROBE,
                            occurrences=2,
                        ),
                    ),
                )
            ),
            minimum_action=IncidentAction.QUARANTINE,
        ),
        _case(
            "P5I-A16",
            "distributed membership-inference probing",
            signed(
                batch(
                    "a16",
                    (
                        event(
                            "a16e1",
                            1,
                            AbuseSignalType.MEMBERSHIP_INFERENCE_SIGNAL,
                            principal="alice",
                            score=160,
                        ),
                        event(
                            "a16e2",
                            2,
                            AbuseSignalType.MEMBERSHIP_INFERENCE_SIGNAL,
                            principal="bob",
                            session="session-b",
                            score=170,
                        ),
                        event(
                            "a16e3",
                            3,
                            AbuseSignalType.MEMBERSHIP_INFERENCE_SIGNAL,
                            principal="carol",
                            session="session-c",
                            score=180,
                        ),
                    ),
                )
            ),
            minimum_action=IncidentAction.QUARANTINE,
        ),
        _case(
            "P5I-A17",
            "training canary leakage signal",
            signed(batch("a17", (event("a17e", 1, AbuseSignalType.CANARY_LEAKAGE),))),
            minimum_action=IncidentAction.REVOKE_DEPLOYMENT,
        ),
    )


def benign_cases() -> tuple[dict[str, object], ...]:
    return (
        _case(
            "P5I-B1",
            "single normal query",
            signed(batch("b1", (event("b1e", 1),))),
            minimum_action=IncidentAction.OBSERVE,
        ),
        _case(
            "P5I-B2",
            "normal multi-principal traffic",
            signed(
                batch(
                    "b2",
                    (
                        event("b2e1", 1, principal="alice"),
                        event("b2e2", 2, principal="bob", session="session-b"),
                    ),
                )
            ),
            minimum_action=IncidentAction.OBSERVE,
        ),
        _case(
            "P5I-B3",
            "isolated low-risk output detail probe",
            signed(batch("b3", (event("b3e", 1, AbuseSignalType.OUTPUT_DETAIL_PROBE),))),
            minimum_action=IncidentAction.OBSERVE,
        ),
    )


def _hardened_blocks(case: dict[str, object]) -> bool:
    engine = ServingAbuseResponseEngine(abuse_policy())
    attestation = case["attestation"]
    for index, prefill in enumerate(case["prefill"]):
        engine.evaluate(
            incident_id=f"prefill-{case['case_id']}-{index}",
            attestation=attestation,
            signed_batch=prefill,
            evaluated_at_epoch=NOW,
        )
    try:
        decision = engine.evaluate(
            incident_id=f"incident-{case['case_id']}",
            attestation=attestation,
            signed_batch=case["signed_batch"],
            evaluated_at_epoch=case["evaluated_at"],
        )
    except AbuseTelemetryRejected:
        return True

    minimum = case["minimum_action"]
    if minimum is None:
        return False
    return _ACTION_ORDER[decision.action] >= _ACTION_ORDER[minimum]


def _vulnerable_attack_succeeds(case: dict[str, object]) -> bool:
    decision = VulnerableServingAbuseResponder().evaluate(
        signed_batch=case["signed_batch"],
        claimed_action=IncidentAction.OBSERVE,
    )
    minimum = case["minimum_action"]
    if minimum is None:
        return True
    return _ACTION_ORDER[decision.action] < _ACTION_ORDER[minimum]


def _benign_passes(case: dict[str, object]) -> bool:
    decision = ServingAbuseResponseEngine(abuse_policy()).evaluate(
        incident_id=f"incident-{case['case_id']}",
        attestation=case["attestation"],
        signed_batch=case["signed_batch"],
        evaluated_at_epoch=case["evaluated_at"],
    )
    return decision.action is IncidentAction.OBSERVE


def _dataset_hash() -> str:
    rows = [
        {
            "case_id": case["case_id"],
            "name": case["name"],
            "minimum_action": (
                case["minimum_action"].value if case["minimum_action"] is not None else "reject"
            ),
        }
        for case in attack_cases()
    ] + [
        {
            "case_id": case["case_id"],
            "name": case["name"],
            "minimum_action": case["minimum_action"].value,
        }
        for case in benign_cases()
    ]
    return hashlib.sha256(
        json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _fixture_hash() -> str:
    fixture = {
        "attestation": asdict(verified_attestation()),
        "policy": {
            "expected_attestation_statement_sha256": abuse_policy().expected_attestation_statement_sha256,
            "allowed_sources": sorted(abuse_policy().allowed_sources),
            "throttle_points": abuse_policy().throttle_points,
            "quarantine_points": abuse_policy().quarantine_points,
            "revoke_points": abuse_policy().revoke_points,
            "signal_weights": sorted(
                (signal.value, weight) for signal, weight in abuse_policy().signal_weights.items()
            ),
        },
    }
    return hashlib.sha256(
        json.dumps(fixture, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


P5I_DATASET_SHA256 = _dataset_hash()
P5I_FIXTURE_SHA256 = _fixture_hash()


def build_report() -> dict[str, object]:
    attacks = attack_cases()
    benign = benign_cases()
    vulnerable_successes = sum(_vulnerable_attack_succeeds(case) for case in attacks)
    hardened_successes = sum(not _hardened_blocks(case) for case in attacks)
    benign_failures = sum(not _benign_passes(case) for case in benign)
    benign_successes = len(benign) - benign_failures
    return {
        "metrics": {
            "adversarial_cases": len(attacks),
            "vulnerable_asr": f"{vulnerable_successes}/{len(attacks)}",
            "hardened_asr": f"{hardened_successes}/{len(attacks)}",
            "hardened_fpr": f"{benign_failures}/{len(benign)}",
            "safe_task_rate": f"{benign_successes}/{len(benign)}",
        },
        "dataset_sha256": P5I_DATASET_SHA256,
        "fixture_sha256": P5I_FIXTURE_SHA256,
        "claim_boundary": {
            "signed_telemetry_integrity": True,
            "deployment_identity_binding": True,
            "anti_replay_and_chain_continuity": True,
            "deterministic_response_policy": True,
            "real_siem_or_soar": False,
            "distributed_quarantine_enforcement": False,
            "trusted_collector_completeness_proof": False,
            "production_behavioral_detection": False,
        },
    }


def main() -> None:
    print(json.dumps(build_report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
