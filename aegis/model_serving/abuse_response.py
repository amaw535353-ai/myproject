from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aegis.model_supply_chain.deployment_attestation import VerifiedDeploymentAttestation


P5I_ABUSE_POLICY_VERSION = "model-serving-abuse-incident-response-v1"
P5I_TELEMETRY_SCHEMA_VERSION = "aegis-serving-abuse-telemetry-batch-v1"
P5I_RESPONSE_MODE = "deterministic-signed-telemetry-response-v1"
P5I_GENESIS_BATCH_SHA256 = "0" * 64


class AbuseSignalType(StrEnum):
    NORMAL_QUERY = "normal_query"
    OUTPUT_DETAIL_PROBE = "output_detail_probe"
    SENSITIVE_CHANNEL_PROBE = "sensitive_channel_probe"
    SESSION_BUDGET_EXHAUSTION = "session_budget_exhaustion"
    REPEATED_QUERY_PROBE = "repeated_query_probe"
    QUERY_REPLAY = "query_replay"
    CANARY_LEAKAGE = "canary_leakage"
    MEMORIZATION_SIGNAL = "memorization_signal"
    MEMBERSHIP_INFERENCE_SIGNAL = "membership_inference_signal"
    EXTRACTION_SIGNAL = "extraction_signal"
    IDENTITY_ANOMALY = "identity_anomaly"


class IncidentAction(StrEnum):
    OBSERVE = "observe"
    THROTTLE = "throttle"
    QUARANTINE = "quarantine"
    REVOKE_DEPLOYMENT = "revoke_deployment"


class AbuseTelemetryRejectReason(StrEnum):
    ATTESTATION_UNVERIFIED = "attestation_unverified"
    IDENTITY_MISMATCH = "identity_mismatch"
    POLICY_INVALID = "policy_invalid"
    COLLECTOR_UNTRUSTED = "collector_untrusted"
    SIGNATURE_INVALID = "signature_invalid"
    BATCH_INVALID = "batch_invalid"
    BATCH_STALE = "batch_stale"
    BATCH_FUTURE = "batch_future"
    BATCH_REPLAY = "batch_replay"
    SEQUENCE_MISMATCH = "sequence_mismatch"
    CHAIN_MISMATCH = "chain_mismatch"
    SOURCE_UNTRUSTED = "source_untrusted"
    EVENT_INVALID = "event_invalid"
    EVENT_DUPLICATE = "event_duplicate"


class AbuseTelemetryRejected(ValueError):
    def __init__(self, reason: AbuseTelemetryRejectReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class ServingAbuseEvent:
    event_id: str
    sequence: int
    observed_at_epoch: int
    principal_id: str
    session_id: str
    query_fingerprint: str
    signal_type: AbuseSignalType
    source: str = "privacy_gateway"
    occurrences: int = 1
    observed_score_milli: int = 0


@dataclass(frozen=True)
class ServingTelemetryBatch:
    deployment_id: str
    package_id: str
    model_id: str
    revision: str
    runtime_id: str
    attestation_statement_sha256: str
    collector_id: str
    batch_id: str
    first_sequence: int
    last_sequence: int
    previous_batch_sha256: str
    window_start_epoch: int
    window_end_epoch: int
    complete: bool
    events: tuple[ServingAbuseEvent, ...]
    schema_version: str = P5I_TELEMETRY_SCHEMA_VERSION


@dataclass(frozen=True)
class SignedServingTelemetryBatch:
    batch: ServingTelemetryBatch
    signature: bytes


def _default_signal_weights() -> Mapping[AbuseSignalType, int]:
    return {
        AbuseSignalType.NORMAL_QUERY: 0,
        AbuseSignalType.OUTPUT_DETAIL_PROBE: 2,
        AbuseSignalType.SENSITIVE_CHANNEL_PROBE: 5,
        AbuseSignalType.SESSION_BUDGET_EXHAUSTION: 4,
        AbuseSignalType.REPEATED_QUERY_PROBE: 4,
        AbuseSignalType.QUERY_REPLAY: 5,
        AbuseSignalType.CANARY_LEAKAGE: 40,
        AbuseSignalType.MEMORIZATION_SIGNAL: 8,
        AbuseSignalType.MEMBERSHIP_INFERENCE_SIGNAL: 7,
        AbuseSignalType.EXTRACTION_SIGNAL: 7,
        AbuseSignalType.IDENTITY_ANOMALY: 20,
    }


def _default_score_floors() -> Mapping[AbuseSignalType, int]:
    return {
        AbuseSignalType.MEMORIZATION_SIGNAL: 120,
        AbuseSignalType.MEMBERSHIP_INFERENCE_SIGNAL: 150,
        AbuseSignalType.EXTRACTION_SIGNAL: 250,
    }


@dataclass(frozen=True)
class ServingAbusePolicy:
    expected_attestation_statement_sha256: str
    trusted_collectors: Mapping[str, bytes]
    allowed_sources: frozenset[str] = frozenset({"privacy_gateway", "serving_gateway"})
    signal_weights: Mapping[AbuseSignalType, int] = field(default_factory=_default_signal_weights)
    score_floors_milli: Mapping[AbuseSignalType, int] = field(default_factory=_default_score_floors)
    max_batch_age_seconds: int = 300
    max_future_skew_seconds: int = 30
    max_occurrences_per_event: int = 20
    distributed_attack_principals: int = 3
    distributed_attack_bonus_points: int = 6
    throttle_points: int = 8
    quarantine_points: int = 16
    revoke_points: int = 32


@dataclass(frozen=True)
class VerifiedIncidentDecision:
    incident_id: str
    deployment_id: str
    package_id: str
    model_id: str
    revision: str
    runtime_id: str
    collector_id: str
    batch_id: str
    batch_sha256: str
    first_sequence: int
    last_sequence: int
    action: IncidentAction
    risk_points: int
    distinct_principals: int
    signal_counts: tuple[tuple[str, int], ...]
    attestation_statement_sha256: str
    telemetry_signature_verified: bool = True
    telemetry_chain_verified: bool = True
    telemetry_complete: bool = True
    quarantine_required: bool = False
    deployment_revocation_required: bool = False
    policy_version: str = P5I_ABUSE_POLICY_VERSION
    response_mode: str = P5I_RESPONSE_MODE
    real_siem_action: bool = False
    real_soar_action: bool = False
    distributed_enforcement: bool = False
    network_operations: int = 0


@dataclass
class _TelemetryCursor:
    last_sequence: int = 0
    last_batch_sha256: str = P5I_GENESIS_BATCH_SHA256


def _reject(reason: AbuseTelemetryRejectReason, message: str) -> None:
    raise AbuseTelemetryRejected(reason, message)


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def canonical_serving_telemetry_batch_bytes(batch: ServingTelemetryBatch) -> bytes:
    document = asdict(batch)
    document["attestation_statement_sha256"] = batch.attestation_statement_sha256.casefold()
    document["previous_batch_sha256"] = batch.previous_batch_sha256.casefold()
    for item in document["events"]:
        item["signal_type"] = str(item["signal_type"])
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def serving_telemetry_batch_digest(batch: ServingTelemetryBatch) -> str:
    return hashlib.sha256(canonical_serving_telemetry_batch_bytes(batch)).hexdigest()


class ServingAbuseResponseEngine:
    """Verify signed deployment-bound telemetry and derive deterministic response actions.

    This lab models evidence integrity, anti-replay/anti-fork sequencing, and response-policy
    derivation. It does not ingest production telemetry, operate a SIEM/SOAR, or enforce
    distributed quarantine/revocation.
    """

    def __init__(self, policy: ServingAbusePolicy) -> None:
        self._policy = policy
        self._cursors: dict[str, _TelemetryCursor] = {}
        self._seen_batch_ids: set[tuple[str, str]] = set()
        self._seen_event_ids: set[tuple[str, str]] = set()

    def _validate_policy(self) -> None:
        if (
            not _is_sha256(self._policy.expected_attestation_statement_sha256)
            or not self._policy.trusted_collectors
            or not self._policy.allowed_sources
            or self._policy.max_batch_age_seconds < 0
            or self._policy.max_future_skew_seconds < 0
            or self._policy.max_occurrences_per_event <= 0
            or self._policy.distributed_attack_principals <= 1
            or self._policy.distributed_attack_bonus_points < 0
            or not (
                0 <= self._policy.throttle_points
                < self._policy.quarantine_points
                < self._policy.revoke_points
            )
            or set(self._policy.signal_weights) != set(AbuseSignalType)
            or any(weight < 0 for weight in self._policy.signal_weights.values())
        ):
            _reject(AbuseTelemetryRejectReason.POLICY_INVALID, "serving abuse policy is inconsistent")
        for signal, floor in self._policy.score_floors_milli.items():
            if not isinstance(signal, AbuseSignalType) or not 0 <= floor <= 1_000:
                _reject(AbuseTelemetryRejectReason.POLICY_INVALID, "invalid signal score floor")

    def _validate_attestation(self, attestation: VerifiedDeploymentAttestation) -> None:
        if (
            not attestation.prior_release_verified
            or not attestation.runtime_policy_verified
            or not attestation.scan_evidence_verified
            or not attestation.privacy_policy_verified
            or not attestation.environment_policy_verified
            or not attestation.attestor_signature_verified
            or not attestation.least_privilege_environment_verified
            or attestation.network_operations != 0
        ):
            _reject(
                AbuseTelemetryRejectReason.ATTESTATION_UNVERIFIED,
                "incident response requires an intact P5-H verified deployment attestation",
            )
        expected = self._policy.expected_attestation_statement_sha256.casefold()
        if (
            not _is_sha256(attestation.statement_sha256)
            or attestation.statement_sha256.casefold() != expected
        ):
            _reject(
                AbuseTelemetryRejectReason.ATTESTATION_UNVERIFIED,
                "deployment attestation does not match the response-policy statement digest",
            )

    def evaluate(
        self,
        *,
        incident_id: str,
        attestation: VerifiedDeploymentAttestation,
        signed_batch: SignedServingTelemetryBatch,
        evaluated_at_epoch: int,
    ) -> VerifiedIncidentDecision:
        self._validate_policy()
        self._validate_attestation(attestation)
        batch = signed_batch.batch

        if not incident_id or evaluated_at_epoch < 0:
            _reject(AbuseTelemetryRejectReason.BATCH_INVALID, "incident/evaluation identity is invalid")

        expected_identity = (
            attestation.deployment_id,
            attestation.package_id,
            attestation.model_id,
            attestation.revision,
            attestation.runtime_id,
        )
        batch_identity = (
            batch.deployment_id,
            batch.package_id,
            batch.model_id,
            batch.revision,
            batch.runtime_id,
        )
        if batch_identity != expected_identity:
            _reject(
                AbuseTelemetryRejectReason.IDENTITY_MISMATCH,
                "telemetry batch identity does not match the attested deployment",
            )
        if (
            not _is_sha256(batch.attestation_statement_sha256)
            or batch.attestation_statement_sha256.casefold()
            != attestation.statement_sha256.casefold()
        ):
            _reject(
                AbuseTelemetryRejectReason.IDENTITY_MISMATCH,
                "telemetry batch is not bound to the exact verified deployment attestation",
            )

        if (
            batch.schema_version != P5I_TELEMETRY_SCHEMA_VERSION
            or not batch.collector_id
            or not batch.batch_id
            or not batch.complete
            or batch.window_start_epoch < 0
            or batch.window_end_epoch < batch.window_start_epoch
            or batch.first_sequence <= 0
            or batch.last_sequence < batch.first_sequence
            or not batch.events
            or len(batch.events) != batch.last_sequence - batch.first_sequence + 1
            or not _is_sha256(batch.previous_batch_sha256)
        ):
            _reject(
                AbuseTelemetryRejectReason.BATCH_INVALID,
                "telemetry batch schema, completeness, sequence range, or window is invalid",
            )
        if evaluated_at_epoch - batch.window_end_epoch > self._policy.max_batch_age_seconds:
            _reject(AbuseTelemetryRejectReason.BATCH_STALE, "telemetry batch is stale")
        if batch.window_end_epoch - evaluated_at_epoch > self._policy.max_future_skew_seconds:
            _reject(AbuseTelemetryRejectReason.BATCH_FUTURE, "telemetry batch is too far in the future")

        public_key_bytes = self._policy.trusted_collectors.get(batch.collector_id)
        if public_key_bytes is None:
            _reject(AbuseTelemetryRejectReason.COLLECTOR_UNTRUSTED, "telemetry collector is untrusted")
        try:
            Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(
                signed_batch.signature,
                canonical_serving_telemetry_batch_bytes(batch),
            )
        except (ValueError, InvalidSignature):
            _reject(AbuseTelemetryRejectReason.SIGNATURE_INVALID, "telemetry signature is invalid")

        batch_key = (batch.deployment_id, batch.batch_id)
        if batch_key in self._seen_batch_ids:
            _reject(AbuseTelemetryRejectReason.BATCH_REPLAY, "telemetry batch ID was already consumed")

        cursor = self._cursors.get(batch.deployment_id, _TelemetryCursor())
        if batch.first_sequence != cursor.last_sequence + 1:
            _reject(
                AbuseTelemetryRejectReason.SEQUENCE_MISMATCH,
                "telemetry sequence does not continue from the last accepted batch",
            )
        if batch.previous_batch_sha256.casefold() != cursor.last_batch_sha256.casefold():
            _reject(
                AbuseTelemetryRejectReason.CHAIN_MISMATCH,
                "telemetry batch does not extend the accepted deployment telemetry chain",
            )

        expected_sequences = list(range(batch.first_sequence, batch.last_sequence + 1))
        actual_sequences = [event.sequence for event in batch.events]
        if actual_sequences != expected_sequences:
            _reject(
                AbuseTelemetryRejectReason.SEQUENCE_MISMATCH,
                "events must be ordered and exactly contiguous within the signed batch",
            )

        batch_event_ids: set[str] = set()
        signal_counts: dict[AbuseSignalType, int] = {signal: 0 for signal in AbuseSignalType}
        risk_points = 0
        attack_principals: set[str] = set()
        all_principals: set[str] = set()

        for event in batch.events:
            event_key = (batch.deployment_id, event.event_id)
            if not event.event_id or event.event_id in batch_event_ids or event_key in self._seen_event_ids:
                _reject(AbuseTelemetryRejectReason.EVENT_DUPLICATE, "event ID is duplicated or replayed")
            batch_event_ids.add(event.event_id)

            if event.source not in self._policy.allowed_sources:
                _reject(AbuseTelemetryRejectReason.SOURCE_UNTRUSTED, "event source is not allowlisted")
            if (
                not event.principal_id
                or not event.session_id
                or not event.query_fingerprint
                or len(event.query_fingerprint) < 8
                or event.observed_at_epoch < batch.window_start_epoch
                or event.observed_at_epoch > batch.window_end_epoch
                or event.occurrences <= 0
                or event.occurrences > self._policy.max_occurrences_per_event
                or not 0 <= event.observed_score_milli <= 1_000
            ):
                _reject(AbuseTelemetryRejectReason.EVENT_INVALID, "telemetry event is malformed")

            floor = self._policy.score_floors_milli.get(event.signal_type)
            if floor is not None and event.observed_score_milli < floor:
                _reject(
                    AbuseTelemetryRejectReason.EVENT_INVALID,
                    "thresholded abuse signal does not meet the deployment-policy score floor",
                )

            signal_counts[event.signal_type] += event.occurrences
            risk_points += self._policy.signal_weights[event.signal_type] * event.occurrences
            all_principals.add(event.principal_id)
            if event.signal_type in {
                AbuseSignalType.MEMORIZATION_SIGNAL,
                AbuseSignalType.MEMBERSHIP_INFERENCE_SIGNAL,
                AbuseSignalType.EXTRACTION_SIGNAL,
            }:
                attack_principals.add(event.principal_id)

        if len(attack_principals) >= self._policy.distributed_attack_principals:
            risk_points += self._policy.distributed_attack_bonus_points

        if risk_points >= self._policy.revoke_points:
            action = IncidentAction.REVOKE_DEPLOYMENT
        elif risk_points >= self._policy.quarantine_points:
            action = IncidentAction.QUARANTINE
        elif risk_points >= self._policy.throttle_points:
            action = IncidentAction.THROTTLE
        else:
            action = IncidentAction.OBSERVE

        digest = serving_telemetry_batch_digest(batch)
        self._cursors[batch.deployment_id] = _TelemetryCursor(
            last_sequence=batch.last_sequence,
            last_batch_sha256=digest,
        )
        self._seen_batch_ids.add(batch_key)
        for event_id in batch_event_ids:
            self._seen_event_ids.add((batch.deployment_id, event_id))

        counts = tuple(
            (signal.value, count)
            for signal, count in sorted(signal_counts.items(), key=lambda item: item[0].value)
            if count
        )
        return VerifiedIncidentDecision(
            incident_id=incident_id,
            deployment_id=batch.deployment_id,
            package_id=batch.package_id,
            model_id=batch.model_id,
            revision=batch.revision,
            runtime_id=batch.runtime_id,
            collector_id=batch.collector_id,
            batch_id=batch.batch_id,
            batch_sha256=digest,
            first_sequence=batch.first_sequence,
            last_sequence=batch.last_sequence,
            action=action,
            risk_points=risk_points,
            distinct_principals=len(all_principals),
            signal_counts=counts,
            attestation_statement_sha256=attestation.statement_sha256.casefold(),
            quarantine_required=action in {
                IncidentAction.QUARANTINE,
                IncidentAction.REVOKE_DEPLOYMENT,
            },
            deployment_revocation_required=action is IncidentAction.REVOKE_DEPLOYMENT,
        )
