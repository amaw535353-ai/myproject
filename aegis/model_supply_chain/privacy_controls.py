from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import StrEnum

from .model_scanning import VerifiedModelScan
from .runtime_isolation import VerifiedRuntimePlan


P5G_PRIVACY_POLICY_VERSION = "model-privacy-extraction-membership-controls-v1"
P5G_PRIVACY_MODE = "synthetic-inference-privacy-gateway-v1"


class PrivacyRejectReason(StrEnum):
    RUNTIME_UNVERIFIED = "runtime_unverified"
    SCAN_UNVERIFIED = "scan_unverified"
    IDENTITY_MISMATCH = "identity_mismatch"
    SCAN_BINDING_MISMATCH = "scan_binding_mismatch"
    REQUEST_INVALID = "request_invalid"
    OUTPUT_MODE_DISALLOWED = "output_mode_disallowed"
    OUTPUT_DETAIL_EXCESSIVE = "output_detail_excessive"
    SENSITIVE_CHANNEL_EXPOSURE = "sensitive_channel_exposure"
    SESSION_BUDGET_EXCEEDED = "session_budget_exceeded"
    REPEATED_QUERY_BUDGET_EXCEEDED = "repeated_query_budget_exceeded"
    QUERY_REPLAY = "query_replay"
    RESPONSE_EVIDENCE_INVALID = "response_evidence_invalid"
    CANARY_LEAKAGE = "canary_leakage"
    MEMORIZATION_OVERLAP_EXCESSIVE = "memorization_overlap_excessive"
    MEMBERSHIP_SIGNAL_EXCESSIVE = "membership_signal_excessive"
    EXTRACTION_SIGNAL_EXCESSIVE = "extraction_signal_excessive"


class PrivacyControlRejected(ValueError):
    def __init__(self, reason: PrivacyRejectReason, message: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class PrivacyInferenceRequest:
    package_id: str
    model_id: str
    revision: str
    runtime_id: str
    scan_evidence_sha256: str
    principal_id: str
    session_id: str
    query_id: str
    query_fingerprint: str
    output_mode: str = "answer_only"
    requested_top_k: int = 0
    requested_confidence_decimals: int = 0
    expose_logits: bool = False
    expose_token_probabilities: bool = False
    expose_embeddings: bool = False
    expose_hidden_states: bool = False


@dataclass(frozen=True)
class PrivacyResponseEvidence:
    output_text: str
    output_tokens: int
    returned_top_k: int = 0
    returned_confidence_decimals: int = 0
    returned_logits: bool = False
    returned_token_probabilities: bool = False
    returned_embeddings: bool = False
    returned_hidden_states: bool = False
    memorization_overlap_ppm: int = 0
    membership_advantage_milli: int = 0
    extraction_similarity_milli: int = 0
    canary_scan_complete: bool = True


@dataclass(frozen=True)
class PrivacyControlPolicy:
    expected_scan_evidence_sha256: str
    allowed_output_modes: frozenset[str] = frozenset(
        {"answer_only", "top_label", "coarse_confidence"}
    )
    max_top_k: int = 1
    max_confidence_decimals: int = 1
    max_output_tokens: int = 256
    max_queries_per_session: int = 4
    max_repeated_fingerprint_queries: int = 2
    forbidden_canary_fragments: tuple[str, ...] = (
        "aegis-canary-7f3a",
        "training-secret-42",
        "private-corpus-marker",
    )
    max_memorization_overlap_ppm: int = 120_000
    max_membership_advantage_milli: int = 150
    max_extraction_similarity_milli: int = 250


@dataclass(frozen=True)
class VerifiedPrivacyResponse:
    package_id: str
    model_id: str
    revision: str
    runtime_id: str
    principal_id: str
    session_id: str
    query_id: str
    output_mode: str
    output_text: str
    output_sha256: str
    output_tokens: int
    session_queries_used: int
    repeated_fingerprint_queries_used: int
    output_minimized: bool = True
    sensitive_channels_denied: bool = True
    canary_scan_clear: bool = True
    memorization_indicator_clear: bool = True
    membership_indicator_clear: bool = True
    extraction_indicator_clear: bool = True
    policy_version: str = P5G_PRIVACY_POLICY_VERSION
    privacy_mode: str = P5G_PRIVACY_MODE
    real_model_inference: bool = False
    raw_logits_exposed: bool = False
    embeddings_exposed: bool = False
    hidden_states_exposed: bool = False
    network_operations: int = 0


class PrivacyBudgetLedger:
    """Deterministic in-memory budget ledger for the P5-G lab."""

    def __init__(self) -> None:
        self._session_counts: dict[tuple[str, str, str, str], int] = {}
        self._fingerprint_counts: dict[tuple[str, str, str, str, str], int] = {}
        self._query_ids: set[tuple[str, str, str, str, str]] = set()

    def consume(
        self,
        *,
        model_id: str,
        revision: str,
        principal_id: str,
        session_id: str,
        query_id: str,
        query_fingerprint: str,
        max_queries_per_session: int,
        max_repeated_fingerprint_queries: int,
    ) -> tuple[int, int]:
        session_key = (model_id, revision, principal_id, session_id)
        query_key = session_key + (query_id,)
        fingerprint_key = session_key + (query_fingerprint,)

        if query_key in self._query_ids:
            raise PrivacyControlRejected(
                PrivacyRejectReason.QUERY_REPLAY,
                "query ID was already consumed in this model/principal/session scope",
            )

        session_count = self._session_counts.get(session_key, 0)
        if session_count >= max_queries_per_session:
            raise PrivacyControlRejected(
                PrivacyRejectReason.SESSION_BUDGET_EXCEEDED,
                "session inference-query budget is exhausted",
            )

        fingerprint_count = self._fingerprint_counts.get(fingerprint_key, 0)
        if fingerprint_count >= max_repeated_fingerprint_queries:
            raise PrivacyControlRejected(
                PrivacyRejectReason.REPEATED_QUERY_BUDGET_EXCEEDED,
                "repeated-query fingerprint budget is exhausted",
            )

        session_count += 1
        fingerprint_count += 1
        self._session_counts[session_key] = session_count
        self._fingerprint_counts[fingerprint_key] = fingerprint_count
        self._query_ids.add(query_key)
        return session_count, fingerprint_count


def _reject(reason: PrivacyRejectReason, message: str) -> None:
    raise PrivacyControlRejected(reason, message)


def _is_sha256(value: str) -> bool:
    lowered = value.casefold()
    return len(lowered) == 64 and all(ch in "0123456789abcdef" for ch in lowered)


def _validate_runtime(runtime: VerifiedRuntimePlan) -> None:
    if (
        not runtime.provenance_verified
        or not runtime.transitive_package_verified
        or not runtime.parser_policy_verified
        or not runtime.backend_policy_verified
        or runtime.remote_code_allowed
        or runtime.dynamic_code_allowed
        or runtime.native_extensions_allowed
        or runtime.custom_ops_allowed
        or runtime.network_access
        or runtime.subprocess_allowed
        or runtime.host_filesystem_write
        or runtime.environment_passthrough
        or runtime.host_ipc
        or runtime.ptrace_allowed
        or not runtime.sandbox_required
        or runtime.model_bytes_parsed
        or runtime.model_executed
        or runtime.network_operations != 0
    ):
        _reject(
            PrivacyRejectReason.RUNTIME_UNVERIFIED,
            "privacy admission requires an intact non-executing P5-E runtime handle",
        )


def _validate_scan(scan: VerifiedModelScan, runtime: VerifiedRuntimePlan) -> None:
    if (
        not scan.subject_digest_pins_verified
        or not scan.exact_component_coverage_verified
        or not scan.runtime_plan_verified
        or not scan.static_indicators_clear
        or not scan.synthetic_probe_indicators_clear
        or scan.indicator_count != 0
        or scan.raw_model_bytes_scanned
        or scan.model_executed
        or scan.network_operations != 0
    ):
        _reject(
            PrivacyRejectReason.SCAN_UNVERIFIED,
            "privacy admission requires an intact clear P5-F scan handle",
        )
    if (
        (scan.package_id, scan.model_id, scan.revision, scan.runtime_id)
        != (runtime.package_id, runtime.model_id, runtime.revision, runtime.runtime_id)
    ):
        _reject(
            PrivacyRejectReason.SCAN_UNVERIFIED,
            "scan handle does not bind to the verified runtime release identity",
        )


class ModelPrivacyGateway:
    """Apply synthetic inference privacy controls after P5-E/P5-F admission.

    The gateway does not run a model. It validates a deterministic response-evidence contract,
    limits oracle fidelity and query volume, rejects canary/memorization/membership/extraction
    indicators, and returns only the modeled minimized response.
    """

    def __init__(
        self,
        policy: PrivacyControlPolicy,
        *,
        ledger: PrivacyBudgetLedger | None = None,
    ) -> None:
        self._policy = policy
        self._ledger = ledger or PrivacyBudgetLedger()

    def release(
        self,
        *,
        request: PrivacyInferenceRequest,
        runtime: VerifiedRuntimePlan,
        scan: VerifiedModelScan,
        evidence: PrivacyResponseEvidence,
    ) -> VerifiedPrivacyResponse:
        _validate_runtime(runtime)
        _validate_scan(scan, runtime)

        identity = (request.package_id, request.model_id, request.revision, request.runtime_id)
        if identity != (runtime.package_id, runtime.model_id, runtime.revision, runtime.runtime_id):
            _reject(
                PrivacyRejectReason.IDENTITY_MISMATCH,
                "privacy request identity does not match verified runtime",
            )
        if identity != (scan.package_id, scan.model_id, scan.revision, scan.runtime_id):
            _reject(
                PrivacyRejectReason.IDENTITY_MISMATCH,
                "privacy request identity does not match verified scan",
            )

        expected_scan_digest = self._policy.expected_scan_evidence_sha256.casefold()
        if (
            not _is_sha256(expected_scan_digest)
            or not _is_sha256(scan.evidence_sha256)
            or not _is_sha256(request.scan_evidence_sha256)
            or not hmac.compare_digest(scan.evidence_sha256.casefold(), expected_scan_digest)
            or not hmac.compare_digest(request.scan_evidence_sha256.casefold(), expected_scan_digest)
        ):
            _reject(
                PrivacyRejectReason.SCAN_BINDING_MISMATCH,
                "privacy policy/request must bind to the exact approved P5-F evidence digest",
            )

        if (
            not request.principal_id
            or not request.session_id
            or not request.query_id
            or not request.query_fingerprint
            or len(request.query_fingerprint) < 8
        ):
            _reject(
                PrivacyRejectReason.REQUEST_INVALID,
                "principal/session/query/fingerprint identity is required",
            )

        if request.output_mode not in self._policy.allowed_output_modes:
            _reject(
                PrivacyRejectReason.OUTPUT_MODE_DISALLOWED,
                "requested output mode is not permitted by privacy policy",
            )
        if (
            request.requested_top_k < 0
            or request.requested_top_k > self._policy.max_top_k
            or request.requested_confidence_decimals < 0
            or request.requested_confidence_decimals > self._policy.max_confidence_decimals
        ):
            _reject(
                PrivacyRejectReason.OUTPUT_DETAIL_EXCESSIVE,
                "requested ranking/confidence detail exceeds privacy policy",
            )

        if (
            request.expose_logits
            or request.expose_token_probabilities
            or request.expose_embeddings
            or request.expose_hidden_states
            or evidence.returned_logits
            or evidence.returned_token_probabilities
            or evidence.returned_embeddings
            or evidence.returned_hidden_states
        ):
            _reject(
                PrivacyRejectReason.SENSITIVE_CHANNEL_EXPOSURE,
                "raw logits, token probabilities, embeddings, and hidden states are denied",
            )

        if (
            evidence.output_tokens < 0
            or evidence.output_tokens > self._policy.max_output_tokens
            or evidence.returned_top_k < 0
            or evidence.returned_top_k > request.requested_top_k
            or evidence.returned_top_k > self._policy.max_top_k
            or evidence.returned_confidence_decimals < 0
            or evidence.returned_confidence_decimals > request.requested_confidence_decimals
            or evidence.returned_confidence_decimals > self._policy.max_confidence_decimals
            or not 0 <= evidence.memorization_overlap_ppm <= 1_000_000
            or not 0 <= evidence.membership_advantage_milli <= 1_000
            or not 0 <= evidence.extraction_similarity_milli <= 1_000
            or not evidence.canary_scan_complete
        ):
            _reject(
                PrivacyRejectReason.RESPONSE_EVIDENCE_INVALID,
                "response privacy evidence is malformed, incomplete, or exceeds requested detail",
            )

        if request.output_mode == "answer_only" and (
            evidence.returned_top_k != 0 or evidence.returned_confidence_decimals != 0
        ):
            _reject(
                PrivacyRejectReason.OUTPUT_DETAIL_EXCESSIVE,
                "answer-only mode may not return ranking or confidence detail",
            )
        if request.output_mode == "top_label" and evidence.returned_confidence_decimals != 0:
            _reject(
                PrivacyRejectReason.OUTPUT_DETAIL_EXCESSIVE,
                "top-label mode may not return numeric confidence detail",
            )

        lowered_output = evidence.output_text.casefold()
        if any(fragment.casefold() in lowered_output for fragment in self._policy.forbidden_canary_fragments):
            _reject(
                PrivacyRejectReason.CANARY_LEAKAGE,
                "response contains a deployment-forbidden training canary fragment",
            )
        if evidence.memorization_overlap_ppm > self._policy.max_memorization_overlap_ppm:
            _reject(
                PrivacyRejectReason.MEMORIZATION_OVERLAP_EXCESSIVE,
                "response memorization-overlap indicator exceeds privacy policy",
            )
        if evidence.membership_advantage_milli > self._policy.max_membership_advantage_milli:
            _reject(
                PrivacyRejectReason.MEMBERSHIP_SIGNAL_EXCESSIVE,
                "synthetic membership-inference advantage exceeds privacy policy",
            )
        if evidence.extraction_similarity_milli > self._policy.max_extraction_similarity_milli:
            _reject(
                PrivacyRejectReason.EXTRACTION_SIGNAL_EXCESSIVE,
                "synthetic model-extraction similarity exceeds privacy policy",
            )

        session_used, fingerprint_used = self._ledger.consume(
            model_id=request.model_id,
            revision=request.revision,
            principal_id=request.principal_id,
            session_id=request.session_id,
            query_id=request.query_id,
            query_fingerprint=request.query_fingerprint,
            max_queries_per_session=self._policy.max_queries_per_session,
            max_repeated_fingerprint_queries=self._policy.max_repeated_fingerprint_queries,
        )

        return VerifiedPrivacyResponse(
            package_id=request.package_id,
            model_id=request.model_id,
            revision=request.revision,
            runtime_id=request.runtime_id,
            principal_id=request.principal_id,
            session_id=request.session_id,
            query_id=request.query_id,
            output_mode=request.output_mode,
            output_text=evidence.output_text,
            output_sha256=hashlib.sha256(evidence.output_text.encode("utf-8")).hexdigest(),
            output_tokens=evidence.output_tokens,
            session_queries_used=session_used,
            repeated_fingerprint_queries_used=fingerprint_used,
        )
