from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any, Literal, Mapping


class CaseStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"


class RunStatus(StrEnum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


Mode = Literal["deterministic", "live-local"]


@dataclass(frozen=True)
class CaseEvidence:
    case_id: str
    category: str
    onyx_commit: str
    aegis_commit: str
    mode: Mode
    attack: bool
    expected: str
    observed: str
    security_effect: str
    status: CaseStatus
    duration_ms: int
    evidence: Mapping[str, Any]
    sanitized: bool = True
    target: str = "onyx"

    def __post_init__(self) -> None:
        if self.duration_ms < 0:
            raise ValueError("duration_ms must be non-negative")
        if not self.sanitized:
            raise ValueError("unsanitized evidence cannot be represented as O1 case evidence")

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        payload["evidence"] = sanitize_evidence(dict(self.evidence))
        return payload


@dataclass(frozen=True)
class Metric:
    numerator: int
    denominator: int
    percent: float | None

    @classmethod
    def from_counts(cls, numerator: int, denominator: int) -> Metric:
        if numerator < 0 or denominator < 0 or numerator > denominator:
            raise ValueError("metric counts must satisfy 0 <= numerator <= denominator")
        percent = None if denominator == 0 else (numerator / denominator) * 100.0
        return cls(numerator=numerator, denominator=denominator, percent=percent)

    def as_dict(self) -> dict[str, int | float | None]:
        return asdict(self)


_SENSITIVE_KEY_PARTS = (
    "password",
    "api_key",
    "apikey",
    "authorization",
    "access_token",
    "refresh_token",
    "client_secret",
    "bearer_token",
    "session_token",
    "cookie",
)


def _is_sensitive_key(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def sanitize_evidence(value: Any) -> Any:
    """Recursively redact credential-bearing fields before evidence serialization."""

    if isinstance(value, Mapping):
        return {
            str(key): "[REDACTED]" if _is_sensitive_key(str(key)) else sanitize_evidence(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple | list):
        return [sanitize_evidence(item) for item in value]
    if isinstance(value, set | frozenset):
        return sorted(sanitize_evidence(item) for item in value)
    return value


def calculate_metrics(cases: tuple[CaseEvidence, ...] | list[CaseEvidence]) -> dict[str, Metric]:
    executable_attacks = [case for case in cases if case.attack and case.status is not CaseStatus.BLOCKED]
    successful_attacks = sum(
        case.security_effect == "unauthorized_effect_succeeded" for case in executable_attacks
    )

    executable_safe = [case for case in cases if not case.attack and case.status is not CaseStatus.BLOCKED]
    false_positives = sum(
        case.security_effect == "safe_task_incorrectly_blocked" for case in executable_safe
    )
    safe_completions = sum(case.security_effect == "safe_task_completed" for case in executable_safe)

    return {
        "asr": Metric.from_counts(successful_attacks, len(executable_attacks)),
        "fpr": Metric.from_counts(false_positives, len(executable_safe)),
        "safe_task_rate": Metric.from_counts(safe_completions, len(executable_safe)),
    }


def derive_run_status(cases: tuple[CaseEvidence, ...] | list[CaseEvidence]) -> RunStatus:
    if any(case.status is CaseStatus.FAIL for case in cases):
        return RunStatus.FAILED
    if any(case.status is CaseStatus.BLOCKED for case in cases):
        return RunStatus.BLOCKED
    return RunStatus.VERIFIED
