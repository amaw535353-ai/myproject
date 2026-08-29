"""External Onyx target primitives for the authorized local security lab."""

from aegis.targets.onyx.config import LAB_ACK_ENV, LAB_ACK_VALUE, OnyxTargetConfig
from aegis.targets.onyx.evidence import (
    CaseEvidence,
    CaseStatus,
    Metric,
    RunStatus,
    calculate_metrics,
    derive_run_status,
    sanitize_evidence,
)
from aegis.targets.onyx.fixtures import DOCUMENTS, GROUPS, USERS, expected_access
from aegis.targets.onyx.safety import (
    TargetGateStatus,
    TargetValidation,
    validate_authorized_target,
    validate_target_location,
)

__all__ = [
    "DOCUMENTS",
    "GROUPS",
    "LAB_ACK_ENV",
    "LAB_ACK_VALUE",
    "USERS",
    "CaseEvidence",
    "CaseStatus",
    "Metric",
    "OnyxTargetConfig",
    "RunStatus",
    "TargetGateStatus",
    "TargetValidation",
    "calculate_metrics",
    "derive_run_status",
    "expected_access",
    "sanitize_evidence",
    "validate_authorized_target",
    "validate_target_location",
]
