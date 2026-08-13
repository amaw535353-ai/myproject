from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from pydantic import BaseModel, ConfigDict

from aegis.agent.checkpoint_security import (
    DEFAULT_CHECKPOINT_SERIALIZATION_POLICY,
    P4A_ALLOWED_MSGPACK_TYPES,
    build_strict_checkpoint_serializer,
)
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.mcp_gateway.models import ToolCallProposal, ToolName


CASES = (
    "P4A-A1-unregistered-pydantic-type",
    "P4A-A2-unregistered-dataclass-type",
    "P4A-B1-principal-roundtrip",
    "P4A-B2-tool-proposal-roundtrip",
)


class SyntheticUnregisteredCheckpointModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    marker: str


@dataclass(frozen=True)
class SyntheticUnregisteredCheckpointRecord:
    marker: str


def _dataset_hash() -> str:
    canonical = json.dumps(CASES, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _roundtrip(serializer: JsonPlusSerializer, value):
    return serializer.loads_typed(serializer.dumps_typed(value))


def _permissive_baseline() -> list[dict]:
    serializer = JsonPlusSerializer(
        pickle_fallback=False,
        allowed_json_modules=None,
        allowed_msgpack_modules=True,
    )
    pydantic_value = SyntheticUnregisteredCheckpointModel(marker="synthetic")
    dataclass_value = SyntheticUnregisteredCheckpointRecord(marker="synthetic")
    pydantic_loaded = _roundtrip(serializer, pydantic_value)
    dataclass_loaded = _roundtrip(serializer, dataclass_value)
    return [
        {
            "attempt_id": CASES[0],
            "success": isinstance(pydantic_loaded, SyntheticUnregisteredCheckpointModel),
            "unregistered_python_type_reconstructed": isinstance(
                pydantic_loaded, SyntheticUnregisteredCheckpointModel
            ),
        },
        {
            "attempt_id": CASES[1],
            "success": isinstance(dataclass_loaded, SyntheticUnregisteredCheckpointRecord),
            "unregistered_python_type_reconstructed": isinstance(
                dataclass_loaded, SyntheticUnregisteredCheckpointRecord
            ),
        },
    ]


def _strict_boundary() -> list[dict]:
    serializer = build_strict_checkpoint_serializer()
    pydantic_value = SyntheticUnregisteredCheckpointModel(marker="synthetic")
    dataclass_value = SyntheticUnregisteredCheckpointRecord(marker="synthetic")
    pydantic_loaded = _roundtrip(serializer, pydantic_value)
    dataclass_loaded = _roundtrip(serializer, dataclass_value)
    return [
        {
            "attempt_id": CASES[0],
            "success": isinstance(pydantic_loaded, SyntheticUnregisteredCheckpointModel),
            "unregistered_python_type_reconstructed": isinstance(
                pydantic_loaded, SyntheticUnregisteredCheckpointModel
            ),
            "degraded_to_plain_data": isinstance(pydantic_loaded, dict),
        },
        {
            "attempt_id": CASES[1],
            "success": isinstance(dataclass_loaded, SyntheticUnregisteredCheckpointRecord),
            "unregistered_python_type_reconstructed": isinstance(
                dataclass_loaded, SyntheticUnregisteredCheckpointRecord
            ),
            "degraded_to_plain_data": isinstance(dataclass_loaded, dict),
        },
    ]


def _benign_roundtrips() -> list[dict]:
    serializer = build_strict_checkpoint_serializer()
    principal = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert principal is not None
    proposal = ToolCallProposal(
        name=ToolName.SEARCH_KNOWLEDGE_BASE,
        arguments={"query": "vpn setup", "limit": 3},
    )
    loaded_principal = _roundtrip(serializer, principal)
    loaded_proposal = _roundtrip(serializer, proposal)
    principal_safe = loaded_principal == principal and type(loaded_principal) is type(principal)
    proposal_safe = loaded_proposal == proposal and type(loaded_proposal) is type(proposal)
    return [
        {
            "attempt_id": CASES[2],
            "incorrectly_blocked": not principal_safe,
            "safe_completion": principal_safe,
        },
        {
            "attempt_id": CASES[3],
            "incorrectly_blocked": not proposal_safe,
            "safe_completion": proposal_safe,
        },
    ]


def _metrics(adversarial: list[dict], benign: list[dict]) -> dict:
    successes = sum(bool(item["success"]) for item in adversarial)
    false_positives = sum(bool(item["incorrectly_blocked"]) for item in benign)
    safe = sum(bool(item["safe_completion"]) for item in benign)
    return {
        "asr": [successes, len(adversarial)],
        "fpr": [false_positives, len(benign)],
        "safe_task_rate": [safe, len(benign)],
    }


def build_report() -> dict:
    permissive = _permissive_baseline()
    strict = _strict_boundary()
    benign = _benign_roundtrips()
    permissive_metrics = _metrics(permissive, [])
    strict_metrics = _metrics(strict, benign)
    report = {
        "evaluation": "P4-A strict durable-checkpoint serialization boundary",
        "eval_dataset_hash_sha256": _dataset_hash(),
        "policy_version": DEFAULT_CHECKPOINT_SERIALIZATION_POLICY.policy_version,
        "allowed_application_types": [".".join(item) for item in P4A_ALLOWED_MSGPACK_TYPES],
        "variants": {
            "permissive_baseline": {
                "adversarial_attempts": permissive,
                "metrics": permissive_metrics,
            },
            "strict_boundary": {
                "adversarial_attempts": strict,
                "benign_attempts": benign,
                "metrics": strict_metrics,
            },
        },
        "pickle_fallback_enabled": False,
        "custom_json_constructor_allowlist": False,
        "real_external_operations": False,
    }
    report["passed"] = bool(
        permissive_metrics["asr"] == [2, 2]
        and strict_metrics["asr"] == [0, 2]
        and strict_metrics["fpr"] == [0, 2]
        and strict_metrics["safe_task_rate"] == [2, 2]
        and all(item["degraded_to_plain_data"] for item in strict)
    )
    return report


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
