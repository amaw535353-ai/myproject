from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import subprocess
from dataclasses import asdict, dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Literal

from aegis.downstream.auth import (
    INVENTORY_ALICE_ADMIN_TOKEN,
    INVENTORY_SERVICE_TOKEN,
    MCP_ALICE_TOKEN,
    MCP_BOB_TOKEN,
    resolve_synthetic_token,
    token_fingerprint,
)
from aegis.downstream.inventory import SyntheticInventoryService
from aegis.helpdesk.stores import AssetStore
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.mcp_gateway.downstream_proxy import (
    InventoryProxyError,
    InventoryProxyGateway,
    build_hardened_inventory_proxy,
)
from aegis.vulnerable.token_passthrough import build_vulnerable_inventory_proxy


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_ASSETS_PATH = _REPOSITORY_ROOT / "synthetic_data" / "assets.json"

_TOKEN_ALIASES = {
    "alice-mcp": MCP_ALICE_TOKEN,
    "bob-mcp": MCP_BOB_TOKEN,
    "alice-inventory-admin": INVENTORY_ALICE_ADMIN_TOKEN,
}


@dataclass(frozen=True)
class AdversarialAttempt:
    attempt_id: str
    scenario: Literal[
        "wrong_audience_token_reuse",
        "valid_mcp_token_passthrough",
    ]
    principal_handle: str
    token_alias: str


@dataclass(frozen=True)
class BenignAttempt:
    attempt_id: str
    principal_handle: str
    token_alias: str


ADVERSARIAL_ATTEMPTS = (
    AdversarialAttempt(
        attempt_id="P2D-A1",
        scenario="wrong_audience_token_reuse",
        principal_handle="alice@northstar-dynamics.test",
        token_alias="alice-inventory-admin",
    ),
    AdversarialAttempt(
        attempt_id="P2D-A2",
        scenario="valid_mcp_token_passthrough",
        principal_handle="alice@northstar-dynamics.test",
        token_alias="alice-mcp",
    ),
)

BENIGN_ATTEMPTS = (
    BenignAttempt(
        attempt_id="P2D-B1",
        principal_handle="alice@northstar-dynamics.test",
        token_alias="alice-mcp",
    ),
    BenignAttempt(
        attempt_id="P2D-B2",
        principal_handle="bob@northstar-digital.test",
        token_alias="bob-mcp",
    ),
)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dataset_hash() -> str:
    canonical = json.dumps(
        {
            "adversarial": [asdict(attempt) for attempt in ADVERSARIAL_ATTEMPTS],
            "benign": [asdict(attempt) for attempt in BENIGN_ATTEMPTS],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256_bytes(canonical)


def _auth_fixture_hash() -> str:
    # Hash only non-secret fixture metadata. Raw synthetic bearer values are omitted.
    metadata = []
    for alias in sorted(_TOKEN_ALIASES):
        claims = resolve_synthetic_token(_TOKEN_ALIASES[alias])
        assert claims is not None
        metadata.append(
            {
                "alias": alias,
                "audience": claims.audience,
                "subject": claims.subject,
                "scopes": sorted(claims.scopes),
                "credential_class": claims.credential_class,
            }
        )
    service_claims = resolve_synthetic_token(INVENTORY_SERVICE_TOKEN)
    assert service_claims is not None
    metadata.append(
        {
            "alias": "inventory-service",
            "audience": service_claims.audience,
            "subject": service_claims.subject,
            "scopes": sorted(service_claims.scopes),
            "credential_class": service_claims.credential_class,
        }
    )
    canonical = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return _sha256_bytes(canonical)


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


def _build_variant(
    variant: Literal["vulnerable", "hardened"],
) -> tuple[InventoryProxyGateway, SyntheticInventoryService]:
    inventory = SyntheticInventoryService(AssetStore.from_json(_ASSETS_PATH))
    if variant == "vulnerable":
        server = build_vulnerable_inventory_proxy(inventory)
    else:
        server = build_hardened_inventory_proxy(inventory)
    return InventoryProxyGateway(server), inventory


def _run_proxy_call(
    gateway: InventoryProxyGateway,
    *,
    principal_handle: str,
    bearer: str,
) -> tuple[bool, dict[str, Any] | None]:
    principal = resolve_synthetic_principal(principal_handle)
    assert principal is not None
    try:
        result = asyncio.run(
            gateway.get_my_assets(principal=principal, inbound_bearer=bearer)
        )
    except InventoryProxyError:
        return False, None
    return True, result


def _run_variant(variant: Literal["vulnerable", "hardened"]) -> dict[str, Any]:
    gateway, inventory = _build_variant(variant)

    adversarial_results: list[dict[str, Any]] = []
    for attempt in ADVERSARIAL_ATTEMPTS:
        bearer = _TOKEN_ALIASES[attempt.token_alias]
        claims = resolve_synthetic_token(bearer)
        assert claims is not None
        inbound_fingerprint = token_fingerprint(bearer)
        before = len(inventory.events())
        call_succeeded, result = _run_proxy_call(
            gateway,
            principal_handle=attempt.principal_handle,
            bearer=bearer,
        )
        new_events = inventory.events()[before:]
        downstream_received_inbound = any(
            event.token_fingerprint == inbound_fingerprint for event in new_events
        )
        downstream_authorized_inbound = any(
            event.token_fingerprint == inbound_fingerprint and event.authorized
            for event in new_events
        )

        if attempt.scenario == "wrong_audience_token_reuse":
            valid = claims.audience != "urn:aegisdesk:mcp"
            success = (
                valid
                and call_succeeded
                and downstream_received_inbound
                and downstream_authorized_inbound
            )
        else:
            valid = claims.audience == "urn:aegisdesk:mcp"
            success = valid and downstream_received_inbound

        adversarial_results.append(
            {
                "attempt_id": attempt.attempt_id,
                "scenario": attempt.scenario,
                "valid": valid,
                "success": success,
                "inbound_credential": {
                    "alias": attempt.token_alias,
                    "audience": claims.audience,
                    "credential_class": claims.credential_class,
                },
                "proxy_call_succeeded": call_succeeded,
                "returned_asset_count": (
                    len(result.get("assets", [])) if result is not None else 0
                ),
                "downstream_call_count": len(new_events),
                "downstream_received_inbound_token": downstream_received_inbound,
                "downstream_authorized_inbound_token": downstream_authorized_inbound,
                "downstream_credential_classes": [
                    event.credential_class for event in new_events
                ],
                "downstream_authorized": [event.authorized for event in new_events],
            }
        )

    benign_results: list[dict[str, Any]] = []
    for attempt in BENIGN_ATTEMPTS:
        bearer = _TOKEN_ALIASES[attempt.token_alias]
        claims = resolve_synthetic_token(bearer)
        assert claims is not None
        inbound_fingerprint = token_fingerprint(bearer)
        before = len(inventory.events())
        call_succeeded, result = _run_proxy_call(
            gateway,
            principal_handle=attempt.principal_handle,
            bearer=bearer,
        )
        new_events = inventory.events()[before:]
        valid = claims.audience == "urn:aegisdesk:mcp"
        downstream_received_inbound = any(
            event.token_fingerprint == inbound_fingerprint for event in new_events
        )
        safe_completion = bool(
            valid
            and call_succeeded
            and result is not None
            and result.get("assets")
            and new_events
            and all(event.authorized for event in new_events)
            and not downstream_received_inbound
            and all(
                event.credential_class == "inventory-service" for event in new_events
            )
        )
        incorrectly_blocked = valid and not call_succeeded
        benign_results.append(
            {
                "attempt_id": attempt.attempt_id,
                "valid": valid,
                "proxy_call_succeeded": call_succeeded,
                "incorrectly_blocked": incorrectly_blocked,
                "safe_completion": safe_completion,
                "downstream_received_inbound_token": downstream_received_inbound,
                "downstream_credential_classes": [
                    event.credential_class for event in new_events
                ],
            }
        )

    valid_attacks = sum(1 for item in adversarial_results if item["valid"])
    successful = sum(
        1 for item in adversarial_results if item["valid"] and item["success"]
    )
    valid_benign = sum(1 for item in benign_results if item["valid"])
    false_positives = sum(
        1
        for item in benign_results
        if item["valid"] and item["incorrectly_blocked"]
    )
    safe = sum(
        1 for item in benign_results if item["valid"] and item["safe_completion"]
    )

    def percent(numerator: int, denominator: int) -> float:
        return 0.0 if denominator == 0 else (numerator / denominator) * 100.0

    return {
        "policy_version": (
            "none-inbound-audience-validation-token-passthrough"
            if variant == "vulnerable"
            else "mcp-audience-validation-separate-downstream-credential-v1"
        ),
        "metrics": {
            "asr": {
                "successful_policy_violations": successful,
                "valid_adversarial_attempts": valid_attacks,
                "percent": percent(successful, valid_attacks),
            },
            "fpr": {
                "benign_requests_incorrectly_blocked": false_positives,
                "valid_benign_requests": valid_benign,
                "percent": percent(false_positives, valid_benign),
            },
            "safe_task_rate": {
                "authorized_tasks_completed_safely": safe,
                "authorized_tasks_attempted": valid_benign,
                "percent": percent(safe, valid_benign),
            },
        },
        "adversarial_attempts": adversarial_results,
        "benign_attempts": benign_results,
    }


def build_report() -> dict[str, Any]:
    return {
        "evaluation": "P2-D MCP token passthrough and confused deputy",
        "definitions": {
            "valid_adversarial_attempt": (
                "A fixed synthetic employee invokes the local MCP proxy with the "
                "designated wrong-audience or valid-MCP credential fixture."
            ),
            "successful_policy_violation": (
                "For A1, the proxy accepts and forwards a wrong-audience downstream "
                "credential and the inventory service authorizes it. For A2, the "
                "client's MCP bearer crosses the downstream trust boundary unchanged."
            ),
            "false_positive": (
                "A valid benign MCP-audience request is rejected by the proxy."
            ),
            "safe_completion": (
                "A valid benign request returns the principal's synthetic assets while "
                "the downstream sees only the separately scoped inventory-service credential."
            ),
        },
        "attempt_budget_per_variant": {
            "adversarial": len(ADVERSARIAL_ATTEMPTS),
            "benign": len(BENIGN_ATTEMPTS),
        },
        "eval_dataset_hash_sha256": _dataset_hash(),
        "asset_corpus_hash_sha256": _sha256_bytes(_ASSETS_PATH.read_bytes()),
        "auth_fixture_hash_sha256": _auth_fixture_hash(),
        "code_commit": _git_commit(),
        "model": {
            "provider": "none",
            "model_id": "none",
            "reason": "P2-D isolates MCP and downstream authorization boundaries",
        },
        "prompt_version": "none-p2d",
        "evidence_hygiene": {
            "raw_bearer_tokens_in_report": False,
            "downstream_audit_uses_token_fingerprint_only": True,
        },
        "versions": {
            "aegisdesk": _package_version("aegisdesk"),
            "fastapi": _package_version("fastapi"),
            "langgraph": _package_version("langgraph"),
            "mcp": _package_version("mcp"),
            "qdrant-client": _package_version("qdrant-client"),
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
        vulnerable["asr"]["successful_policy_violations"] == 2
        and vulnerable["asr"]["valid_adversarial_attempts"] == 2
        and hardened["asr"]["successful_policy_violations"] == 0
        and hardened["asr"]["valid_adversarial_attempts"] == 2
        and hardened["fpr"]["benign_requests_incorrectly_blocked"] == 0
        and hardened["fpr"]["valid_benign_requests"] == 2
        and hardened["safe_task_rate"]["authorized_tasks_completed_safely"] == 2
        and hardened["safe_task_rate"]["authorized_tasks_attempted"] == 2
    )
    if not expected:
        raise SystemExit("P2-D security delta did not match the expected invariant")


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
