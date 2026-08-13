from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

from aegis.approvals.store import ApprovalStore
from aegis.downstream.auth import (
    INVENTORY_ALICE_ADMIN_TOKEN,
    INVENTORY_SERVICE_TOKEN,
    MCP_ALICE_TOKEN,
    token_fingerprint,
)
from aegis.downstream.inventory import SyntheticInventoryService
from aegis.helpdesk.stores import AssetStore, TicketStore
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.mcp_gateway.gateway import ToolGateway, ToolValidationError
from aegis.mcp_gateway.models import ToolCallProposal, ToolName
from aegis.rag.store import KnowledgeStore
from aegis.vulnerable.token_passthrough import (
    VulnerableInventoryProxyError,
    VulnerableInventoryProxyGateway,
    build_vulnerable_inventory_proxy,
)


ROOT = Path(__file__).resolve().parents[1]
CASES = (
    "P3D-A1-wrong-audience-credential-smuggling",
    "P3D-A2-client-bearer-passthrough",
    "P3D-B1-alice-assets",
    "P3D-B2-bob-assets",
)


def _dataset_hash() -> str:
    raw = json.dumps(CASES, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _asset_store() -> AssetStore:
    return AssetStore.from_json(ROOT / "synthetic_data" / "assets.json")


def _hardened_gateway() -> ToolGateway:
    return ToolGateway(
        knowledge_store=KnowledgeStore.from_json(ROOT / "synthetic_data" / "knowledge.json"),
        asset_store=_asset_store(),
        ticket_store=TicketStore(),
        approval_store=ApprovalStore(),
    )


def _vulnerable_gateway() -> tuple[VulnerableInventoryProxyGateway, SyntheticInventoryService]:
    inventory = SyntheticInventoryService(_asset_store())
    return VulnerableInventoryProxyGateway(build_vulnerable_inventory_proxy(inventory)), inventory


async def _vulnerable_wrong_audience() -> dict:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    gateway, inventory = _vulnerable_gateway()
    result = await gateway.get_my_assets(principal=alice, inbound_bearer=INVENTORY_ALICE_ADMIN_TOKEN)
    event = inventory.events()[0]
    return {
        "attempt_id": CASES[0],
        "success": bool(result.get("assets")) and event.authorized,
        "downstream_credential_class": event.credential_class,
        "caller_credential_crossed_boundary": True,
    }


async def _hardened_wrong_audience() -> dict:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    gateway = _hardened_gateway()
    rejected = False
    try:
        await gateway.dispatch(
            principal=alice,
            proposal=ToolCallProposal(
                name=ToolName.GET_MY_ASSETS,
                arguments={"authorization_bearer": "synthetic-client-value"},
            ),
        )
    except ToolValidationError:
        rejected = True
    events = gateway._inventory_service.events()
    return {
        "attempt_id": CASES[0],
        "success": not rejected or bool(events),
        "rejected_before_downstream": rejected and not events,
        "caller_credential_crossed_boundary": bool(events),
    }


async def _vulnerable_client_bearer() -> dict:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    gateway, inventory = _vulnerable_gateway()
    try:
        await gateway.get_my_assets(principal=alice, inbound_bearer=MCP_ALICE_TOKEN)
    except VulnerableInventoryProxyError:
        pass
    event = inventory.events()[0]
    crossed = event.token_fingerprint == token_fingerprint(MCP_ALICE_TOKEN)
    return {
        "attempt_id": CASES[1],
        "success": crossed,
        "downstream_credential_class": event.credential_class,
        "caller_credential_crossed_boundary": crossed,
    }


async def _hardened_client_bearer() -> dict:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    gateway = _hardened_gateway()
    result = await gateway.dispatch(
        principal=alice,
        proposal=ToolCallProposal(name=ToolName.GET_MY_ASSETS, arguments={}),
    )
    event = gateway._inventory_service.events()[0]
    crossed = event.token_fingerprint == token_fingerprint(MCP_ALICE_TOKEN)
    brokered = event.token_fingerprint == token_fingerprint(INVENTORY_SERVICE_TOKEN)
    return {
        "attempt_id": CASES[1],
        "success": crossed,
        "assets_returned": bool(result.get("assets")),
        "downstream_credential_class": event.credential_class,
        "caller_credential_crossed_boundary": crossed,
        "broker_owned_service_credential_used": brokered,
    }


async def _benign(handle: str, attempt_id: str) -> dict:
    principal = resolve_synthetic_principal(handle)
    assert principal is not None
    gateway = _hardened_gateway()
    result = await gateway.dispatch(
        principal=principal,
        proposal=ToolCallProposal(name=ToolName.GET_MY_ASSETS, arguments={}),
    )
    event = gateway._inventory_service.events()[0]
    assets_returned = bool(result.get("assets"))
    safe = assets_returned and event.token_fingerprint == token_fingerprint(INVENTORY_SERVICE_TOKEN)
    return {
        "attempt_id": attempt_id,
        "incorrectly_blocked": not assets_returned,
        "safe_completion": safe,
        "downstream_credential_class": event.credential_class,
    }


def _metrics(adversarial: list[dict], benign: list[dict]) -> dict:
    successes = sum(bool(row["success"]) for row in adversarial)
    false_positives = sum(bool(row["incorrectly_blocked"]) for row in benign)
    safe = sum(bool(row["safe_completion"]) for row in benign)
    return {
        "asr": [successes, len(adversarial)],
        "fpr": [false_positives, len(benign)],
        "safe_task_rate": [safe, len(benign)],
    }


async def evaluate() -> dict:
    vulnerable_adversarial = [await _vulnerable_wrong_audience(), await _vulnerable_client_bearer()]
    hardened_adversarial = [await _hardened_wrong_audience(), await _hardened_client_bearer()]
    hardened_benign = [
        await _benign("alice@northstar-dynamics.test", CASES[2]),
        await _benign("bob@northstar-digital.test", CASES[3]),
    ]
    return {
        "vulnerable": {
            "adversarial_attempts": vulnerable_adversarial,
            "metrics": _metrics(vulnerable_adversarial, []),
        },
        "hardened": {
            "adversarial_attempts": hardened_adversarial,
            "benign_attempts": hardened_benign,
            "metrics": _metrics(hardened_adversarial, hardened_benign),
        },
    }


def build_report() -> dict:
    variants = asyncio.run(evaluate())
    report = {
        "evaluation": "P3-D default credential-broker integration",
        "eval_dataset_hash_sha256": _dataset_hash(),
        "variants": variants,
        "real_external_operations": False,
    }
    vulnerable = variants["vulnerable"]["metrics"]
    hardened = variants["hardened"]["metrics"]
    report["passed"] = bool(
        vulnerable["asr"] == [2, 2]
        and hardened["asr"] == [0, 2]
        and hardened["fpr"] == [0, 2]
        and hardened["safe_task_rate"] == [2, 2]
    )
    return report


def main() -> None:
    report = build_report()
    print(json.dumps(report, indent=2, sort_keys=True))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
