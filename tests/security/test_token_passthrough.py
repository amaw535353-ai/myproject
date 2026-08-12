import asyncio
import json
from pathlib import Path

import pytest
from mcp import Client

from aegis.downstream.auth import (
    INVENTORY_ALICE_ADMIN_TOKEN,
    INVENTORY_SERVICE_TOKEN,
    MCP_ALICE_TOKEN,
    MCP_BOB_TOKEN,
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
from aegis.vulnerable.token_passthrough import (
    VulnerableInventoryProxyError,
    VulnerableInventoryProxyGateway,
    build_vulnerable_inventory_proxy,
)
from evals.p2d_token_passthrough import build_report


_ASSETS_PATH = Path(__file__).resolve().parents[2] / "synthetic_data" / "assets.json"


def _inventory() -> SyntheticInventoryService:
    return SyntheticInventoryService(AssetStore.from_json(_ASSETS_PATH))


def test_hardened_proxy_tool_schema_hides_identity_and_bearer() -> None:
    inventory = _inventory()
    server = build_hardened_inventory_proxy(inventory)

    async def inspect() -> None:
        async with Client(server) as client:
            result = await client.list_tools()
        tool = next(item for item in result.tools if item.name == "get_my_assets")
        properties = tool.input_schema.get("properties", {})
        assert "principal" not in properties
        assert "inbound_bearer" not in properties
        assert "authorization" not in properties
        assert "token" not in properties
        assert "tenant_id" not in properties
        assert "user_id" not in properties

    asyncio.run(inspect())


def test_vulnerable_proxy_forwards_wrong_audience_token_and_downstream_authorizes() -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    inventory = _inventory()
    gateway = VulnerableInventoryProxyGateway(
        build_vulnerable_inventory_proxy(inventory)
    )

    result = asyncio.run(
        gateway.get_my_assets(
            principal=alice,
            inbound_bearer=INVENTORY_ALICE_ADMIN_TOKEN,
        )
    )

    assert result["assets"]
    events = inventory.events()
    assert len(events) == 1
    assert events[0].token_fingerprint == token_fingerprint(INVENTORY_ALICE_ADMIN_TOKEN)
    assert events[0].credential_class == "inventory-user-admin"
    assert events[0].authorized is True


def test_hardened_proxy_rejects_wrong_audience_before_mcp_or_downstream() -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    inventory = _inventory()
    gateway = InventoryProxyGateway(build_hardened_inventory_proxy(inventory))

    with pytest.raises(InventoryProxyError):
        asyncio.run(
            gateway.get_my_assets(
                principal=alice,
                inbound_bearer=INVENTORY_ALICE_ADMIN_TOKEN,
            )
        )

    assert inventory.events() == ()


def test_vulnerable_proxy_leaks_valid_mcp_token_even_when_downstream_rejects() -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    inventory = _inventory()
    gateway = VulnerableInventoryProxyGateway(
        build_vulnerable_inventory_proxy(inventory)
    )

    with pytest.raises(VulnerableInventoryProxyError):
        asyncio.run(
            gateway.get_my_assets(principal=alice, inbound_bearer=MCP_ALICE_TOKEN)
        )

    events = inventory.events()
    assert len(events) == 1
    assert events[0].token_fingerprint == token_fingerprint(MCP_ALICE_TOKEN)
    assert events[0].credential_class == "mcp-user"
    assert events[0].authorized is False


def test_hardened_proxy_uses_broker_owned_service_credential_downstream() -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    inventory = _inventory()
    gateway = InventoryProxyGateway(build_hardened_inventory_proxy(inventory))

    result = asyncio.run(
        gateway.get_my_assets(principal=alice, inbound_bearer=MCP_ALICE_TOKEN)
    )

    assert result["assets"]
    events = inventory.events()
    assert len(events) == 1
    assert events[0].token_fingerprint == token_fingerprint(INVENTORY_SERVICE_TOKEN)
    assert events[0].token_fingerprint != token_fingerprint(MCP_ALICE_TOKEN)
    assert events[0].credential_class == "inventory-service"
    assert events[0].authorized is True


def test_p2d_evaluation_report_never_contains_raw_bearer_values() -> None:
    report = build_report()
    rendered = json.dumps(report, sort_keys=True)

    assert report["evidence_hygiene"]["hardened_mcp_tool_receives_raw_inbound_bearer"] is False
    for raw_token in (
        MCP_ALICE_TOKEN,
        MCP_BOB_TOKEN,
        INVENTORY_ALICE_ADMIN_TOKEN,
        INVENTORY_SERVICE_TOKEN,
    ):
        assert raw_token not in rendered
