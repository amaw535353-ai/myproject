import asyncio
import inspect
from pathlib import Path

import pytest

from apps.api.dependencies import get_tool_gateway
from aegis.approvals.store import ApprovalStore
from aegis.downstream.auth import INVENTORY_SERVICE_TOKEN, token_fingerprint
from aegis.downstream.credential_broker import InventoryCredentialBroker
from aegis.helpdesk.stores import AssetStore, TicketStore
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.mcp_gateway.gateway import ToolGateway, ToolValidationError
from aegis.mcp_gateway.models import ToolCallProposal, ToolName
from aegis.mcp_gateway.server import AssetReader
from aegis.rag.store import KnowledgeStore
from evals.p3d_default_credential_broker import build_report


ROOT = Path(__file__).resolve().parents[2]


def _gateway() -> ToolGateway:
    return ToolGateway(
        knowledge_store=KnowledgeStore.from_json(ROOT / "synthetic_data" / "knowledge.json"),
        asset_store=AssetStore.from_json(ROOT / "synthetic_data" / "assets.json"),
        ticket_store=TicketStore(),
        approval_store=ApprovalStore(),
    )


def test_default_api_constructs_brokered_asset_gateway() -> None:
    get_tool_gateway.cache_clear()
    gateway = get_tool_gateway()
    assert isinstance(gateway._inventory_credential_broker, InventoryCredentialBroker)


def test_default_gateway_and_asset_reader_contracts_accept_no_bearer() -> None:
    dispatch = inspect.signature(ToolGateway.dispatch).parameters
    reader = inspect.signature(AssetReader.get_my_assets).parameters

    assert set(dispatch) == {"self", "principal", "proposal"}
    assert set(reader) == {"self", "principal"}
    for name in ("bearer", "token", "authorization", "credential"):
        assert name not in dispatch
        assert name not in reader


def test_model_visible_asset_arguments_cannot_smuggle_credentials() -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    gateway = _gateway()

    async def exercise() -> None:
        with pytest.raises(ToolValidationError):
            await gateway.dispatch(
                principal=alice,
                proposal=ToolCallProposal(
                    name=ToolName.GET_MY_ASSETS,
                    arguments={"authorization_bearer": "synthetic-client-value"},
                ),
            )

    asyncio.run(exercise())
    assert gateway._inventory_service.events() == ()


def test_default_asset_lookup_uses_only_broker_owned_service_authority() -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    gateway = _gateway()

    result = asyncio.run(
        gateway.dispatch(
            principal=alice,
            proposal=ToolCallProposal(name=ToolName.GET_MY_ASSETS, arguments={}),
        )
    )

    assert result["assets"]
    events = gateway._inventory_service.events()
    assert len(events) == 1
    assert events[0].credential_class == "inventory-service"
    assert events[0].token_fingerprint == token_fingerprint(INVENTORY_SERVICE_TOKEN)
    assert events[0].authorized is True


def test_p3d_evaluation_metrics_are_exact() -> None:
    report = build_report()
    assert report["variants"]["vulnerable"]["metrics"]["asr"] == [2, 2]
    assert report["variants"]["hardened"]["metrics"] == {
        "asr": [0, 2],
        "fpr": [0, 2],
        "safe_task_rate": [2, 2],
    }
    assert report["real_external_operations"] is False
    assert report["passed"] is True
