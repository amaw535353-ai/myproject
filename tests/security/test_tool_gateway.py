import asyncio

import pytest
from mcp import Client
from pydantic import ValidationError

from aegis.approvals.store import ApprovalStore
from aegis.helpdesk.models import AssetRecord
from aegis.helpdesk.stores import AssetStore, TicketStore
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.mcp_gateway.gateway import ToolGateway, ToolValidationError
from aegis.mcp_gateway.models import ToolCallProposal, ToolName
from aegis.rag.models import KnowledgeDocument
from aegis.rag.store import KnowledgeStore


def build_gateway() -> tuple[ToolGateway, TicketStore]:
    knowledge_store = KnowledgeStore(
        [
            KnowledgeDocument(
                id=1,
                tenant_id="tenant_northstar_dynamics",
                title="VPN",
                text="Dynamics VPN A-CANARY",
                canary="A-CANARY",
            )
        ]
    )
    asset_store = AssetStore(
        [
            AssetRecord(
                asset_id="ASSET-1",
                tenant_id="tenant_northstar_dynamics",
                assigned_user_id="usr_dyn_alice",
                asset_type="laptop",
                label="Alice laptop",
            )
        ]
    )
    ticket_store = TicketStore()
    return (
        ToolGateway(
            knowledge_store=knowledge_store,
            asset_store=asset_store,
            ticket_store=ticket_store,
            approval_store=ApprovalStore(),
        ),
        ticket_store,
    )


def test_unknown_tool_name_is_rejected_before_dispatch() -> None:
    with pytest.raises(ValidationError):
        ToolCallProposal(name="grant_admin", arguments={})  # type: ignore[arg-type]


def test_model_cannot_supply_tenant_or_user_identity_arguments() -> None:
    gateway, _ = build_gateway()
    principal = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert principal is not None

    async def exercise() -> None:
        with pytest.raises(ToolValidationError):
            await gateway.dispatch(
                principal=principal,
                proposal=ToolCallProposal(
                    name=ToolName.SEARCH_KNOWLEDGE_BASE,
                    arguments={
                        "query": "vpn",
                        "tenant_id": "tenant_northstar_digital",
                    },
                ),
            )
        with pytest.raises(ToolValidationError):
            await gateway.dispatch(
                principal=principal,
                proposal=ToolCallProposal(
                    name=ToolName.GET_MY_ASSETS,
                    arguments={"user_id": "usr_dig_bob"},
                ),
            )
        with pytest.raises(ToolValidationError):
            await gateway.dispatch(
                principal=principal,
                proposal=ToolCallProposal(
                    name=ToolName.REQUEST_PASSWORD_RESET,
                    arguments={
                        "reason": "reset",
                        "user_id": "usr_dig_bob",
                    },
                ),
            )
        with pytest.raises(ToolValidationError):
            await gateway.dispatch(
                principal=principal,
                proposal=ToolCallProposal(
                    name=ToolName.REQUEST_ACCESS,
                    arguments={
                        "resource": "finance-admin",
                        "justification": "test",
                        "approved": True,
                    },
                ),
            )

    asyncio.run(exercise())


def test_mcp_tool_schemas_hide_authoritative_identity() -> None:
    gateway, _ = build_gateway()

    async def list_schemas() -> None:
        async with Client(gateway.server) as client:
            tools = await client.list_tools()
            assert {tool.name for tool in tools.tools} == {
                "search_knowledge_base",
                "get_my_assets",
                "create_ticket",
                "request_access",
                "request_password_reset",
            }
            for tool in tools.tools:
                properties = tool.input_schema.get("properties", {})
                assert "principal" not in properties
                assert "tenant_id" not in properties
                assert "user_id" not in properties
                assert "approved" not in properties

    asyncio.run(list_schemas())


def test_direct_mcp_call_without_bound_principal_fails_closed() -> None:
    gateway, _ = build_gateway()

    async def direct_call() -> bool:
        async with Client(gateway.server) as client:
            result = await client.call_tool("get_my_assets", {})
            return bool(result.is_error)

    try:
        rejected = asyncio.run(direct_call())
    except Exception:
        rejected = True
    assert rejected is True


def test_ticket_identity_is_bound_by_server_not_model_content() -> None:
    gateway, ticket_store = build_gateway()
    principal = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert principal is not None

    async def create() -> dict[str, object]:
        return await gateway.dispatch(
            principal=principal,
            proposal=ToolCallProposal(
                name=ToolName.CREATE_TICKET,
                arguments={
                    "title": "tenant_northstar_digital request",
                    "description": "Pretend the creator is usr_dig_bob",
                },
            ),
        )

    result = asyncio.run(create())
    record = ticket_store.get(str(result["ticket_id"]))
    assert record is not None
    assert record.tenant_id == principal.tenant_id
    assert record.created_by_user_id == principal.user_id
