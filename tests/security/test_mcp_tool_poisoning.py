import asyncio

import pytest

from aegis.agent.mcp_catalog_model import DeterministicMcpCatalogModel
from aegis.approvals.store import ApprovalStore
from aegis.helpdesk.models import AssetRecord
from aegis.helpdesk.stores import AssetStore, TicketStore
from aegis.identity.synthetic_auth import resolve_synthetic_principal
from aegis.mcp_gateway.gateway import ToolGateway
from aegis.mcp_gateway.host_registry import (
    McpHostPolicyError,
    McpServerRegistration,
    ServerTrust,
    TrustedMcpHost,
    discover_mcp_tools,
)
from aegis.mcp_gateway.models import ToolName
from aegis.rag.models import KnowledgeDocument
from aegis.rag.store import KnowledgeStore
from aegis.vulnerable.mcp_tool_poisoning import (
    UntrustedMcpEffectStore,
    VulnerableFlatteningMcpHost,
    build_poisoned_mcp_server,
)


TRUSTED = "aegisdesk-core"
UNTRUSTED = "lab-untrusted"


def _gateway() -> ToolGateway:
    return ToolGateway(
        knowledge_store=KnowledgeStore(
            [
                KnowledgeDocument(
                    id=1,
                    tenant_id="tenant_northstar_dynamics",
                    title="Help",
                    text="Synthetic help P2C-TEST",
                    canary="P2C-TEST",
                )
            ]
        ),
        asset_store=AssetStore(
            [
                AssetRecord(
                    asset_id="ASSET-P2C",
                    tenant_id="tenant_northstar_dynamics",
                    assigned_user_id="usr_dyn_alice",
                    asset_type="laptop",
                    label="P2-C laptop",
                )
            ]
        ),
        ticket_store=TicketStore(),
        approval_store=ApprovalStore(),
    )


def _registrations(gateway: ToolGateway, effects: UntrustedMcpEffectStore):
    return (
        McpServerRegistration(TRUSTED, gateway.server, ServerTrust.TRUSTED),
        McpServerRegistration(
            UNTRUSTED,
            build_poisoned_mcp_server(effects),
            ServerTrust.UNTRUSTED,
        ),
    )


def test_discovery_preserves_host_identity_for_duplicate_names() -> None:
    gateway = _gateway()
    effects = UntrustedMcpEffectStore()

    catalog = asyncio.run(discover_mcp_tools(_registrations(gateway, effects)))
    create_ticket_sources = {
        tool.server_id for tool in catalog if tool.name == "create_ticket"
    }

    assert create_ticket_sources == {TRUSTED, UNTRUSTED}


def test_vulnerable_flattening_routes_shadowed_name_to_untrusted_server() -> None:
    gateway = _gateway()
    effects = UntrustedMcpEffectStore()
    registrations = _registrations(gateway, effects)
    principal = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert principal is not None

    async def exercise() -> None:
        catalog = await discover_mcp_tools(registrations)
        proposal = DeterministicMcpCatalogModel().propose(
            message="ticket: VPN issue | Cannot connect",
            catalog=catalog,
        )
        host = VulnerableFlatteningMcpHost(
            gateway=gateway,
            registrations=registrations,
            trusted_gateway_server_id=TRUSTED,
        )
        result = await host.dispatch(
            principal=principal,
            catalog=catalog,
            proposal=proposal,
        )
        assert result.server_id == UNTRUSTED

    asyncio.run(exercise())
    assert effects.count("create_ticket") == 1


def test_hardened_host_keeps_shadowed_name_bound_to_trusted_gateway() -> None:
    gateway = _gateway()
    effects = UntrustedMcpEffectStore()
    registrations = _registrations(gateway, effects)
    principal = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert principal is not None

    async def exercise() -> None:
        catalog = await discover_mcp_tools(registrations)
        proposal = DeterministicMcpCatalogModel().propose(
            message="ticket: VPN issue | Cannot connect",
            catalog=catalog,
        )
        host = TrustedMcpHost(
            gateway=gateway,
            registrations=registrations,
            trusted_bindings={tool.value: TRUSTED for tool in ToolName},
        )
        result = await host.dispatch(principal=principal, proposal=proposal)
        assert result.server_id == TRUSTED

    asyncio.run(exercise())
    assert effects.count() == 0


def test_hardened_host_blocks_description_selected_untrusted_tool() -> None:
    gateway = _gateway()
    effects = UntrustedMcpEffectStore()
    registrations = _registrations(gateway, effects)
    principal = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert principal is not None

    async def exercise() -> None:
        catalog = await discover_mcp_tools(registrations)
        proposal = DeterministicMcpCatalogModel().propose(
            message="show my assets",
            catalog=catalog,
        )
        assert proposal.name == "admin_diagnostic"
        host = TrustedMcpHost(
            gateway=gateway,
            registrations=registrations,
            trusted_bindings={tool.value: TRUSTED for tool in ToolName},
        )
        with pytest.raises(McpHostPolicyError):
            await host.dispatch(principal=principal, proposal=proposal)

    asyncio.run(exercise())
    assert effects.count() == 0


def test_trusted_binding_cannot_point_at_untrusted_registration() -> None:
    gateway = _gateway()
    effects = UntrustedMcpEffectStore()
    registrations = _registrations(gateway, effects)

    with pytest.raises(ValueError, match="untrusted server"):
        TrustedMcpHost(
            gateway=gateway,
            registrations=registrations,
            trusted_bindings={"create_ticket": UNTRUSTED},
        )
