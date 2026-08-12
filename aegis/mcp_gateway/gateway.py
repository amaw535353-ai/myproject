from typing import Any

from mcp import Client
from pydantic import BaseModel, ValidationError

from aegis.approvals.store import ApprovalStore
from aegis.helpdesk.stores import AssetStore, TicketStore
from aegis.identity.models import Principal
from aegis.mcp_gateway.models import (
    CreateTicketArgs,
    GetMyAssetsArgs,
    RequestAccessArgs,
    RequestPasswordResetArgs,
    SearchKnowledgeBaseArgs,
    ToolCallProposal,
    ToolName,
)
from aegis.mcp_gateway.security_context import bind_principal, reset_principal
from aegis.mcp_gateway.server import build_mcp_server
from aegis.rag.store import KnowledgeStore


class ToolGatewayError(RuntimeError):
    pass


class ToolValidationError(ToolGatewayError):
    pass


class ToolExecutionError(ToolGatewayError):
    pass


_ARGUMENT_MODELS: dict[ToolName, type[BaseModel]] = {
    ToolName.SEARCH_KNOWLEDGE_BASE: SearchKnowledgeBaseArgs,
    ToolName.GET_MY_ASSETS: GetMyAssetsArgs,
    ToolName.CREATE_TICKET: CreateTicketArgs,
    ToolName.REQUEST_ACCESS: RequestAccessArgs,
    ToolName.REQUEST_PASSWORD_RESET: RequestPasswordResetArgs,
}


class ToolGateway:
    def __init__(
        self,
        *,
        knowledge_store: KnowledgeStore,
        asset_store: AssetStore,
        ticket_store: TicketStore,
        approval_store: ApprovalStore,
    ) -> None:
        self.server = build_mcp_server(
            knowledge_store=knowledge_store,
            asset_store=asset_store,
            ticket_store=ticket_store,
            approval_store=approval_store,
        )

    def normalize_proposal(self, proposal: ToolCallProposal) -> ToolCallProposal:
        """Validate and canonicalize model-visible arguments before execution/state save."""
        argument_model = _ARGUMENT_MODELS[proposal.name]
        try:
            validated = argument_model.model_validate(proposal.arguments)
        except ValidationError as exc:
            raise ToolValidationError(
                f"invalid arguments for tool {proposal.name.value}"
            ) from exc
        return proposal.model_copy(update={"arguments": validated.model_dump()})

    async def dispatch(
        self,
        *,
        principal: Principal,
        proposal: ToolCallProposal,
    ) -> dict[str, Any]:
        normalized = self.normalize_proposal(proposal)

        token = bind_principal(principal)
        try:
            async with Client(self.server) as client:
                result = await client.call_tool(
                    normalized.name.value,
                    normalized.arguments,
                )
        finally:
            reset_principal(token)

        if result.is_error:
            raise ToolExecutionError(f"tool {normalized.name.value} failed")
        if result.structured_content is None:
            raise ToolExecutionError(
                f"tool {normalized.name.value} returned no structured output"
            )
        return dict(result.structured_content)
