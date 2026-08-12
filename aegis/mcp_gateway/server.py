from typing import Annotated

from mcp.server import MCPServer
from mcp.server.mcpserver import Resolve

from aegis.approvals.models import ApprovalAction
from aegis.approvals.store import ApprovalStore
from aegis.helpdesk.stores import AssetStore, TicketStore
from aegis.identity.models import Principal
from aegis.mcp_gateway.models import (
    ApprovalRequestOutput,
    CreateTicketOutput,
    GetMyAssetsOutput,
    SearchKnowledgeBaseOutput,
)
from aegis.mcp_gateway.security_context import require_bound_principal
from aegis.rag.models import SearchResult
from aegis.rag.store import KnowledgeStore


PrincipalDependency = Annotated[Principal, Resolve(require_bound_principal)]


def build_mcp_server(
    *,
    knowledge_store: KnowledgeStore,
    asset_store: AssetStore,
    ticket_store: TicketStore,
    approval_store: ApprovalStore,
) -> MCPServer:
    mcp = MCPServer("AegisDesk Tools")

    @mcp.tool()
    def search_knowledge_base(
        query: str,
        principal: PrincipalDependency,
        limit: int = 3,
    ) -> SearchKnowledgeBaseOutput:
        """Search only the authenticated principal's tenant knowledge base."""
        documents = knowledge_store.search(principal=principal, query=query, limit=limit)
        return SearchKnowledgeBaseOutput(
            results=[
                SearchResult(
                    document_id=document.document_id,
                    title=document.title,
                    text=document.text,
                )
                for document in documents
            ]
        )

    @mcp.tool()
    def get_my_assets(principal: PrincipalDependency) -> GetMyAssetsOutput:
        """Return assets assigned to the authenticated principal only."""
        return GetMyAssetsOutput(assets=asset_store.get_my_assets(principal))

    @mcp.tool()
    def create_ticket(
        title: str,
        description: str,
        principal: PrincipalDependency,
    ) -> CreateTicketOutput:
        """Create a help-desk ticket for the authenticated principal's tenant."""
        record = ticket_store.create(
            principal=principal,
            title=title,
            description=description,
        )
        return CreateTicketOutput(
            ticket_id=record.ticket_id,
            status=record.status,
            title=record.title,
        )

    @mcp.tool()
    def request_access(
        resource: str,
        justification: str,
        principal: PrincipalDependency,
    ) -> ApprovalRequestOutput:
        """Create a pending access request. This tool never grants access."""
        record = approval_store.create(
            requester=principal,
            action=ApprovalAction.REQUEST_ACCESS,
            arguments={
                "resource": resource,
                "justification": justification,
            },
        )
        return ApprovalRequestOutput(
            approval_id=record.approval_id,
            action=record.action.value,
            status=record.status.value,
            expires_at=record.expires_at.isoformat(),
        )

    @mcp.tool()
    def request_password_reset(
        reason: str,
        principal: PrincipalDependency,
    ) -> ApprovalRequestOutput:
        """Create a pending password-reset request. This tool never resets credentials."""
        record = approval_store.create(
            requester=principal,
            action=ApprovalAction.REQUEST_PASSWORD_RESET,
            arguments={"reason": reason},
        )
        return ApprovalRequestOutput(
            approval_id=record.approval_id,
            action=record.action.value,
            status=record.status.value,
            expires_at=record.expires_at.isoformat(),
        )

    return mcp
