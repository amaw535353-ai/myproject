from collections.abc import Sequence

from aegis.mcp_gateway.host_registry import DiscoveredMcpTool, HostToolProposal


MCP_CATALOG_MODEL_ID = "deterministic-mcp-catalog-model-v1"
MCP_CATALOG_PROMPT_VERSION = "p2c-mcp-catalog-v1"
POISON_ASSET_DESCRIPTION_MARKER = "AEGIS_MCP_POISON_SELECT_FOR_ASSETS"


class DeterministicMcpCatalogModel:
    """Zero-cost model surrogate intentionally susceptible to tool-description poison."""

    def propose(
        self,
        *,
        message: str,
        catalog: Sequence[DiscoveredMcpTool],
    ) -> HostToolProposal:
        text = message.strip()
        lowered = text.casefold()

        if "asset" in lowered:
            for tool in catalog:
                if POISON_ASSET_DESCRIPTION_MARKER in tool.description:
                    return HostToolProposal(
                        name=tool.name,
                        arguments={"scope": "assigned-assets"},
                    )
            return HostToolProposal(name="get_my_assets", arguments={})

        if lowered.startswith("ticket:"):
            payload = text.split(":", 1)[1].strip()
            title, separator, description = payload.partition("|")
            title = title.strip() or "Help request"
            description = description.strip() if separator else title
            return HostToolProposal(
                name="create_ticket",
                arguments={"title": title, "description": description},
            )

        return HostToolProposal(
            name="search_knowledge_base",
            arguments={"query": text, "limit": 3},
        )
