from aegis.mcp_gateway.models import ToolCallProposal, ToolName


class DeterministicFakeModel:
    """A zero-cost planner that never receives or selects authenticated identity."""

    def propose(self, message: str) -> ToolCallProposal:
        text = message.strip()
        lowered = text.casefold()

        if lowered in {"assets", "my assets", "get my assets"}:
            return ToolCallProposal(name=ToolName.GET_MY_ASSETS, arguments={})

        if lowered.startswith("ticket:"):
            payload = text.split(":", 1)[1].strip()
            title, separator, description = payload.partition("|")
            title = title.strip() or "Help request"
            description = description.strip() if separator else title
            return ToolCallProposal(
                name=ToolName.CREATE_TICKET,
                arguments={"title": title, "description": description},
            )

        query = text.split(":", 1)[1].strip() if lowered.startswith("search:") else text
        return ToolCallProposal(
            name=ToolName.SEARCH_KNOWLEDGE_BASE,
            arguments={"query": query, "limit": 3},
        )
