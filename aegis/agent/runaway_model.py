from dataclasses import dataclass

from aegis.mcp_gateway.models import ToolCallProposal, ToolName


RUNAWAY_MODEL_ID = "deterministic-runaway-agent-model-v1"
RUNAWAY_PROMPT_VERSION = "p2g-agent-loop-v1"


@dataclass(frozen=True)
class RunawayDecision:
    proposal: ToolCallProposal | None


class DeterministicRunawayModel:
    """Zero-cost planner with deterministic benign and runaway behaviors."""

    model_id = RUNAWAY_MODEL_ID
    prompt_version = RUNAWAY_PROMPT_VERSION

    def propose(self, *, message: str, iteration: int) -> RunawayDecision:
        if message == "attack:duplicate-ticket":
            return RunawayDecision(
                proposal=ToolCallProposal(
                    name=ToolName.CREATE_TICKET,
                    arguments={
                        "title": "Synthetic loop ticket",
                        "description": "Repeated by the deterministic P2-G loop model",
                    },
                )
            )

        if message == "attack:context-growth":
            return RunawayDecision(
                proposal=ToolCallProposal(
                    name=ToolName.SEARCH_KNOWLEDGE_BASE,
                    arguments={
                        "query": f"vpn setup deterministic-loop-{iteration}",
                        "limit": 2,
                    },
                )
            )

        if message == "benign:ticket":
            if iteration == 0:
                return RunawayDecision(
                    proposal=ToolCallProposal(
                        name=ToolName.CREATE_TICKET,
                        arguments={
                            "title": "Synthetic benign ticket",
                            "description": "One expected help-desk action",
                        },
                    )
                )
            return RunawayDecision(proposal=None)

        if message == "benign:search":
            if iteration == 0:
                return RunawayDecision(
                    proposal=ToolCallProposal(
                        name=ToolName.SEARCH_KNOWLEDGE_BASE,
                        arguments={"query": "vpn setup", "limit": 1},
                    )
                )
            return RunawayDecision(proposal=None)

        return RunawayDecision(proposal=None)
