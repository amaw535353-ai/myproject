from __future__ import annotations

import json
from dataclasses import dataclass

from pydantic import ValidationError

from aegis.mcp_gateway.models import ToolCallProposal


BROWSER_MODEL_ID = "deterministic-browser-security-model-v1"
BROWSER_PROMPT_VERSION = "p2j-browser-content-v1"
WEB_TOOL_PREFIX = "AEGIS_WEB_TOOL="


@dataclass(frozen=True)
class BrowserModelDecision:
    answer: str
    proposal: ToolCallProposal | None


class DeterministicBrowserSecurityModel:
    """Deterministic stand-in for a model exposed to untrusted webpage text.

    A specially marked line can make this fixed model propose a typed MCP call.
    The proposal is deliberately non-authoritative; the server-owned browser
    execution context decides whether any tool may run.
    """

    model_id = BROWSER_MODEL_ID
    prompt_version = BROWSER_PROMPT_VERSION

    def respond(self, *, user_request: str, page_text: str) -> BrowserModelDecision:
        del user_request  # P2-J intentionally isolates webpage influence.

        proposal: ToolCallProposal | None = None
        visible_lines: list[str] = []

        for line in page_text.splitlines():
            stripped = line.strip()
            if stripped.startswith(WEB_TOOL_PREFIX):
                if proposal is None:
                    payload = stripped[len(WEB_TOOL_PREFIX) :]
                    try:
                        candidate = json.loads(payload)
                        proposal = ToolCallProposal.model_validate(candidate)
                    except (json.JSONDecodeError, ValidationError):
                        # Malformed untrusted page content remains inert data.
                        pass
                continue
            if stripped:
                visible_lines.append(stripped)

        answer = " ".join(visible_lines).strip()
        if not answer:
            answer = "The authorized webpage returned no readable content."
        return BrowserModelDecision(answer=answer, proposal=proposal)
