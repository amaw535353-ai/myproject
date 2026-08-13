from __future__ import annotations

from aegis.browser.answering import (
    BrowserAnswerOutcome,
    BrowserPageReader,
    BrowserToolStatus,
)
from aegis.identity.models import Principal
from aegis.mcp_gateway.gateway import ToolGateway


class VulnerableBrowserAnswerRunner:
    """Intentionally vulnerable P2-J baseline.

    It uses the same safe synthetic network fetcher and deterministic browser
    model as the hardened runner, but blindly treats a proposal originating only
    from webpage content as execution authority.
    """

    def __init__(self, *, reader: BrowserPageReader, gateway: ToolGateway) -> None:
        self._reader = reader
        self._gateway = gateway

    async def answer(
        self,
        *,
        principal: Principal,
        url: str,
        user_request: str,
    ) -> BrowserAnswerOutcome:
        read = self._reader.read(url=url, user_request=user_request)
        proposal = read.decision.proposal

        if proposal is None:
            return BrowserAnswerOutcome(
                answer=read.decision.answer,
                final_url=read.fetch.final_url,
                visited_urls=read.fetch.visited_urls,
                connected_ips=read.fetch.connected_ips,
                proposal=None,
                tool_status=BrowserToolStatus.NONE,
                tool_result=None,
            )

        result = await self._gateway.dispatch(principal=principal, proposal=proposal)
        return BrowserAnswerOutcome(
            answer=read.decision.answer,
            final_url=read.fetch.final_url,
            visited_urls=read.fetch.visited_urls,
            connected_ips=read.fetch.connected_ips,
            proposal=proposal,
            tool_status=BrowserToolStatus.EXECUTED,
            tool_result=result,
        )
