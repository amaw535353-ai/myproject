from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from aegis.browser.model import BrowserModelDecision, DeterministicBrowserSecurityModel
from aegis.identity.models import Principal
from aegis.mcp_gateway.gateway import ToolGateway
from aegis.mcp_gateway.models import ToolCallProposal
from aegis.network.fetcher import FetchResult, SafeUrlFetcher
from aegis.policy.tool_capabilities import ToolCapabilityDenied, ToolCapabilityPolicy


class BrowserContentError(RuntimeError):
    """Raised when fetched browser content cannot safely enter model context."""


class BrowserToolStatus(StrEnum):
    NONE = "none"
    BLOCKED = "blocked"
    EXECUTED = "executed"


@dataclass(frozen=True)
class BrowserReadResult:
    fetch: FetchResult
    decision: BrowserModelDecision


@dataclass(frozen=True)
class BrowserAnswerOutcome:
    answer: str
    final_url: str
    visited_urls: tuple[str, ...]
    connected_ips: tuple[str, ...]
    proposal: ToolCallProposal | None
    tool_status: BrowserToolStatus
    tool_result: dict[str, Any] | None


class BrowserPageReader:
    """Shared fetch/decode/model pipeline used by both P2-J variants.

    SafeUrlFetcher retains the P2-E network boundary. After a successful fetch,
    page bytes remain untrusted model context and do not gain tool authority.
    """

    def __init__(
        self,
        *,
        fetcher: SafeUrlFetcher,
        model: DeterministicBrowserSecurityModel,
    ) -> None:
        self._fetcher = fetcher
        self._model = model

    def read(self, *, url: str, user_request: str) -> BrowserReadResult:
        fetched = self._fetcher.fetch(url)
        if fetched.status_code < 200 or fetched.status_code >= 300:
            raise BrowserContentError("browser fetch did not return a successful response")
        try:
            page_text = fetched.body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise BrowserContentError("browser page must decode as UTF-8") from exc
        return BrowserReadResult(
            fetch=fetched,
            decision=self._model.respond(
                user_request=user_request,
                page_text=page_text,
            ),
        )


class BrowserAnswerRunner:
    """Hardened browser answer path with a server-owned capability boundary."""

    def __init__(
        self,
        *,
        reader: BrowserPageReader,
        gateway: ToolGateway,
        capability_policy: ToolCapabilityPolicy,
    ) -> None:
        self._reader = reader
        self._gateway = gateway
        self._capability_policy = capability_policy

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

        try:
            self._capability_policy.require_allowed(proposal)
        except ToolCapabilityDenied:
            return BrowserAnswerOutcome(
                answer=read.decision.answer,
                final_url=read.fetch.final_url,
                visited_urls=read.fetch.visited_urls,
                connected_ips=read.fetch.connected_ips,
                proposal=proposal,
                tool_status=BrowserToolStatus.BLOCKED,
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
