from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from aegis.agent.default_budgeted_runner import DefaultBudgetedAgentRunner
from aegis.agent.execution_budget import byte_size
from aegis.agent.graph import AgentState
from aegis.identity.models import Principal
from aegis.mcp_gateway.models import ToolCallProposal, ToolName
from aegis.memory.models import MemoryRecord
from aegis.memory.store import SqliteMemoryStore


P3E_MEMORY_POLICY_VERSION = "default-memory-data-not-authority-v1"
_MEMORY_CONTEXT_LABEL = "untrusted_user_memory"


@dataclass(frozen=True)
class PlanningMemoryContext:
    notes: tuple[str, ...]
    rendered_context: str


class DefaultMemoryContextService:
    """Default-runtime durable memory that can affect context, never authority.

    Stored content is retrieved only with the current server-derived Principal. The
    only planner influence implemented here is additional text in a read-only search
    query. Memory never chooses the tool, Principal, tenant, roles, approval state,
    or downstream authorization material.
    """

    policy_version = P3E_MEMORY_POLICY_VERSION

    def __init__(self, store: SqliteMemoryStore, *, max_planning_records: int = 3) -> None:
        if max_planning_records < 1:
            raise ValueError("max_planning_records must be positive")
        self._store = store
        self._max_planning_records = max_planning_records

    @property
    def store(self) -> SqliteMemoryStore:
        return self._store

    def remember(self, *, principal: Principal, content: str) -> MemoryRecord:
        return self._store.remember(principal=principal, content=content)

    def recall(self, *, principal: Principal, limit: int = 50) -> list[MemoryRecord]:
        return self._store.list_for_principal(principal=principal, limit=limit)

    @staticmethod
    def _render(message: str, notes: tuple[str, ...]) -> str:
        return json.dumps(
            {
                "user_message": message,
                _MEMORY_CONTEXT_LABEL: list(notes),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def planning_context(
        self,
        *,
        principal: Principal,
        message: str,
        max_context_bytes: int,
    ) -> PlanningMemoryContext:
        records = self.recall(principal=principal, limit=100)
        candidates = [record.content for record in records[-self._max_planning_records :]]
        candidates.reverse()  # newest first

        selected: list[str] = []
        base = self._render(message, ())
        if byte_size(base) > max_context_bytes:
            return PlanningMemoryContext(notes=(), rendered_context=base)

        for content in candidates:
            fitted = self._fit_note(
                message=message,
                selected=tuple(selected),
                content=content,
                max_context_bytes=max_context_bytes,
            )
            if fitted:
                selected.append(fitted)

        notes = tuple(selected)
        return PlanningMemoryContext(
            notes=notes,
            rendered_context=self._render(message, notes),
        )

    def _fit_note(
        self,
        *,
        message: str,
        selected: tuple[str, ...],
        content: str,
        max_context_bytes: int,
    ) -> str:
        if byte_size(self._render(message, selected + (content,))) <= max_context_bytes:
            return content

        low = 0
        high = len(content)
        best = ""
        while low <= high:
            midpoint = (low + high) // 2
            candidate = content[:midpoint]
            rendered = self._render(message, selected + (candidate,))
            if byte_size(rendered) <= max_context_bytes:
                best = candidate
                low = midpoint + 1
            else:
                high = midpoint - 1
        return best

    def enrich_proposal(
        self,
        *,
        proposal: ToolCallProposal,
        context: PlanningMemoryContext,
    ) -> ToolCallProposal:
        # The base model chooses the tool from the current user message only. Durable
        # memory is allowed to influence data-plane search text after that decision.
        if proposal.name is not ToolName.SEARCH_KNOWLEDGE_BASE or not context.notes:
            return proposal

        arguments: dict[str, Any] = dict(proposal.arguments)
        query = str(arguments["query"])
        memory_blob = json.dumps(
            list(context.notes),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        arguments["query"] = (
            f"{query}\n{_MEMORY_CONTEXT_LABEL}={memory_blob}"
        )
        return proposal.model_copy(update={"arguments": arguments})


class DefaultMemoryAwareAgentRunner(DefaultBudgetedAgentRunner):
    """Budgeted agent runner with principal-scoped durable memory context."""

    def __init__(
        self,
        *,
        memory_context: DefaultMemoryContextService,
        **kwargs: Any,
    ) -> None:
        self._memory_context = memory_context
        super().__init__(**kwargs)

    @property
    def memory_policy_version(self) -> str:
        return self._memory_context.policy_version

    @property
    def memory_context(self) -> DefaultMemoryContextService:
        return self._memory_context

    def _plan(self, state: AgentState) -> dict[str, ToolCallProposal]:
        context = self._memory_context.planning_context(
            principal=state["principal"],
            message=state["message"],
            max_context_bytes=self._execution_limits.max_context_bytes,
        )
        self._budget().before_model(context.rendered_context)

        # Critical authority split: the planner receives the current message as its
        # tool-selection input. Memory can only enrich the already-selected read-only
        # search query through DefaultMemoryContextService.enrich_proposal().
        proposal = self._model.propose(state["message"])
        return {
            "proposal": self._memory_context.enrich_proposal(
                proposal=proposal,
                context=context,
            )
        }
