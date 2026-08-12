from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from aegis.mcp_gateway.models import ToolCallProposal


class BudgetDimension(StrEnum):
    STEPS = "steps"
    MODEL_CALLS = "model_calls"
    TOOL_CALLS = "tool_calls"
    RETRIES = "retries"
    INPUT_BYTES = "input_bytes"
    CONTEXT_BYTES = "context_bytes"
    RESULT_BYTES = "result_bytes"
    ELAPSED_MS = "elapsed_ms"
    SAME_TOOL_CALLS = "same_tool_call_count"


class BudgetExceeded(RuntimeError):
    def __init__(self, *, dimension: BudgetDimension, limit: int, observed: int) -> None:
        self.dimension = dimension
        self.limit = limit
        self.observed = observed
        super().__init__(
            f"resource budget exceeded for {dimension.value}: observed {observed}, limit {limit}"
        )


@dataclass(frozen=True)
class AgentExecutionLimits:
    max_steps: int = 20
    max_model_calls: int = 8
    max_tool_calls: int = 5
    max_retries: int = 2
    max_input_bytes: int = 1024
    max_context_bytes: int = 900
    max_result_bytes: int = 4096
    max_elapsed_ms: int = 5000
    max_same_tool_call_count: int = 1

    def __post_init__(self) -> None:
        positive = (
            self.max_steps,
            self.max_model_calls,
            self.max_tool_calls,
            self.max_input_bytes,
            self.max_context_bytes,
            self.max_result_bytes,
            self.max_elapsed_ms,
            self.max_same_tool_call_count,
        )
        if any(value <= 0 for value in positive):
            raise ValueError("positive execution limits must be greater than zero")
        if self.max_retries < 0:
            raise ValueError("max_retries must be zero or greater")


P2G_EXECUTION_LIMITS = AgentExecutionLimits()
P2G_POLICY_VERSION = "server-owned-agent-budget-v1"


@dataclass(frozen=True)
class BudgetSnapshot:
    steps: int
    model_calls: int
    tool_calls: int
    retries: int
    result_bytes: int
    max_context_bytes_observed: int
    elapsed_ms: int


ClockMs = Callable[[], int]


def monotonic_ms() -> int:
    return time.monotonic_ns() // 1_000_000


def byte_size(value: Any) -> int:
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    rendered = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return len(rendered.encode("utf-8"))


def proposal_fingerprint(proposal: ToolCallProposal) -> str:
    payload = proposal.model_dump(mode="json")
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class ExecutionBudget:
    """Server-owned resource budget for one agent execution."""

    def __init__(
        self,
        *,
        limits: AgentExecutionLimits,
        clock_ms: ClockMs = monotonic_ms,
    ) -> None:
        self.limits = limits
        self._clock_ms = clock_ms
        self._started_ms = clock_ms()
        self._steps = 0
        self._model_calls = 0
        self._tool_calls = 0
        self._retries = 0
        self._result_bytes = 0
        self._max_context_bytes_observed = 0
        self._same_call_counts: dict[str, int] = {}

    def validate_input(self, text: str) -> None:
        self._check_elapsed()
        self._require(
            BudgetDimension.INPUT_BYTES,
            byte_size(text),
            self.limits.max_input_bytes,
        )

    def before_model(self, context: str) -> None:
        self._check_elapsed()
        context_bytes = byte_size(context)
        self._max_context_bytes_observed = max(
            self._max_context_bytes_observed,
            context_bytes,
        )
        self._require(
            BudgetDimension.CONTEXT_BYTES,
            context_bytes,
            self.limits.max_context_bytes,
        )
        self._consume_step()
        next_calls = self._model_calls + 1
        self._require(
            BudgetDimension.MODEL_CALLS,
            next_calls,
            self.limits.max_model_calls,
        )
        self._model_calls = next_calls

    def before_tool(self, proposal: ToolCallProposal) -> None:
        self._check_elapsed()
        next_calls = self._tool_calls + 1
        self._require(
            BudgetDimension.TOOL_CALLS,
            next_calls,
            self.limits.max_tool_calls,
        )

        fingerprint = proposal_fingerprint(proposal)
        same_count = self._same_call_counts.get(fingerprint, 0) + 1
        self._require(
            BudgetDimension.SAME_TOOL_CALLS,
            same_count,
            self.limits.max_same_tool_call_count,
        )

        self._consume_step()
        self._tool_calls = next_calls
        self._same_call_counts[fingerprint] = same_count

    def after_tool(self, result: dict[str, Any]) -> None:
        self._check_elapsed()
        next_bytes = self._result_bytes + byte_size(result)
        self._require(
            BudgetDimension.RESULT_BYTES,
            next_bytes,
            self.limits.max_result_bytes,
        )
        self._result_bytes = next_bytes

    def record_retry(self) -> None:
        self._check_elapsed()
        next_retries = self._retries + 1
        self._require(
            BudgetDimension.RETRIES,
            next_retries,
            self.limits.max_retries,
        )
        self._consume_step()
        self._retries = next_retries

    def snapshot(self) -> BudgetSnapshot:
        return BudgetSnapshot(
            steps=self._steps,
            model_calls=self._model_calls,
            tool_calls=self._tool_calls,
            retries=self._retries,
            result_bytes=self._result_bytes,
            max_context_bytes_observed=self._max_context_bytes_observed,
            elapsed_ms=max(0, self._clock_ms() - self._started_ms),
        )

    def _consume_step(self) -> None:
        next_steps = self._steps + 1
        self._require(
            BudgetDimension.STEPS,
            next_steps,
            self.limits.max_steps,
        )
        self._steps = next_steps

    def _check_elapsed(self) -> None:
        elapsed = max(0, self._clock_ms() - self._started_ms)
        self._require(
            BudgetDimension.ELAPSED_MS,
            elapsed,
            self.limits.max_elapsed_ms,
        )

    @staticmethod
    def _require(
        dimension: BudgetDimension,
        observed: int,
        limit: int,
    ) -> None:
        if observed > limit:
            raise BudgetExceeded(
                dimension=dimension,
                observed=observed,
                limit=limit,
            )
