import pytest

from aegis.agent.execution_budget import (
    AgentExecutionLimits,
    BudgetDimension,
    BudgetExceeded,
    ExecutionBudget,
)
from aegis.mcp_gateway.models import ToolCallProposal, ToolName


def proposal() -> ToolCallProposal:
    return ToolCallProposal(
        name=ToolName.CREATE_TICKET,
        arguments={"title": "A", "description": "B"},
    )


def test_budget_accepts_small_benign_execution() -> None:
    budget = ExecutionBudget(limits=AgentExecutionLimits())
    budget.validate_input("hello")
    budget.before_model("hello")
    budget.before_tool(proposal())
    budget.after_tool({"ok": True})
    snapshot = budget.snapshot()
    assert snapshot.model_calls == 1
    assert snapshot.tool_calls == 1
    assert snapshot.result_bytes > 0


def test_duplicate_tool_call_fails_closed() -> None:
    budget = ExecutionBudget(
        limits=AgentExecutionLimits(max_same_tool_call_count=1)
    )
    budget.before_tool(proposal())
    with pytest.raises(BudgetExceeded) as exc:
        budget.before_tool(proposal())
    assert exc.value.dimension is BudgetDimension.SAME_TOOL_CALLS


def test_context_bytes_are_bounded() -> None:
    budget = ExecutionBudget(limits=AgentExecutionLimits(max_context_bytes=8))
    with pytest.raises(BudgetExceeded) as exc:
        budget.before_model("0123456789")
    assert exc.value.dimension is BudgetDimension.CONTEXT_BYTES


def test_model_calls_are_bounded() -> None:
    budget = ExecutionBudget(limits=AgentExecutionLimits(max_model_calls=1))
    budget.before_model("a")
    with pytest.raises(BudgetExceeded) as exc:
        budget.before_model("a")
    assert exc.value.dimension is BudgetDimension.MODEL_CALLS


def test_tool_calls_are_bounded_for_unique_calls() -> None:
    budget = ExecutionBudget(
        limits=AgentExecutionLimits(
            max_tool_calls=1,
            max_same_tool_call_count=2,
        )
    )
    budget.before_tool(proposal())
    second = ToolCallProposal(
        name=ToolName.CREATE_TICKET,
        arguments={"title": "C", "description": "D"},
    )
    with pytest.raises(BudgetExceeded) as exc:
        budget.before_tool(second)
    assert exc.value.dimension is BudgetDimension.TOOL_CALLS


def test_retry_budget_is_bounded() -> None:
    budget = ExecutionBudget(limits=AgentExecutionLimits(max_retries=1))
    budget.record_retry()
    with pytest.raises(BudgetExceeded) as exc:
        budget.record_retry()
    assert exc.value.dimension is BudgetDimension.RETRIES


def test_cumulative_result_bytes_are_bounded() -> None:
    budget = ExecutionBudget(limits=AgentExecutionLimits(max_result_bytes=12))
    budget.after_tool({"a": "b"})
    with pytest.raises(BudgetExceeded) as exc:
        budget.after_tool({"c": "0123456789"})
    assert exc.value.dimension is BudgetDimension.RESULT_BYTES


def test_input_bytes_are_bounded() -> None:
    budget = ExecutionBudget(limits=AgentExecutionLimits(max_input_bytes=4))
    with pytest.raises(BudgetExceeded) as exc:
        budget.validate_input("hello")
    assert exc.value.dimension is BudgetDimension.INPUT_BYTES


def test_elapsed_time_is_bounded_with_injected_clock() -> None:
    now = [100]

    def clock() -> int:
        return now[0]

    budget = ExecutionBudget(
        limits=AgentExecutionLimits(max_elapsed_ms=10),
        clock_ms=clock,
    )
    now[0] = 111
    with pytest.raises(BudgetExceeded) as exc:
        budget.validate_input("ok")
    assert exc.value.dimension is BudgetDimension.ELAPSED_MS
