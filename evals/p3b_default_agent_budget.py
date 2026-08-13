from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

from aegis.agent.default_budgeted_runner import DefaultBudgetedAgentRunner
from aegis.agent.execution_budget import BudgetExceeded, P2G_EXECUTION_LIMITS, byte_size
from aegis.agent.fake_model import DeterministicFakeModel
from aegis.approvals.store import ApprovalStore
from aegis.helpdesk.stores import AssetStore, TicketStore
from aegis.identity.models import Principal, Role
from aegis.mcp_gateway.gateway import ToolGateway
from aegis.rag.store import KnowledgeStore
from aegis.vulnerable.p3b_partial_agent_budget import VulnerablePartialAgentRunner


ROOT = Path(__file__).resolve().parents[1]
ALICE = Principal(user_id="usr_dyn_alice", tenant_id="tenant_northstar_dynamics", roles=frozenset({Role.EMPLOYEE}))
CASES = (
    ("P3B-A1", "oversized_input_before_planning", 100, 1000, False),
    ("P3B-A2", "oversized_context_before_model", 50, 850, False),
    ("P3B-B1", "normal_ticket", 12, 30, True),
    ("P3B-B2", "normal_assets", 0, 0, True),
)


def _message(case) -> str:
    if case[1] == "normal_assets":
        return "assets"
    return f"ticket: {'T' * case[2]} | {'D' * case[3]}"


def _dataset_hash() -> str:
    raw = json.dumps(CASES, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def _stores():
    approvals = ApprovalStore()
    tickets = TicketStore()
    gateway = ToolGateway(
        knowledge_store=KnowledgeStore.from_json(ROOT / "synthetic_data" / "knowledge.json"),
        asset_store=AssetStore.from_json(ROOT / "synthetic_data" / "assets.json"),
        ticket_store=tickets,
        approval_store=approvals,
    )
    return approvals, tickets, gateway


def _runner(hardened: bool):
    approvals, tickets, gateway = _stores()
    model = DeterministicFakeModel()
    if hardened:
        runner = DefaultBudgetedAgentRunner(model=model, gateway=gateway, approval_store=approvals)
    else:
        runner = VulnerablePartialAgentRunner(model=model, gateway=gateway)
    return runner, tickets


async def _case(spec, hardened: bool) -> dict:
    runner, _tickets = _runner(hardened)
    message = _message(spec)
    tool = None
    rejection = None
    try:
        outcome = await runner.run(principal=ALICE, message=message)
        tool = outcome.tool.value
    except BudgetExceeded as exc:
        rejection = exc.dimension.value
    if spec[4]:
        return {
            "attempt_id": spec[0], "scenario": spec[1], "valid": True,
            "input_bytes": byte_size(message), "incorrectly_blocked": rejection is not None,
            "safe_completion": rejection is None and tool is not None, "tool": tool,
        }
    return {
        "attempt_id": spec[0], "scenario": spec[1], "valid": True,
        "input_bytes": byte_size(message), "success": rejection is None and tool is not None,
        "rejection": rejection, "tool": tool,
    }


def main() -> None:
    print(json.dumps({"evaluation": "P3-B default AgentRunner execution budget integration", "eval_dataset_hash_sha256": _dataset_hash()}, indent=2))


if __name__ == "__main__":
    main()
