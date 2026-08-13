# P3-B: default agent execution budget

## Security property

Every default autonomous agent run receives a fresh server-owned P2-G `ExecutionBudget`. The model, request body, retrieved content, graph checkpoint, and tool result cannot choose or increase its limits. Before model planning or tool dispatch, and after tool output, the host enforces the configured input, context, step, model-call, tool-call, duplicate-call, retry, result-byte, and elapsed-time limits.

The default FastAPI path converts budget exhaustion into a generic fail-closed response without exposing internal counters or tool output.

## Trust boundary

`HTTP request -> server-owned execution budget -> deterministic model -> typed MCP gateway -> tool result`

Budget state is stored in a Python `ContextVar` owned by the host, not in LangGraph state. Each `run()` creates a new budget and resets the context in `finally`, including failed runs.

Human approval dwell time is not part of this autonomous execution window. High-impact execution after approval remains governed by the P3-A consolidated effect chain rather than by an agent-loop timer.

## Matched comparison

The intentionally weak P3-B comparison preserves the old default behavior: one typed tool call can execute, but there is no P2-G input/context/time/byte budget. The deterministic evaluation submits two otherwise valid local ticket requests: one exceeds the 1024-byte input ceiling and one fits that ceiling but exceeds the 900-byte model-context ceiling. The weak comparison executes them; the hardened default rejects before the corresponding planning/side-effect boundary. Two ordinary local tasks form the benign set.

No real accounts, credentials, external targets, paid model APIs, or network attacks are used.

## Residual risk

- The default graph is still one-shot and retains its older one-tool-call compatibility guard. P3-B adds the full P2-G accounting boundary but does not convert the default agent into a multi-step loop.
- The current default runner has no automatic retry loop, so its retry counter remains zero. Any future retry mechanism must explicitly call the budget retry accounting before another attempt.
- Result-size enforcement happens after a tool returns. It prevents oversized output from continuing through the agent, but cannot undo an already completed side effect. Side-effecting tools therefore still require their own authorization and idempotency controls.
- These budgets are process-local. They are not distributed per-tenant quotas, API rate limits, or cross-replica concurrency controls.
- A Python byte/time budget does not replace OS/container memory, CPU, file-descriptor, process, or network quotas.
- Production model/tool calls need cancellable deadlines and timeout propagation so a blocked remote call cannot consume resources beyond the host's intended deadline.
