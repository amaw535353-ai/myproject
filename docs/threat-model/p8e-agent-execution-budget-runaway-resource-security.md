# P8-E threat model — agent execution budget, resource, and runaway-execution security

## Scope

P8-E models resource safety for agentic execution. It treats model/tool call counts, token consumption, synthetic policy-derived cost, wall-clock duration, agent steps, recursion depth, fan-out, retries, repeated operations, irreversible actions, and delegated budget allocations as security-sensitive state.

The analyzer is deterministic and synthetic. It does not terminate live processes, charge provider accounts, execute external tools, or query cloud billing systems.

## Security objective

A caller must not be able to convert runaway or over-budget execution into an allowed result by declaring that a run stayed within budget, that cost was zero, or that no loop/resource exhaustion occurred.

Every run must remain bounded by the root budget and every delegated sub-budget. Delegated budgets must not amplify the parent authority or oversubscribe additive parent capacity. Resource accounting must be derived from exact execution events and policy-pinned model rates, then tied back to the original principal, tenant, goal, delegation, plan step, and P8-D tool observation.

## Canonical model

The fixture contains:

- model cost-rate records: **2**;
- budget envelopes: **8**;
- delegated budget allocations: **4**;
- execution runs: **4**;
- execution events: **10**.

The four clean runs align with the P8-D search, ticket mutation, release deployment, and telemetry configuration paths.

## Boundaries enforced

### Exact evidence binding

The analyzer requires exact manifest ID/version/SHA-256 and freshness plus exact P8-A, P8-C, and P8-D assessment evidence digests. It also requires the upstream evidence to retain the verification flags that make delegation, plan-step authorization, and tool-observation provenance trustworthy enough for this deterministic layer.

### Delegated budget non-amplification

Each child budget is compared with its parent across model calls, tool calls, token ceiling, synthetic cost ceiling, elapsed time, step count, recursion depth, fan-out, retry count, repeated-operation count, irreversible-action count, and irreversible-action rate.

Direct child budgets are also checked for additive oversubscription on model calls, tool calls, tokens, cost, step count, and irreversible-action count. A set of individually bounded child allocations therefore cannot reserve more additive capacity than the parent makes available.

### Model/tool/token/cost ceilings

Model calls and tool calls are counted from exact typed execution events. Tokens come only from model-call events. Cost is re-derived from policy-pinned synthetic model rates using input/output token counts; caller-owned cost claims must match the derived value.

The cost number is a deterministic test-unit estimate expressed in micro-USD. It is not a live provider bill and does not claim real-time price accuracy.

### Runaway execution detection

The event parent graph must be acyclic. P8-E derives:

- maximum execution depth;
- maximum fan-out of any event;
- retry count from the attempt number;
- repeated-operation count from the operation key; and
- total agent-step count.

These properties are compared against exact budget ceilings. This catches synthetic recursion overruns, fan-out explosions, retry storms, and repeated-operation loops.

### Irreversible-action rate limits

Irreversible tool events are counted both as a total and in a rolling 60-second window. This models a safety boundary where a fast sequence of state-changing actions can be denied even when the run has not yet exceeded a broader tool-call ceiling.

### Upstream safety continuity

Delegated events require an allowed P8-A delegation. Every execution event requires an allowed P8-C plan step. Tool-call events require an allowed P8-D observation binding. Original principal, tenant, goal, and budget delegation IDs must remain continuous through the execution record.

## Open-source and free implementation resources reviewed

P8-E intentionally adds **no new runtime dependency**. The design was informed by freely available/open-source mechanisms that can be integrated later without changing the deterministic lab boundary:

- **LangGraph (MIT)** — supports a runtime `recursion_limit`, raises `GraphRecursionError` when the graph exceeds the configured super-step limit, and exposes the current step counter for proactive termination/degradation. This maps directly to P8-E recursion/step ceilings.
- **LiteLLM core (MIT outside its enterprise directory)** — provides an open-source AI gateway with spend tracking, cost tracking, and rate limiting. This is a practical future enforcement point for provider-facing model-call and spend ceilings.
- **OpenTelemetry + OpenTelemetry Python (Apache-2.0)** — vendor-neutral traces/metrics/logs and semantic conventions provide a free way to emit run, call-count, duration, token, retry, and budget-denial telemetry without coupling AegisDesk to a commercial backend.
- **OpenLIT (Apache-2.0)** — OpenTelemetry-native GenAI observability with cost/usage dashboards and custom model pricing. It can be used as a free/self-hosted evidence sink for resource-accounting telemetry.
- **Langfuse core (MIT; enterprise folders have a separate license)** — open-source AI engineering/observability with metrics and self-hosting support. It is another optional free core for inspecting model/tool usage and costs.

These projects are references/integration options, not trusted evidence sources in the P8-E test fixture. Their presence does not turn synthetic cost estimates into provider billing truth or make runtime enforcement production-grade.

## Intentionally vulnerable baseline

`VulnerableDeclaredExecutionBudgetSafety` trusts caller declarations that a run is within budget, has no runaway loop, and has no resource exhaustion. It also accepts caller-owned aggregate cost and step counts without binding them to execution events or model-rate policy.

## Deterministic evaluation

An isolated byte-for-byte local harness executed the exact standalone P8-E core analyzer, fixture, evaluator, vulnerable baseline, and tests before upload.

Results:

- P8-E pytest outcomes: **18 passed**;
- adversarial cases: **129**;
- vulnerable ASR: **129/129**;
- hardened ASR: **0/129**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- execution-budget graph SHA-256: `6ded859ac55c7bd348313593fa73104fab41b6694482a8b9f764108ac51914e7`;
- adversarial dataset SHA-256: `b5abbaa72815e06ce1ddec4577f996a47a13b341cdaacbae7f5f03896de61cd5`;
- fixture SHA-256: `19165ac7dbdaa6437213cc149ecf357351e0d17d76f4027905943599138940c7`;
- clean assessment evidence SHA-256: `7a4b8ca83bae7ef6477f0464b26c064db7db5ea0e2009b42155a46beb40130fb`.

This is not a claim that full-repository pytest executed locally.

## Claim boundary

P8-E can claim deterministic synthetic execution-budget analysis, delegated-budget non-amplification/oversubscription detection, model/tool/token/step/latency ceilings, policy-derived synthetic model cost, recursion/fan-out/retry/repeated-operation analysis, irreversible-action rate limiting, and exact P8-A/P8-C/P8-D evidence binding.

P8-E does **not** claim production provider billing enforcement, a production runtime kill switch, live provider-price accuracy, distributed resource-accounting correctness, real infrastructure CPU/RAM/GPU quotas, complete denial-of-wallet prevention, exhaustive loop detection, cloud quota enforcement, or networked remediation.
