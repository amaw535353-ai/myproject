# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P2-G

P2-G adds a deterministic **agent-loop and resource-exhaustion** comparison at the model/tool execution -> host resource-budget trust boundary.

Verified security architecture carried forward:

- server-derived synthetic principals and mandatory tenant-filtered hardened RAG;
- typed MCP tools with trusted principal injection outside model-visible arguments;
- high-impact requests create pending approval records only and require bound human approval;
- retrieved text cannot expand server-owned tool capabilities;
- MCP discovery metadata cannot override host-owned server/tool bindings;
- inbound MCP bearer credentials terminate at the gateway and never reach downstream tool execution;
- downstream access uses a server-owned credential broker with a separate least-privilege credential;
- outbound URL policy revalidates DNS answers and every redirect target before synthetic connection;
- durable memory remains data and cannot replace server-derived identity, tenant, role, or approval authority;
- intentionally vulnerable demonstrations remain isolated and use only local synthetic effects;
- deterministic fake/no-model evaluations, Qdrant local mode, SQLite, in-memory MCP, and GitHub Actions require no paid model API.

P2-G introduces `AgentExecutionLimits`, `ExecutionBudget`, and `BoundedLoopAgentRunner`. The host owns limits for steps, model calls, tool calls, retries, input/context/result bytes, elapsed time, and repeated identical tool calls. Model output, retrieved text, MCP results, and client state cannot alter those limits.

The intentionally vulnerable comparison uses the same authenticated principal, deterministic runaway model, MCP gateway, tool schemas, corpus, and six-iteration lab safety ceiling but does not apply a security budget. One attack repeats the same side-effecting ticket call; the other grows context through repeated authorized searches with unique call arguments.

The existing default `AgentRunner` remains structurally stricter for its current workflow because it allows only one tool call. P2-G is a service-level multi-step boundary so future agent loops can be enabled without making model persistence equivalent to unlimited execution authority.

## Run in Codespaces

```bash
python -m pip install -e ".[dev]"
pytest
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

The separate intentionally vulnerable HTTP lab from earlier Phase 2 exercises is launched only through its explicit factory:

```bash
uvicorn apps.vulnerable_api.main:create_intentionally_vulnerable_lab_app \
  --factory --host 127.0.0.1 --port 8001
```

Never expose the vulnerable lab publicly and never point attack examples at third-party systems.

## Deterministic security comparisons

```bash
python -m evals.p2a_tenant_boundary
python -m evals.p2b_indirect_prompt_injection
python -m evals.p2c_mcp_tool_poisoning
python -m evals.p2d_token_passthrough
python -m evals.p2e_ssrf_redirects
python -m evals.p2f_durable_memory_poisoning
python -m evals.p2g_resource_exhaustion
```

P2-G uses two fixed adversarial attempts and two benign attempts per variant. Both variants use the same authenticated synthetic employee, deterministic model and prompt version, MCP gateway, schemas, data, and lab iteration ceiling; only the server-owned execution-budget policy differs.

Reports include raw ASR/FPR/SafeTaskRate numerators and denominators plus code/dependency/model/prompt/policy/dataset evidence. They record counters and the hardened block dimension, but do not print tool-result bodies, raw context, ticket IDs, credentials, or canaries.

Threat-model evidence:

- `docs/threat-model/p2a-tenant-boundary.md`
- `docs/threat-model/p2b-indirect-prompt-injection.md`
- `docs/threat-model/p2c-mcp-tool-poisoning.md`
- `docs/threat-model/p2d-token-passthrough.md`
- `docs/threat-model/p2e-ssrf-redirects.md`
- `docs/threat-model/p2f-durable-memory-poisoning.md`
- `docs/threat-model/p2g-resource-exhaustion.md`

### Prototype limitations

P2-G proves deterministic in-process resource accounting. A production agent still needs provider-side token/cost limits, cancellation for hung tools, streaming byte caps, distributed per-user/per-tenant quotas, concurrency/load shedding, and operating-system/container CPU and memory isolation.

The approval subsystem still uses LangGraph `InMemorySaver` and an in-memory approval store. A process restart loses pending workflows. Durable approval persistence remains a later hardening milestone.

## Synthetic identities

- Employee, Dynamics: `alice@northstar-dynamics.test`
- Approver, Dynamics: `carol.approver@northstar-dynamics.test`
- Employee, Digital: `bob@northstar-digital.test`
- Approver, Digital: `dave.approver@northstar-digital.test`

`X-Aegis-User` is a synthetic lab authentication handle, not a production authentication design.

All organizations, identities, records, credentials, canaries, poison documents, MCP servers, network routes, memory records, resource-exhaustion workloads, and side effects in this repository are synthetic.
