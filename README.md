# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P2-E

P2-E adds a deterministic **SSRF / DNS / redirect-revalidation** comparison at the outbound URL -> network destination trust boundary.

Verified security architecture carried forward:

- server-derived synthetic principals and mandatory tenant-filtered hardened RAG;
- typed MCP tools with trusted principal injection outside model-visible arguments;
- high-impact requests create pending approval records only and require bound human approval;
- retrieved text cannot expand server-owned tool capabilities;
- MCP discovery metadata cannot override host-owned server/tool bindings;
- inbound MCP bearer credentials terminate at the gateway and are never available to downstream MCP tool execution;
- downstream access uses a server-owned credential broker with a separate least-privilege credential;
- intentionally vulnerable demonstrations remain isolated and use only local synthetic effects;
- deterministic fake/no-model evaluations, Qdrant local mode, in-memory MCP, and GitHub Actions require no paid model API.

P2-E introduces a server-owned `UrlSecurityPolicy`, deterministic resolver, and in-memory synthetic HTTP transport. The vulnerable comparison checks only the initial allowlisted hostname, then trusts its DNS answer and follows redirects without revalidation. The hardened fetcher requires HTTPS, exact host allowlisting, default port, safe authority syntax, globally routable DNS answers, bounded redirects/body size, and **revalidates every redirect target before connection**.

No P2-E test opens a socket or performs real DNS. Link-local and loopback addresses are deterministic labels inside the synthetic transport only.

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
```

P2-E uses two fixed adversarial attempts and two benign attempts per variant. Both variants use the same synthetic allowlist, DNS records, routes, redirect/body budgets, and attempt budget; only outbound authorization differs.

The adversarial cases are:

- an allowlisted public URL that redirects to a synthetic link-local destination;
- an allowlisted hostname whose deterministic DNS result is loopback/private.

The hardened path revalidates the redirect and rejects non-global resolved addresses before transport dispatch. Reports include raw ASR/FPR/SafeTaskRate numerators and denominators plus code/dependency/policy/dataset/network-fixture evidence without response bodies or real network traffic.

Threat-model evidence:

- `docs/threat-model/p2a-tenant-boundary.md`
- `docs/threat-model/p2b-indirect-prompt-injection.md`
- `docs/threat-model/p2c-mcp-tool-poisoning.md`
- `docs/threat-model/p2d-token-passthrough.md`
- `docs/threat-model/p2e-ssrf-redirects.md`

### Prototype limitations

P2-E proves outbound authorization invariants with a synthetic transport. A production network tool still needs a real HTTP client integration that pins the policy-approved destination, strong TLS verification, explicit proxy behavior, independent egress filtering, timeouts, byte/redirect budgets, and telemetry redaction.

The approval subsystem still uses LangGraph `InMemorySaver` and an in-memory approval store. A process restart loses pending workflows. Durable persistence remains a later hardening milestone.

## Synthetic identities

- Employee, Dynamics: `alice@northstar-dynamics.test`
- Approver, Dynamics: `carol.approver@northstar-dynamics.test`
- Employee, Digital: `bob@northstar-digital.test`
- Approver, Digital: `dave.approver@northstar-digital.test`

`X-Aegis-User` is a synthetic lab authentication handle, not a production authentication design.

All organizations, identities, records, credentials, canaries, poison documents, MCP servers, network routes, and side effects in this repository are synthetic.
