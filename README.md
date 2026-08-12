# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P2-D

P2-D adds a deterministic **MCP token-passthrough / confused-deputy** comparison at the `MCP client -> gateway -> MCP tool -> downstream resource` trust boundaries.

Verified security architecture carried forward:

- server-derived synthetic principals and mandatory tenant-filtered hardened RAG;
- typed MCP tools with trusted principal injection outside model-visible arguments;
- high-impact requests create pending approval records only and require bound human approval;
- retrieved text cannot expand server-owned tool capabilities;
- MCP discovery metadata cannot override host-owned server/tool bindings;
- intentionally vulnerable demonstrations remain isolated and use only local synthetic effects;
- deterministic fake/no-model evaluations, Qdrant local mode, in-memory MCP, and GitHub Actions require no paid model API.

P2-D uses a local synthetic inventory resource server and fixed synthetic bearer fixtures. The intentionally vulnerable proxy performs no MCP audience validation, carries the caller bearer into MCP context, and forwards it unchanged. The hardened design takes a different path: the MCP-facing gateway validates audience, subject, and scope, **discards the raw bearer before MCP execution**, binds only the trusted `Principal`, and lets a server-owned `InventoryCredentialBroker` call inventory with a separate `assets:read` service credential. Raw bearer values are excluded from evaluation output and downstream audit evidence.

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

Never expose the vulnerable lab publicly and never point the attack examples at third-party systems.

## Deterministic security comparisons

```bash
python -m evals.p2a_tenant_boundary
python -m evals.p2b_indirect_prompt_injection
python -m evals.p2c_mcp_tool_poisoning
python -m evals.p2d_token_passthrough
```

P2-D uses two fixed adversarial attempts and two benign attempts per variant. Both variants use the same synthetic principals, token fixtures, inventory service, asset corpus, MCP tool surface, and attempt budget; only credential-boundary handling differs.

The adversarial cases demonstrate wrong-audience token reuse and valid MCP token passthrough. In the hardened path, wrong-audience credentials are rejected before MCP execution, and valid MCP credentials are never placed in MCP tool context or forwarded downstream. The broker API accepts only the trusted principal; it owns the separate inventory-service credential.

Reports include raw ASR/FPR/SafeTaskRate numerators and denominators plus code/dependency/model/policy/dataset/corpus metadata. They do not print raw bearer values, response bodies, canaries, approval handles, or ticket IDs.

Threat-model evidence:

- `docs/threat-model/p2a-tenant-boundary.md`
- `docs/threat-model/p2b-indirect-prompt-injection.md`
- `docs/threat-model/p2c-mcp-tool-poisoning.md`
- `docs/threat-model/p2d-token-passthrough.md`

### Prototype limitations

The P2-D synthetic token registry and `InventoryCredentialBroker` prove trust-boundary behavior; they are **not** an OAuth or token-exchange implementation. Production code must use standards-compliant authorization libraries/identity providers, resource/audience binding, short-lived tokens, HTTPS, least-privilege scopes, secure credential storage/rotation, and redacted telemetry.

The approval subsystem still uses LangGraph `InMemorySaver` and an in-memory approval store. A process restart loses pending workflows. Durable persistence remains a later hardening milestone.

## Synthetic identities

- Employee, Dynamics: `alice@northstar-dynamics.test`
- Approver, Dynamics: `carol.approver@northstar-dynamics.test`
- Employee, Digital: `bob@northstar-digital.test`
- Approver, Digital: `dave.approver@northstar-digital.test`

`X-Aegis-User` is a synthetic lab authentication handle, not a production authentication design.

All organizations, identities, records, credentials, canaries, poison documents, MCP servers, and side effects in this repository are synthetic.
