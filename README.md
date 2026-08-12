# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P2-C

P2-C adds a deterministic MCP tool-poisoning and tool-shadowing comparison at the **MCP server -> host** trust boundary.

Verified security architecture carried forward:

- server-derived synthetic principals and mandatory tenant-filtered hardened RAG;
- typed MCP tools with trusted principal injection outside model-visible arguments;
- high-impact requests create pending approval records only and require bound human approval;
- P2-B adds a server-owned capability policy so retrieved text cannot authorize tools;
- intentionally vulnerable demonstrations remain under `aegis/vulnerable/` and use only local synthetic effects;
- deterministic fake models, Qdrant local mode, in-memory MCP, and GitHub Actions require no paid model API.

P2-C adds a host-assigned MCP `server_id` and immutable trusted tool bindings. MCP discovery metadata is preserved for model/evaluation use, but duplicate bare names, descriptions, annotations, and advertised server labels are not authorization.

The intentionally vulnerable P2-C host flattens multiple MCP catalogs into a bare-name dictionary using last-server-wins semantics. A synthetic untrusted server shadows `create_ticket` and also advertises an `admin_diagnostic` description that deterministically steers the fake model on asset requests. The hardened host resolves `create_ticket` only through its trusted AegisDesk binding and blocks `admin_diagnostic` because no trusted binding exists.

## Run in Codespaces

```bash
python -m pip install -e ".[dev]"
pytest
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

The separate intentionally vulnerable HTTP lab from P2-A/P2-B can still be launched only through its explicit factory:

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
```

P2-C uses two fixed adversarial attempts and two benign attempts per variant. Both vulnerable and hardened adversarial runs use the same synthetic principal, MCP servers, discovered catalog, deterministic model, messages, tool schemas, and attempt budget; only the host resolution/authorization policy differs. The benign set uses the same trusted-only catalog for both variants.

Reports include raw ASR/FPR/SafeTaskRate numerators and denominators plus code/dependency/model/prompt/policy and deterministic dataset/catalog hashes. They do not print response bodies, credentials, canaries, approval handles, or ticket IDs.

Threat-model evidence:

- `docs/threat-model/p2a-tenant-boundary.md`
- `docs/threat-model/p2b-indirect-prompt-injection.md`
- `docs/threat-model/p2c-mcp-tool-poisoning.md`

### Prototype persistence limitation

The approval subsystem still uses LangGraph `InMemorySaver` and an in-memory approval store. A process restart loses pending workflows. Durable persistence remains a later hardening milestone.

## Synthetic identities

- Employee, Dynamics: `alice@northstar-dynamics.test`
- Approver, Dynamics: `carol.approver@northstar-dynamics.test`
- Employee, Digital: `bob@northstar-digital.test`
- Approver, Digital: `dave.approver@northstar-digital.test`

`X-Aegis-User` is a synthetic lab authentication handle, not a production authentication design.

All organizations, identities, records, credentials, canaries, poison documents, MCP servers, and side effects in this repository are synthetic.
