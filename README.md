# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P2-F

P2-F adds a deterministic **durable-memory poisoning** comparison at the persisted context -> authorization trust boundary.

Verified security architecture carried forward:

- server-derived synthetic principals and mandatory tenant-filtered hardened RAG;
- typed MCP tools with trusted principal injection outside model-visible arguments;
- high-impact requests create pending approval records only and require bound human approval;
- retrieved text cannot expand server-owned tool capabilities;
- MCP discovery metadata cannot override host-owned server/tool bindings;
- inbound MCP bearer credentials terminate at the gateway and never reach downstream tool execution;
- downstream access uses a server-owned credential broker with a separate least-privilege credential;
- outbound URL policy revalidates DNS answers and every redirect target before synthetic connection;
- intentionally vulnerable demonstrations remain isolated and use only local synthetic effects;
- deterministic fake/no-model evaluations, Qdrant local mode, SQLite, in-memory MCP, and GitHub Actions require no paid model API.

P2-F introduces a SQLite-backed `SqliteMemoryStore` and a hardened `MemoryAwareService`. Memory rows are server-stamped with the authenticated tenant/user and recalled only for that same principal. Stored content remains untrusted data: it is never parsed into `Principal`, roles, tenant identity, or approval authority.

The intentionally vulnerable comparison does the opposite. It recognizes a synthetic `AEGIS_MEMORY_PRINCIPAL=` directive inside a persisted note and promotes it into the Principal used by downstream authorization-sensitive services. Two fixed attacks demonstrate why that is unsafe: a durable cross-tenant asset identity override and a durable fabricated human-approver identity.

P2-F is currently a **service-level security boundary** rather than a new default FastAPI route. That keeps persistence isolated until its authorization properties are proven.

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
```

P2-F uses two fixed adversarial attempts and two benign attempts per variant. Both variants use the same authenticated users, asset corpus, SQLite memory store, approval store, persisted payloads, and attempt budget; only whether recalled memory is allowed to replace authoritative identity differs.

The evaluation reopens the same SQLite file through a new service/store instance before the second action. Reports include raw ASR/FPR/SafeTaskRate numerators and denominators plus code/dependency/policy/dataset evidence without raw memory contents.

Threat-model evidence:

- `docs/threat-model/p2a-tenant-boundary.md`
- `docs/threat-model/p2b-indirect-prompt-injection.md`
- `docs/threat-model/p2c-mcp-tool-poisoning.md`
- `docs/threat-model/p2d-token-passthrough.md`
- `docs/threat-model/p2e-ssrf-redirects.md`
- `docs/threat-model/p2f-durable-memory-poisoning.md`

### Prototype limitations

P2-F proves that durable memory cannot replace authentication or authorization state. It does not yet cover semantic poisoning of harmless responses, memory provenance/retention, cross-tenant vectorized memory, summarization attacks, or deletion/incident-response workflows.

The approval subsystem still uses LangGraph `InMemorySaver` and an in-memory approval store. A process restart loses pending workflows. Durable approval persistence remains a later hardening milestone.

## Synthetic identities

- Employee, Dynamics: `alice@northstar-dynamics.test`
- Approver, Dynamics: `carol.approver@northstar-dynamics.test`
- Employee, Digital: `bob@northstar-digital.test`
- Approver, Digital: `dave.approver@northstar-digital.test`

`X-Aegis-User` is a synthetic lab authentication handle, not a production authentication design.

All organizations, identities, records, credentials, canaries, poison documents, MCP servers, network routes, memory records, and side effects in this repository are synthetic.
