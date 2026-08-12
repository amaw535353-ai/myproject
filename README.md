# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P2-A

P2-A adds the first **intentionally vulnerable comparison baseline** while preserving the hardened P1 security spine.

Verified security architecture carried forward from Phase 1:

- synthetic server-resolved principals;
- mandatory tenant filtering for hardened RAG;
- model-visible tool arguments never include authoritative identity fields;
- MCP `Resolve(...)` injects the trusted principal outside the model schema;
- strict Pydantic validation rejects malformed or extra tool arguments;
- low-impact tools: `search_knowledge_base`, `get_my_assets`, and `create_ticket`;
- high-impact tools `request_access` and `request_password_reset` create pending approval requests only;
- approval records bind requester, tenant, exact action, normalized arguments, expiry, and a server nonce;
- same-tenant human approver required; replay, transfer, mutation, self-approval, cross-tenant approval, and expiry fail closed;
- deterministic fake model, in-memory MCP, Qdrant local mode, and CI remain $0.

P2-A intentionally adds two unsafe behaviors for authorized local testing:

1. unfiltered retrieval from a shared multi-tenant vector collection;
2. trusting a client-supplied `tenant_id` as the retrieval authorization boundary.

These behaviors live only in `aegis/vulnerable/` and `apps/vulnerable_api/`. The hardened `apps.api.main` does not import, mount, or feature-flag them, and the vulnerable module intentionally has **no module-level `app` object**.

## Run the hardened app in Codespaces

```bash
python -m pip install -e ".[dev]"
pytest
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

## Run the intentionally vulnerable lab

**Local synthetic lab only. Never expose this port publicly and never point the attack examples at third-party systems.** The explicit factory target is required on purpose:

```bash
uvicorn apps.vulnerable_api.main:create_intentionally_vulnerable_lab_app \
  --factory --host 127.0.0.1 --port 8001
```

Example cross-tenant leakage reproduction using Alice's synthetic Dynamics identity:

```bash
curl -s http://127.0.0.1:8001/v1/knowledge/search-unfiltered \
  -H 'Content-Type: application/json' \
  -H 'X-Aegis-User: alice@northstar-dynamics.test' \
  -d '{"query":"vpn password reset","limit":5}'
```

Example tenant-substitution reproduction:

```bash
curl -s http://127.0.0.1:8001/v1/knowledge/search-client-tenant \
  -H 'Content-Type: application/json' \
  -H 'X-Aegis-User: alice@northstar-dynamics.test' \
  -d '{"query":"vpn","tenant_id":"tenant_northstar_digital","limit":5}'
```

## Deterministic P2-A comparison

```bash
python -m evals.p2a_tenant_boundary
```

The report compares the vulnerable and hardened variants with the same two adversarial payloads, synthetic principal, corpus, deterministic embeddings, query limits, and attempt budget. It records ASR numerator/denominator, hashes, dependency versions, HTTP outcomes, and retrieved document IDs without printing response bodies or canary values. FPR and SafeTaskRate are intentionally deferred until a matched benign dataset exists.

See `docs/threat-model/p2a-tenant-boundary.md` for threats, preconditions, reproduction steps, controls, evidence, framework mappings, and residual risk.

### Prototype persistence limitation

The approval subsystem still uses LangGraph `InMemorySaver` and an in-memory approval store. A process restart loses pending workflows. Durable SQLite-backed approval/checkpoint persistence remains a later hardening milestone.

## Synthetic identities

- Employee, Dynamics: `alice@northstar-dynamics.test`
- Approver, Dynamics: `carol.approver@northstar-dynamics.test`
- Employee, Digital: `bob@northstar-digital.test`
- Approver, Digital: `dave.approver@northstar-digital.test`

`X-Aegis-User` is a synthetic lab authentication handle, not a production authentication design.

All organizations, identities, records, credentials, and canaries in this repository are synthetic.
