# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P2-B

P2-B adds a deterministic poisoned-document indirect prompt-injection scenario and a server-owned capability boundary for the read-only RAG answer path.

Verified security architecture carried forward:

- server-derived synthetic principals and mandatory tenant-filtered hardened RAG;
- typed MCP tools with trusted principal injection outside model-visible arguments;
- high-impact requests create pending approval records only and require bound human approval;
- vulnerable demonstrations live only under `aegis/vulnerable/` and the separately launched `apps/vulnerable_api/` factory;
- deterministic fake models, Qdrant local mode, in-memory MCP, and GitHub Actions require no paid model API.

P2-A demonstrates shared-vector cross-tenant leakage and client-controlled tenant substitution. P2-B demonstrates a different boundary: an authorized same-tenant document contains a synthetic instruction that causes the fixed RAG model to propose `create_ticket` or `request_access` even though the user asked only a read-only knowledge question.

The vulnerable P2-B runner blindly dispatches the proposal. The hardened `/v1/rag/answer` path applies the server-owned `read-only-rag-capability-v1` policy before MCP dispatch. Retrieved text and model output cannot modify that capability set.

## Run the hardened app in Codespaces

```bash
python -m pip install -e ".[dev]"
pytest
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

Read-only RAG answer:

```bash
curl -s http://127.0.0.1:8000/v1/rag/answer \
  -H 'Content-Type: application/json' \
  -H 'X-Aegis-User: alice@northstar-dynamics.test' \
  -d '{"query":"vpn setup","limit":1}'
```

## Run the intentionally vulnerable lab

**Local synthetic lab only. Never expose this port publicly and never point the examples at third-party systems.**

```bash
uvicorn apps.vulnerable_api.main:create_intentionally_vulnerable_lab_app \
  --factory --host 127.0.0.1 --port 8001
```

P2-B poisoned-document reproduction:

```bash
curl -s http://127.0.0.1:8001/v1/rag/answer-poisonable \
  -H 'Content-Type: application/json' \
  -H 'X-Aegis-User: alice@northstar-dynamics.test' \
  -d '{"query":"orchid orchid orchid diagnostic","limit":1}'
```

The vulnerable response reports that the synthetic `create_ticket` proposal executed. The hardened matched evaluation blocks the same proposal before MCP dispatch.

## Deterministic security comparisons

```bash
python -m evals.p2a_tenant_boundary
python -m evals.p2b_indirect_prompt_injection
```

P2-B uses two fixed adversarial attempts and one matched benign request per variant. It records ASR, FPR, and SafeTaskRate with raw numerators/denominators plus code/dependency/model/prompt/policy/corpus evidence. It does not print answer bodies, canaries, approval handles, or ticket IDs.

Threat-model evidence:

- `docs/threat-model/p2a-tenant-boundary.md`
- `docs/threat-model/p2b-indirect-prompt-injection.md`

### Prototype persistence limitation

The approval subsystem still uses LangGraph `InMemorySaver` and an in-memory approval store. A process restart loses pending workflows. Durable SQLite-backed approval/checkpoint persistence remains a later hardening milestone.

## Synthetic identities

- Employee, Dynamics: `alice@northstar-dynamics.test`
- Approver, Dynamics: `carol.approver@northstar-dynamics.test`
- Employee, Digital: `bob@northstar-digital.test`
- Approver, Digital: `dave.approver@northstar-digital.test`

`X-Aegis-User` is a synthetic lab authentication handle, not a production authentication design.

All organizations, identities, records, credentials, canaries, poison documents, and side effects in this repository are synthetic.
