# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P1-A

This branch implements the first security spine:

- synthetic server-resolved principals;
- direct Qdrant local-mode retrieval;
- mandatory server-side tenant filtering;
- strict request schemas that reject identity/tenant substitution;
- deterministic, zero-cost local embeddings;
- CI that uses no paid model API or external model service.

The effective `tenant_id` is never accepted from the request body, prompt, retrieved text, or model output. It is derived from the authenticated principal by trusted server-side code.

## Synthetic identities

Use the `X-Aegis-User` header in this lab only:

- `alice@northstar-dynamics.test`
- `bob@northstar-digital.test`

These values are synthetic handles. The server maps them to immutable principals and tenant IDs. `X-Aegis-User` is not intended as a production authentication mechanism.

## Run in Codespaces

```bash
python -m pip install -e ".[dev]"
pytest
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

Example:

```bash
curl -s http://127.0.0.1:8000/v1/knowledge/search \
  -H 'Content-Type: application/json' \
  -H 'X-Aegis-User: alice@northstar-dynamics.test' \
  -d '{"query":"vpn setup","limit":3}'
```

## Security status

Only P1-A controls are implemented. Approval workflows, MCP tools, the vulnerable baseline, agent execution, tracing, SSRF protections, and later evaluation tooling are intentionally not present yet.

All organizations, identities, records, and canary strings in this repository are synthetic.
