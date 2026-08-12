# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P1-B

P1-B adds a deterministic LangGraph agent and an MCP v2 tool gateway while preserving the P1-A tenant boundary.

Security properties implemented so far:

- synthetic server-resolved principals;
- mandatory tenant filtering for RAG;
- model-visible tool arguments never include authoritative identity fields;
- MCP `Resolve(...)` injects the trusted principal outside the model schema;
- a second Pydantic validation boundary rejects malformed or extra tool arguments;
- only three low-impact tools are available: `search_knowledge_base`, `get_my_assets`, and `create_ticket`;
- each agent run has a one-tool-call budget;
- deterministic fake model and local in-memory MCP client keep CI at $0.

High-impact tools (`request_access` and `request_password_reset`) are intentionally deferred until the approval-binding milestone.

## Synthetic identities

Use the `X-Aegis-User` header in this lab only:

- `alice@northstar-dynamics.test`
- `bob@northstar-digital.test`

The header is a synthetic lab authentication handle, not a production authentication design.

## Run in Codespaces

```bash
python -m pip install -e ".[dev]"
pytest
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

Tenant-isolated RAG:

```bash
curl -s http://127.0.0.1:8000/v1/knowledge/search \
  -H 'Content-Type: application/json' \
  -H 'X-Aegis-User: alice@northstar-dynamics.test' \
  -d '{"query":"vpn setup","limit":3}'
```

Deterministic agent:

```bash
curl -s http://127.0.0.1:8000/v1/agent/run \
  -H 'Content-Type: application/json' \
  -H 'X-Aegis-User: alice@northstar-dynamics.test' \
  -d '{"message":"assets"}'
```

Other deterministic examples:

```text
search: vpn setup
ticket: VPN problem | I cannot connect to the synthetic VPN.
```

All organizations, identities, records, credentials, and canaries in this repository are synthetic.
