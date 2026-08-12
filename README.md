# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P1-C

P1-C adds human-approval binding for high-impact requests while preserving the P1-A tenant boundary and P1-B typed MCP gateway.

Security properties implemented so far:

- synthetic server-resolved principals;
- mandatory tenant filtering for RAG;
- model-visible tool arguments never include authoritative identity fields;
- MCP `Resolve(...)` injects the trusted principal outside the model schema;
- a second Pydantic validation boundary rejects malformed or extra tool arguments;
- low-impact tools: `search_knowledge_base`, `get_my_assets`, and `create_ticket`;
- high-impact request tools: `request_access` and `request_password_reset`;
- high-impact tools create **pending approval requests only** and never grant access or reset credentials;
- approval records bind requester, tenant, exact action, normalized arguments, expiry, and a server nonce;
- only a same-tenant `admin_approver` other than the requester can approve;
- approved records are consumed once; argument mutation, transfer, replay, self-approval, cross-tenant approval, and expiry fail closed;
- LangGraph interrupts pause high-impact workflows and resume with a server-owned thread ID;
- the resume payload itself is not authorization; the approval store is re-checked after resume;
- each agent run still has a one-tool-call budget;
- deterministic fake model and local in-memory MCP client keep CI at $0.

### Prototype persistence limitation

P1-C deliberately uses LangGraph `InMemorySaver` and an in-memory approval store for a lightweight Codespaces-compatible lab. A process restart loses pending workflows. Durable SQLite-backed approval/checkpoint persistence is a later hardening milestone and is required before treating this as production-ready.

## Synthetic identities

Use the `X-Aegis-User` header in this lab only:

- Employee, Dynamics: `alice@northstar-dynamics.test`
- Approver, Dynamics: `carol.approver@northstar-dynamics.test`
- Employee, Digital: `bob@northstar-digital.test`
- Approver, Digital: `dave.approver@northstar-digital.test`

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

Low-impact deterministic agent call:

```bash
curl -s http://127.0.0.1:8000/v1/agent/run \
  -H 'Content-Type: application/json' \
  -H 'X-Aegis-User: alice@northstar-dynamics.test' \
  -d '{"message":"assets"}'
```

High-impact request grammar:

```text
access: finance-read | Need quarterly reporting access
password-reset: I forgot my synthetic password
```

The first call returns a synthetic `approval_id` with `status=pending_approval`. A same-tenant approver can then review it:

```bash
curl -s http://127.0.0.1:8000/v1/approvals/<approval_id>/decision \
  -H 'Content-Type: application/json' \
  -H 'X-Aegis-User: carol.approver@northstar-dynamics.test' \
  -d '{"decision":"approve"}'
```

Approval means only that the synthetic request passed human review. AegisDesk does not yet implement an access grant or credential reset side effect.

All organizations, identities, records, credentials, and canaries in this repository are synthetic.
