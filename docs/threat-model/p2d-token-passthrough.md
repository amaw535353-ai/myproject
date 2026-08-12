# P2-D — MCP token passthrough and confused-deputy boundary

## Security property

An inbound bearer credential is validated at the MCP-facing gateway for the MCP audience and trusted principal, then discarded before MCP tool execution. A downstream call is authorized through a separate server-owned credential broker. The caller bearer is therefore unavailable to the MCP tool and cannot be forwarded downstream by accident.

## Hardened trust boundary

```text
synthetic MCP client bearer
        |
        v
MCP-facing gateway
  validate audience + subject + scope
        |
        | raw bearer ends here
        v
trusted Principal only
        |
        v
MCP tool
        |
        v
server-owned credential broker
        |
        | inventory-service credential (assets:read)
        v
synthetic inventory resource server
```

This differs intentionally from the vulnerable lab, which carries the raw bearer into MCP request context and forwards it unchanged. Vulnerable bearer state is defined only under `aegis/vulnerable/`.

## Primary-source alignment

Current Model Context Protocol authorization guidance requires MCP servers to validate that access tokens are intended for the MCP resource and states that MCP servers must not accept or transit tokens intended for other resources. When an MCP server calls an upstream API, that API uses a separate credential for the upstream resource; the inbound MCP token must not be passed through.

Primary references:

- https://modelcontextprotocol.io/specification/draft/basic/authorization
- https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices

## Synthetic lab setup

All credentials and services are deterministic local fixtures. No credential grants access to a real system. The fixture set contains valid Alice and Bob MCP-audience credentials, a synthetic Alice inventory-admin credential for the downstream inventory audience, and one AegisDesk inventory service credential scoped to `assets:read`.

Evaluation reports use aliases/classes rather than raw bearer values. The inventory audit stores only a short SHA-256 fingerprint and non-secret classification fields.

## Attack P2D-A1 — wrong-audience token reuse

The vulnerable proxy accepts the synthetic inventory-admin token as if it were an MCP credential and forwards it unchanged. The inventory service recognizes its own audience and authorizes the request.

The hardened gateway rejects the token before MCP execution because its audience is not `urn:aegisdesk:mcp`. No broker call or downstream call occurs.

## Attack P2D-A2 — valid MCP token passed downstream

The vulnerable proxy carries Alice's valid MCP bearer into MCP context and forwards it unchanged. The inventory service rejects it because the audience is wrong, but the audit proves the client bearer crossed the downstream trust boundary. Passthrough itself is the policy violation.

The hardened gateway validates Alice's MCP credential, then enters MCP execution with only the trusted `Principal`. The MCP tool calls `InventoryCredentialBroker`, whose API accepts only the principal and internally uses the separate `inventory-service` credential. Alice's bearer is structurally unavailable to that call path.

## Benign tasks

Two matched benign requests use valid MCP credentials for Alice and Bob. The hardened path should return each principal's authorized synthetic assets with FPR 0/2, SafeTaskRate 2/2, and no downstream observation of either client bearer.

## Regression tests

- valid MCP bearer is bound to the trusted principal;
- wrong-audience bearer is rejected at the gateway;
- Alice's MCP bearer cannot transfer to Bob;
- the hardened MCP schema exposes no principal, bearer, authorization, token, tenant, or user fields;
- the credential broker API accepts a principal but no caller bearer/token parameter;
- vulnerable wrong-audience passthrough remains reproducible in the isolated lab;
- hardened rejection occurs before MCP and downstream execution;
- vulnerable valid-MCP passthrough is observable even when downstream rejects it;
- hardened downstream calls use only the broker-owned service credential;
- P2-D evaluation output contains no raw bearer values.

## Evidence and metrics

`python -m evals.p2d_token_passthrough` records the code commit, dependency versions, deterministic attempt-set and corpus hashes, raw ASR/FPR/SafeTaskRate numerators and denominators, credential class/audience, downstream-call counts, and boolean passthrough evidence. It also records that the hardened MCP tool does not receive the raw inbound bearer.

## Residual risk

This milestone does not implement OAuth cryptography, discovery, PKCE, DCR, token exchange, refresh tokens, TLS, or a real authorization server. `InventoryCredentialBroker` is a local architectural stand-in for a production credential/token-exchange component. Production should use standards-compliant identity libraries/providers, audience/resource validation, short-lived downstream credentials, encrypted secret storage, least-privilege scopes, HTTPS, rotation, and redacted telemetry rather than recreating token validation manually.
