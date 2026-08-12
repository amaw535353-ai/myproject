# P2-D — MCP token passthrough and confused-deputy boundary

## Security property

An MCP server must validate that an inbound bearer credential was issued for the MCP resource and is bound to the authenticated principal. If the MCP server calls a downstream resource server, it must use a separate, narrowly scoped downstream credential. The caller's bearer token is never forwarded.

## Trust boundary

```text
synthetic MCP client bearer
        |
        v
MCP server / proxy
        |
        | separate server-controlled inventory credential
        v
synthetic inventory resource server
```

The inbound bearer, tool arguments, model output, and downstream responses are untrusted relative to authorization decisions. The trusted `Principal` remains server-owned request context.

## Primary-source alignment

Current Model Context Protocol authorization guidance requires MCP servers to validate that access tokens are intended for the MCP server and states that MCP servers must not accept or transit tokens intended for other resources. When an MCP server calls an upstream API, the access token used with that API is a separate token issued for that upstream resource; the MCP server must not pass through the token it received from the MCP client.

Primary references:

- https://modelcontextprotocol.io/specification/draft/basic/authorization
- https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices

The MCP security guide explicitly describes token passthrough as an anti-pattern and calls out security-control circumvention, audit/accountability failures, trust-boundary violations, stolen-token proxying, and confused-deputy risk.

## Synthetic lab setup

All credentials and services in this exercise are local deterministic fixtures. No credential grants access to a real service.

The fixture set contains:

- valid Alice and Bob MCP-audience credentials;
- a synthetic Alice inventory-admin credential intended only for the downstream inventory audience;
- one AegisDesk inventory service credential scoped only to `assets:read`.

Evaluation reports identify credentials only by safe aliases/classes and never emit the raw bearer values. The synthetic inventory audit records only a short SHA-256 fingerprint plus non-secret classification fields.

## Attack P2D-A1 — wrong-audience token reuse through the proxy

### Preconditions

- The attacker has the fixed synthetic inventory-admin credential for Alice.
- The downstream inventory service is represented as reachable only through the local proxy object in this lab.
- The vulnerable MCP proxy performs no inbound audience validation.

### Vulnerable behavior

The vulnerable proxy accepts the inventory-audience credential as if it were an MCP credential and forwards the same bearer unchanged. The inventory service recognizes its own audience and authorizes the synthetic asset request. This violates the MCP resource boundary and turns the MCP proxy into a deputy for a credential that was never issued to it.

### Hardened behavior

The hardened proxy validates the bearer before any downstream call:

1. credential exists in the synthetic validator;
2. audience is `urn:aegisdesk:mcp`;
3. subject equals the trusted principal's `user_id`;
4. required `mcp:tools` scope is present.

The inventory-audience token fails closed, and the downstream service records no call.

## Attack P2D-A2 — valid MCP bearer passed downstream

### Preconditions

- Alice presents a valid synthetic MCP-audience credential.
- The vulnerable proxy forwards the same bearer unchanged.

### Vulnerable behavior

The downstream inventory service correctly rejects the token because it is not inventory-audience, but its audit evidence proves that the MCP client's bearer crossed the downstream trust boundary. The policy violation is the passthrough itself; successful downstream authorization is not required for this attempt to count as a security failure.

### Hardened behavior

The hardened proxy validates Alice's MCP credential and then discards it for downstream authorization. It calls inventory with the separate `inventory-service` credential scoped to `assets:read`. The downstream audit therefore never sees Alice's MCP bearer.

## Benign tasks

Two matched benign requests use valid MCP credentials for Alice and Bob. The hardened path should return each principal's authorized synthetic assets with:

- FPR 0/2;
- SafeTaskRate 2/2;
- no downstream observation of either client bearer.

The vulnerable proxy is expected to fail these requests because the downstream service rejects MCP-audience credentials. This illustrates that token passthrough is both unsafe and operationally brittle.

## Regression tests

- valid MCP bearer is bound to the trusted principal;
- wrong-audience bearer is rejected;
- Alice's MCP bearer cannot be transferred to Bob;
- hidden principal/bearer dependencies do not appear in the MCP tool schema;
- vulnerable wrong-audience passthrough is reproducible;
- hardened wrong-audience rejection occurs before downstream execution;
- vulnerable valid-MCP passthrough is observable even when downstream rejects it;
- hardened downstream call uses only the separate service credential;
- P2-D evaluation output contains no raw bearer values.

## Evidence and metrics

`python -m evals.p2d_token_passthrough` records:

- code commit;
- dependency versions;
- deterministic attempt-set hash;
- synthetic asset-corpus hash;
- non-secret auth-fixture metadata hash;
- raw ASR/FPR/SafeTaskRate numerators and denominators;
- credential class/audience, downstream-call counts, and boolean passthrough evidence.

Raw bearer values are deliberately excluded.

## Residual risk

This milestone does not implement OAuth cryptography, discovery, PKCE, DCR, token exchange, refresh tokens, TLS, or a real authorization server. The deterministic registry exists only to prove architectural invariants. Production implementation should use standards-compliant authorization libraries/identity providers, audience/resource indicators, short-lived tokens, encrypted credential storage, least-privilege scopes, HTTPS, and redacted telemetry rather than recreating token validation manually.
