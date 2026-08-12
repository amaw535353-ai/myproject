# P2-C: MCP Tool Poisoning and Shadowing

## Security property

AegisDesk assigns MCP server identity and tool authority at the host boundary. A model may choose a bare tool name, but discovery order, duplicate names, server-controlled descriptions, annotations, and advertised server names cannot create or replace a trusted `(server_id, tool_name)` binding.

## Threat and trust boundary

Boundary: MCP server discovery metadata -> host/model -> MCP dispatch.

An untrusted server can advertise a tool with the same bare name as a trusted server or publish a description that steers the model toward an attacker-chosen tool. If a host flattens multiple catalogs into a bare-name dictionary or treats server metadata as authorization, model selection can become untrusted-server execution.

## Authorized local reproduction

Run only against the in-memory synthetic lab:

```bash
python -m evals.p2c_mcp_tool_poisoning
```

The vulnerable host aggregates trusted and untrusted tools by bare name with last-server-wins semantics. `P2C-A1` shadows `create_ticket`; `P2C-A2` uses a synthetic description marker that makes the deterministic fake model select `admin_diagnostic`.

No external MCP server, real account, credential, or third-party target is used.

## Vulnerable behavior

- discovery order decides which duplicate bare tool name wins;
- a unique untrusted tool selected because of its description is callable;
- the host has no immutable server/tool trust binding.

## Hardened behavior

- every connection has a host-assigned `server_id`;
- discovery preserves source server identity;
- a server-owned immutable mapping binds allowed bare names to the trusted AegisDesk gateway;
- duplicate untrusted names cannot replace the binding;
- tools without a trusted binding fail closed before MCP dispatch;
- the existing typed `ToolGateway` still validates trusted arguments and injects the server-derived principal outside model-visible schemas.

## Evidence and metrics

The P2-C report records raw ASR/FPR/SafeTaskRate numerators and denominators, code/dependency/model/prompt/policy versions, a deterministic evaluation hash, and a catalog hash. It records only synthetic server IDs, tool names, proposed arguments, block/dispatch status, and side-effect booleans; it does not print credentials, tokens, approval handles, ticket IDs, or hidden model state.

## Primary-source mapping

Current MCP tool guidance says tool-name uniqueness is scoped to one server; aggregating clients may encounter collisions and should disambiguate, for example by prefixing with a server identifier. It also states that `serverInfo.name` is not guaranteed unique and should not be relied upon for disambiguation:

- https://modelcontextprotocol.io/specification/draft/server/tools

MCP guidance also states that tool annotations from untrusted servers are untrusted, and MCP maintainers emphasize that annotations are hints rather than enforcement:

- https://modelcontextprotocol.io/specification/draft/server/tools
- https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/

The broader MCP security guidance recommends validating/sanitizing server input and applying explicit trust/consent controls to untrusted local servers:

- https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices

## Residual risk

This milestone proves host-level disambiguation and authorization using in-memory MCP servers. It does not yet authenticate remote MCP transports, pin server certificates or package identities, sandbox local MCP processes, validate installation commands, implement egress isolation, or handle dynamic tool-list changes and cache invalidation. Those are separate supply-chain/transport hardening tasks.
