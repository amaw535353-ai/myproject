# P4-A strict checkpoint serialization boundary

## Security property

Checkpoint data may restore only the small set of AegisDesk application types that the default agent graph legitimately persists. Other custom Python types remain plain data when loaded. Pickle fallback is disabled and custom JSON constructor revival is not enabled.

## Threat

LangGraph checkpoints serialize graph state and later deserialize it during execution or resume. A broad deserialization policy gives checkpoint data more authority than the runtime needs. P4-A narrows that policy to the exact application types required by `AgentState`.

The P3-E/P3-F verification logs exposed warnings for `Role`, `Principal`, `ToolName`, and `ToolCallProposal`: those types were being loaded under LangGraph's permissive default rather than an explicit AegisDesk allowlist.

## Boundary

The default `AgentRunner` no longer constructs `InMemorySaver()` with the framework default serializer. It uses `build_strict_in_memory_checkpointer()` from `aegis/agent/checkpoint_security.py`.

The exact application allowlist is:

- `aegis.identity.models.Role`
- `aegis.identity.models.Principal`
- `aegis.mcp_gateway.models.ToolName`
- `aegis.mcp_gateway.models.ToolCallProposal`

The serializer is constructed with `pickle_fallback=False`, `allowed_json_modules=None`, and the exact msgpack type list above. LangGraph's built-in safe msgpack types remain available through its built-in safe set.

## Deterministic evaluation

`evals/p4a_strict_checkpoint_serialization.py` compares the permissive serializer posture with the explicit strict boundary using only local synthetic objects. Two unregistered synthetic application types are restored as their Python types under the permissive baseline but remain plain data under the strict boundary. Two legitimate AegisDesk state types round-trip successfully.

The milestone passes only when the permissive baseline rate is 2/2, the strict-boundary rate is 0/2, false positives are 0/2, and safe task completion is 2/2.

## Non-goals and residual risk

P4-A does not make an in-memory checkpointer durable or production suitable. It does not provide checkpoint confidentiality or replace storage access controls. A future durable checkpointer must reuse the same strict serializer policy or an equivalently narrow allowlist and independently protect checkpoint integrity and access.

No external service, real credential, real user data, or uncontrolled outbound operation is introduced by this milestone.
