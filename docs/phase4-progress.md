# Phase 4 hardening progress

Phase 4 starts after the six Phase 3 integration gaps were closed. P4-A narrows the LangGraph checkpoint type policy used by the default agent runtime.

Current posture after P4-A:

- Phase 3 integration gaps: 0 open.
- P4-A checkpoint type policy: implemented and evaluated.
- Default agent checkpoint application allowlist: 4 exact AegisDesk types.
- Pickle fallback: disabled.
- Custom JSON constructor revival: disabled.
- Real external operations introduced by P4-A: none.

The default graph now uses an explicit serializer policy rather than the framework's broad compatibility default. Unregistered local synthetic types remain plain data while the legitimate `Principal` and `ToolCallProposal` state types continue to round-trip.

The next hardening target should extend this policy to a durable checkpointer and add integrity protection for persisted checkpoint state before any production durability claim is made.
