# Phase 4 hardening progress

Phase 4 starts after the six Phase 3 integration gaps were closed. P4-A narrowed the LangGraph checkpoint type policy used by the default agent runtime. P4-B extends that boundary to local durable checkpoint persistence with tamper-evident integrity and a separate monotonic local anchor.

Current posture after P4-B:

- Phase 3 integration gaps: 0 open.
- P4-A checkpoint type policy: implemented and evaluated.
- P4-B durable checkpoint integrity: implemented and evaluated.
- Default agent checkpoint application allowlist: 4 exact AegisDesk types.
- Pickle fallback: disabled.
- Custom JSON constructor revival: disabled.
- Default API checkpoint persistence: local SQLite with checkpoint and pending-write HMAC integrity.
- Default API checkpoint rollback binding: separate local SQLite monotonic head anchor.
- Real external operations introduced by P4-B: none.
- Production durability claim: none.

The default API now injects a `DurableIntegrityCheckpointer` into the agent graph. Persisted checkpoints retain the P4-A exact type policy, checkpoint rows are bound into a monotonic authenticated chain, the current chain head is stored in a separate local anchor database, and pending writes are authenticated individually and as a complete set. Modified or single-database rolled-back state fails closed before it is returned to the graph.

P4-B remains intentionally local and synthetic. The HMAC key is not externally protected, and the anchor database is a second local file rather than a production-independent trust service. A production deployment would still need protected durable storage, externalized key custody/rotation, operational backup and recovery, and multi-process concurrency design.

The next hardening target should address checkpoint confidentiality and secret minimization so durable graph state does not become a plaintext data-at-rest liability even when integrity is preserved.
