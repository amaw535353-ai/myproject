# Phase 3 integration progress

Phase 3 started with six integration gaps from the Phase 2 exit review. P3-A closed `P3-G01`. P3-B closes `P3-G02` by promoting the P2-G execution budget into the default agent runtime.

Current posture after P3-B:

- Phase 2 controls: 19/19 implemented and evaluated.
- Default API controls: 14.
- Partial default API controls: 0.
- Lab-only controls: 5 (`P2-D`, `P2-E`, `P2-F`, `P2-I`, `P2-J`).
- Open Phase 3 gaps: 4.

The remaining gaps are `P3-G03` through `P3-G06`: govern non-default browser/artifact/network surfaces; preserve credential brokering for future downstream adapters; preserve durable memory as data rather than authority; and replace local synthetic trust abstractions before production claims.

P3-B keeps the execution budget server-owned and outside model-visible graph state. Human approval waiting and the separate durable high-impact effect worker are outside the autonomous agent-run elapsed budget. Resource limits remain local process controls rather than distributed quotas.
