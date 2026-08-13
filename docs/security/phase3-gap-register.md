# Phase 3 Gap Register — P3-A Baseline

This register contains the open integration gaps identified by the Phase 2 exit review. It is intentionally narrower than the full prototype-limitations list: these are the gaps that must shape the first Phase 3 control-plane milestones.

## P3-G01 — Default runtime stops at P2-M

**Severity:** Critical  
**Risk:** P2-N through P2-S are proven controls but are not yet the authority used by the default API high-impact effect path.

Acceptance requires the default approval-to-synthetic-effect path to compose P2-N freshness, P2-O provenance, P2-P generation fencing, P2-Q recovery, P2-R protected checkpointing, and P2-S receipt witnessing above P2-L/P2-M. Stale, forged, rollback-restored, and equivocated authority cases must be rejected through default application wiring. The lab must retain approval-only high-impact semantics and synthetic local effects.

Required evidence: default-runtime integration tests, deterministic regression evaluation, and composition-root documentation.

## P3-G02 — Control-plane write-path exclusivity

**Severity:** Critical  
**Risk:** Future direct writes can violate generation, journal, checkpoint, and receipt-history invariants.

Acceptance requires one authoritative repository/coordinator for covered subject, policy, signing-key, generation, checkpoint, and witness mutations. Runtime modules must not receive direct mutation-capable stores that bypass that coordinator, and negative tests must prove bypass writes are unavailable or fail closed.

Required evidence: write-path inventory, negative bypass tests, and a single-writer architecture note.

## P3-G03 — Protected authority trust-domain abstraction

**Severity:** High  
**Risk:** The checkpoint and witness are local deterministic proofs; colocating production state with rollback-restorable authority would invalidate the independence assumption.

Acceptance requires explicit injected checkpoint/witness interfaces with server-owned authority, audience, and key configuration. Runtime startup must reject rollback-domain aliasing or missing protected authority. The local deterministic implementation remains a documented lab adapter.

Required evidence: startup fail-closed tests, trust-domain configuration tests, and deployment-boundary documentation.

## P3-G04 — Control-plane composition and startup recovery

**Severity:** High  
**Risk:** State, effect, anchor, checkpoint, and witness primitives do not yet have one default composition root that owns ordering and startup recovery.

Acceptance requires one composition root for the high-impact control plane. Crash recovery and protected-history validation must finish before new authorization or first-effect execution is enabled, and duplicate authority representations must be removed or explicitly marked non-authoritative.

Required evidence: composition-root tests, startup recovery tests, and an authority/data-flow diagram.

## P3-G05 — Feature promotion gates for component-only controls

**Severity:** Medium  
**Risk:** Optional features could later be enabled without their hardened Phase 2 boundary.

Acceptance requires server-owned enablement gates for external MCP discovery, network/browser access, artifact ingestion, durable memory, and general multi-step execution. Configuration tests must reject feature/control mismatches while preserving the safe disabled-by-default runtime.

Required evidence: feature-control mapping, configuration regression tests, and default-runtime inventory.

## Ordering

P3-G01 and P3-G02 are the blocking control-plane gaps. P3-G03 and P3-G04 harden the trust/composition model required to make that integration operationally coherent. P3-G05 governs later promotion of optional features and should not expand the current milestone scope.
