# Phase 4 hardening progress

## Phase 4 complete

Phase 4 is complete for the current AegisDesk checkpoint-security lab scope. P4-A through P4-P are implemented, documented, deterministically evaluated, and enforced by CI. P4-Q adds the machine-readable claim/evidence exit gate that prevents the repository from silently overstating what those milestones prove.

Current posture:

- Phase 3 integration gaps: 0 open.
- P4-A strict checkpoint serialization: complete.
- P4-B durable local checkpoint integrity: complete.
- P4-C checkpoint confidentiality and structural secret minimization: complete.
- P4-D checkpoint encryption-key lifecycle and migration: complete.
- P4-E authenticated encrypted backup/restore: complete.
- P4-F checkpoint deployment trust-provider policy boundary: complete.
- P4-G synthetic external checkpoint adapter contract harness: complete.
- P4-H checkpoint runtime operation-provider seam: complete.
- P4-I checkpoint lifecycle capability-provider boundary: complete.
- P4-J synthetic external-style lifecycle contract harness: complete.
- P4-K lifecycle deployment trust-provider policy boundary: complete.
- P4-L deterministic lifecycle failure and in-process fencing harness: complete.
- P4-M durable local lifecycle command journal and restart reconciliation: complete.
- P4-N separate local lifecycle-journal witness and rollback detection: complete.
- P4-O provider-owned authenticated lifecycle outcome receipts: complete.
- P4-P provider-internal crash-safe command state and proof-based recovery: complete.
- P4-Q Phase 4 claim/evidence exit gate: complete when its deterministic gate passes on exact `main`.

## Default checkpoint runtime

The default API uses `OperationProviderKeyLifecycleCheckpointer`. Strict deserialization remains allowlisted; pickle fallback and arbitrary constructor revival remain disabled. Dynamic checkpoint and pending-write payloads are encrypted with local AES-256-GCM before SQLite persistence. Checkpoint integrity, encryption-key lifecycle, monotonic local heads, and lifecycle capabilities are routed through explicit provider interfaces.

The default implementations remain local synthetic components. They do not establish external custody, an independent failure domain, or production durability.

## Lifecycle and recovery evidence

P4-L through P4-P progressively model lifecycle command identity, fencing, crash ambiguity, restart-safe journals, local rollback witnesses, provider-owned outcome evidence, and provider-internal crash recovery. P4-P records authenticated provider command state before mutation and binds normalized lifecycle arguments. After mutation begins, recovery does not blindly re-run migration, snapshot, or restore; it requires deterministic observable proof of the intended result or fails closed.

These later milestones are lab harnesses rather than default request-path infrastructure. Their SQLite stores and HMAC keys remain same-host synthetic artifacts.

## P4-Q evidence registry

`aegis/security/phase4_controls.py` is the canonical Phase 4 machine-readable evidence register. For every P4-A through P4-P milestone it records the threat model, deterministic evaluation, implementation evidence paths, evidence posture, supported claims, residual assumptions, and explicit non-production trust posture.

`evals/p4q_phase4_exit_gate.py` fails closed if a milestone disappears, evidence paths or evaluations are missing, CI stops running a Phase 4 evaluation, supported claims grow into prohibited production/distributed claims, residual assumptions disappear, an included implementation becomes production-ready/operationally external/independent-failure-domain without policy redesign, or Phase 3 integration gaps reappear.

The three evidence postures are intentionally explicit: seven `default_local` controls, two `policy_boundary` milestones, and seven `synthetic_lab` milestones.

## Claims that Phase 4 supports

Phase 4 supports claims about deterministic checkpoint-security behavior inside this repository: strict serialization, local authenticated integrity/confidentiality, key lifecycle, authenticated local backup/restore, explicit provider and lifecycle boundaries, deployment-policy checks, synthetic external-style contracts, deterministic failure/fencing semantics, authenticated restart state, local rollback detection, provider outcome evidence, and proof-based provider crash recovery.

## Claims that Phase 4 does not support

Phase 4 does **not** claim a production external checkpoint adapter, a production external lifecycle provider, production checkpoint durability, production disaster recovery, remote KMS/HSM custody, an independent failure domain, distributed fencing, a distributed transaction, distributed consensus, exactly-once execution, or real external trust operations.

The checkpoint database, local integrity/encryption keys, lifecycle journals, local witness, provider outcome store, provider command store, and their local HMAC keys can ultimately share host fate. A host compromise or coordinated rollback therefore remains outside the protection established by the local/synthetic evidence.

## Phase 5

Phase 5 moves beyond checkpoint hardening into **model and AI supply-chain security**. The first milestone should define a model-artifact provenance and safe-loading boundary: artifact identity, digest/signature verification, trusted-source policy, serialization/loader restrictions, and deterministic rejection of tampered or untrusted model artifacts. Later Phase 5 milestones can build on that foundation for malicious adapters/fine-tunes, model poisoning, model registry provenance, inference-runtime provenance, model privacy/extraction, and adversarial-ML defenses.
