# P8-J — agent rollback, recovery, and persistence-boundary security

## Scope

P8-J treats recovery as a security boundary rather than an operational reset button. A checkpoint can be internally consistent and still be unsafe to resume if it preserves revoked credentials, quarantined messages, superseded memory, rejected artifacts, stale authorization state, or state transitions that upstream evidence already denied.

The deterministic `AgentRollbackRecoverySecurityAnalyzer` models recovery items, checkpoint ancestry, recovery authorizations, and resume/rollback/restore operations. It binds exact P8-B memory, P8-I artifact, and P8-H state-transition assessment digests and verification flags.

## Threat model

The attacker can influence caller declarations, recovery requests, checkpoint metadata, persistence-item state, recovery authorization scope, target generation, restore/quarantine/revocation partitions, or upstream evidence objects. The attacker succeeds if recovery resumes or restores a state that should remain revoked, quarantined, superseded, or otherwise unsafe.

Representative threats include:

- resuming a compromised checkpoint because it is the newest snapshot;
- rolling back past the tenant's policy-pinned recovery floor;
- silently omitting compromised source-only items instead of quarantining or revoking them;
- restoring revoked credential material instead of requiring refresh/re-issuance;
- restoring a message or artifact already marked non-restorable;
- restoring memory whose P8-B write/retrieval evidence is denied or missing;
- restoring an artifact whose P8-I action evidence is denied or missing;
- restoring task/policy state whose P8-H transition evidence is denied or missing;
- widening a rollback authorization to another actor, principal, tenant, mode, item set, or rollback depth;
- replaying an expired recovery authorization;
- using caller-provided "safe recovery" summaries to override derived evidence.

## Hardened properties

The analyzer enforces:

- exact recovery graph ID/version/SHA-256 and manifest freshness;
- exact P8-B/P8-I/P8-H evidence digests and verification flags;
- exact recovery-item, checkpoint, authorization, and operation coverage;
- trusted owners and policy-pinned item/checkpoint profiles;
- acyclic checkpoint ancestry with monotonically increasing generation;
- tenant, session, original-principal, and state-digest continuity;
- policy-pinned recovery-floor generations;
- compromised/quarantined checkpoint resume denial;
- target checkpoint freshness and expiry checks;
- exact target restore partitioning;
- explicit quarantine/revocation of compromised source-only persistence;
- revoked, quarantined, and superseded item non-restoration;
- credential resurrection denial when refresh/re-issuance is required;
- message/artifact non-restorable policy enforcement;
- upstream P8-B memory safety, P8-I artifact safety, and P8-H state-transition safety at recovery time;
- authorization actor/principal/tenant/mode/item/depth/expiry binding;
- explicit destructive-rollback authorization; and
- caller-declared denied/risk/target summaries matching derived facts exactly.

## Deterministic fixture

The canonical fixture contains:

- **8 persistence items**;
- **4 checkpoints**;
- **2 recovery authorizations**; and
- **3 recovery operations**.

The checkpoint chain is `checkpoint-root → checkpoint-safe-1 → checkpoint-safe-2 → checkpoint-compromised`. The compromised generation contains a quarantined rejected message, a revoked stale credential, and a quarantined poisoned artifact. The clean rollback restores `checkpoint-safe-2`, quarantines the rejected message and poisoned artifact, and revokes the stale credential under a bounded destructive authorization.

Exact isolated validation:

- tests: **17 passed**;
- adversarial cases: **130**;
- vulnerable ASR: **130/130**;
- hardened ASR: **0/130**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- recovery graph SHA-256: `b8a38dd2e9002fb9ff4864442918e6ac4ec11f9584c8b851f93de034e57b774a`;
- adversarial dataset SHA-256: `66f2aa0fd8e99c3f7dedf65d63fc3448cfedd4aee49930f86b19e6ae7bc13e46`;
- fixture SHA-256: `d4071cd7552a2ce9be3dfeec85763591a05dcd5eeadd4b9541d6199aa16d297b`;
- clean assessment SHA-256: `1bbf03a27b206911c23abed3af2cbace3c515e48785aeff802cf947857ff23eb`.

This validation exercised the standalone P8-J module/fixture/evaluator/vulnerable baseline/tests in an isolated Python environment. It is not full-repository pytest and not production checkpoint, backup, database, credential, or agent-runtime integration.

## Free/open-source implementation path

P8-J adds no runtime dependency. Optional future integrations include:

- **Temporal Server (MIT)** for durable workflow history, retry/cancellation, and replay-aware execution. P8-J would still independently enforce security-specific recovery floors, revocation, quarantine, and authorization semantics.
- **restic (BSD-2-Clause)** for encrypted, content-addressed snapshot backup/restore and repository integrity checking. A restic snapshot would remain storage evidence, not sufficient proof that an agent checkpoint is safe to resume.
- **Litestream (Apache-2.0)** for continuous SQLite replication and restore when an agent's durable state is SQLite-backed. P8-J would still validate recovery provenance and non-restoration of revoked/quarantined state.

These are optional future evidence/enforcement substrates, not dependencies or executed P8-J evidence.

## Claim boundary

P8-J does **not** claim:

- production backup/restore enforcement;
- production checkpoint-store integration;
- real credential revocation or rotation;
- cryptographic checkpoint attestation;
- immutable/WORM storage guarantees;
- production disaster-recovery certification;
- semantic proof that a recovered agent state is benign;
- formal rollback/recovery safety proof;
- exhaustive persistence/recovery attack coverage; or
- networked remediation.

`trusted`, `compromised`, `revoked`, and `quarantined` are deterministic policy classifications in this synthetic lab, not cryptographic or operational attestations.
