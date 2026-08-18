# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P2-R

P2-R adds an **externally protected monotonic recovery checkpoint abstraction** around the P2-Q control plane. P2-Q can detect and recover partial commits between the execution database and local anchor/journal, but restoring both local files to the same older internally consistent snapshot removes the local evidence that a later generation existed. P2-R adds a third synthetic protected-domain checkpoint that is excluded from that two-file restore set and binds the active generation to the canonical P2-Q journal hash-chain head. Authorization issuance and the first synthetic effect fail closed unless the local execution generation, local anchor generation, protected generation, and reconstructed journal head all agree.

Verified security architecture carried forward:

- server-derived synthetic principals and mandatory tenant-filtered hardened RAG;
- typed MCP tools with trusted principal injection outside model-visible arguments;
- high-impact requests create pending approval records only and require bound human approval;
- retrieved text and webpage content cannot expand server-owned tool capabilities;
- MCP discovery metadata cannot override host-owned server/tool bindings;
- inbound MCP bearer credentials terminate at the gateway and never reach downstream tool execution;
- downstream access uses a server-owned credential broker with a separate least-privilege credential;
- outbound URL policy revalidates DNS answers and every redirect target before synthetic connection;
- durable memory remains data and cannot replace server-derived identity, tenant, role, or approval authority;
- multi-step agent execution is bounded by server-owned step/model/tool/retry/byte/time budgets;
- telemetry is converted to typed, allowlisted, pseudonymized security events before export;
- untrusted artifacts receive server-owned storage paths, passive rendering, and bounded archive extraction;
- durable approvals/workflows remain bound across restart and are non-replayable once completed;
- approved effects use a server-derived idempotency key and downstream idempotency ledger;
- current authorization is revalidated at the first synthetic effect boundary;
- cached authorization is accepted only when its policy version and revocation epoch match authoritative state;
- authorization evidence must carry a valid Ed25519 signature from the expected issuer for the exact effect-worker audience;
- signed claims bind the tenant, exact outbox record, policy version, revocation epoch, decision validity window, signing key ID, and monotonic key epoch;
- an obsolete signing key cannot become authoritative again through the normal rotation API;
- an independent monotonic control-plane generation is signed into the P2-P authorization envelope;
- the first new effect requires exact equality with that independent generation, so rolling back only the execution database cannot restore authority;
- P2-Q journals control-plane changes as `prepared`, `applied`, and `active` and commits each covered security mutation with its execution-generation marker;
- authorization issuance and the first effect fail closed while a control-plane change is pending or execution/anchor generations disagree;
- deterministic recovery completes a recognized partial control-plane change forward before new authorization is usable;
- P2-R keeps a monotonic protected checkpoint outside the two local rollback-restorable databases;
- the protected checkpoint binds generation to the canonical active P2-Q journal hash-chain head, so equal generation numbers are insufficient when journal integrity diverges;
- a local generation that is ahead of the protected checkpoint is unusable until prefix-validated recovery catches the checkpoint forward, while a protected checkpoint ahead of local state is treated as rollback and never decremented;
- the independent generation/checkpoint locks are held through first-effect validation and commit, giving the local lab an ordered security boundary rather than a distributed-consensus claim;
- provenance/freshness denial creates durable terminal state so old evidence cannot later revive;
- intentionally vulnerable demonstrations remain isolated and use only local synthetic effects;
- deterministic fake/no-model evaluations, Qdrant local mode, SQLite, in-memory MCP, and GitHub Actions require no paid model API.

P2-K introduced `DurableApprovalStore` and `DurableWorkflowStore`, preserving requester/tenant/action/normalized-argument binding across process restart. P2-L extended that boundary with `TransactionalEffectCoordinator`: approval consumption and creation of the bound outbox message happen inside one SQLite transaction. The outbox is not populated from model-visible authority or resume-time client arguments.

The P2-L downstream `SyntheticIdempotentEffectService` uses a separate local SQLite ledger keyed by a server-derived idempotency key. At-least-once delivery remains safe across crash-after-effect and duplicate worker delivery because the downstream returns the existing identical synthetic effect instead of recording a duplicate.

P2-M added `RevalidatingDurableEffectWorker` and `SyntheticRevalidatingEffectService`. Current synthetic authorization state and the downstream effect ledger share the execution database, so a decisive current-authorization read and first effect insert can occur inside one `BEGIN IMMEDIATE` transaction. If current authorization is invalid, the service records a bound denial tombstone and the worker cancels the outbox. Restoring authorization later does not resurrect the old approval.

P2-N models the harder distributed case where that execution-time check is served by a stale replica. `CachedAuthorizationReplica` emits a frozen server-owned decision bound to the exact outbox record and carrying the replica's `policy_version` and `revocation_epoch`. `VersionFencedSyntheticEffectService` reads the authoritative counters and inserts the first synthetic effect in one transaction; exact version equality is required. A stale subject-revocation epoch or stale policy version therefore fails closed even when the replica still says `allowed`.

P2-O makes those authorization claims cryptographically attributable. `AuthorizationDecisionSigner` signs canonical `aegis.authz-decision.v1` claims with a synthetic Ed25519 issuer key. The downstream `ProvenanceFencedSyntheticEffectService` accepts only the expected issuer/audience, trusted current signing-key epoch, valid signature and validity window, exact tenant/outbox binding, current P2-N policy/revocation versions, and an `allowed` result before the first synthetic effect is inserted.

`TrustedAuthorizationKeyStore` keeps only trusted Ed25519 public keys and the authoritative current key epoch in the same SQLite execution boundary as the P2-N version counters and synthetic effect ledger. Key rotation is monotonic. Signature verification, current key-epoch checking, P2-N freshness checking, durable denial lookup, and first effect insertion are serialized by the same local `BEGIN IMMEDIATE` transaction.

P2-P adds `ControlPlaneGenerationStore` in a **separate SQLite database**. `AnchoredAuthorizationSigner` wraps the complete P2-O signed decision in canonical `aegis.authz-envelope.v1` evidence carrying `control_plane_generation` and signs that envelope with the synthetic issuer key. `RollbackResistantSyntheticEffectService` refuses to use an anchor database that resolves to the execution-database path, requires the envelope generation to equal the independent current generation, verifies the envelope signature, and then runs the complete P2-O check before creating a new effect.

The generation store's `locked_current()` holds a local `BEGIN IMMEDIATE` lock while the P2-P service validates the signed generation envelope and the inner P2-O service commits the effect. Thus a local generation advance is ordered either before the effect (which causes old evidence to fail) or after it (meaning the effect completed under the prior current generation). This is deliberately a local lab guarantee, not a claim of distributed consensus.

P2-Q adds `CrashSafeControlPlaneCoordinator`. The independent anchor database now also holds an immutable change journal. `prepare()` records the next target generation. `_apply_execution()` commits the covered authorization-state mutation and `execution_control_plane_state.applied_generation` with the exact change ID and mutation hash in one execution-database transaction. `activate()` advances the independent generation and marks the same journal row active in one anchor-database transaction only after the execution marker matches.

`RecoverableAnchoredAuthorizationReplica` issues evidence only when there is no pending journal row and the execution generation equals the active anchor generation. `CrashSafeRollbackResistantSyntheticEffectService` rechecks the same condition under the independent generation lock before running the full P2-P/P2-O/P2-N checks and committing a first synthetic effect. `recover()` is idempotent and finishes `prepared` or `applied` changes forward; it never decrements a generation or attempts to reconstruct old authority.

P2-R adds `SyntheticProtectedCheckpointAuthority` and `ExternallyCheckpointedControlPlaneCoordinator`. The checkpoint record is a monotonic `(authority_id, generation, journal_head_sha256)` tuple. Generation 1 starts from a deterministic genesis head; every active P2-Q change extends the canonical chain with the prior head, from/target generations, change ID, and canonical typed mutation hash. Before authority is usable, P2-R reconstructs and validates that active chain and requires its current head to equal the protected record.

A P2-R commit deliberately does not pretend that three stores participate in one transaction. It finishes the P2-Q local protocol and then advances the protected checkpoint with compare-and-swap semantics. If the process dies after local activation, local generation can temporarily be ahead of the protected checkpoint; issuance/effect execution fails closed and recovery advances the protected checkpoint only after proving its current generation/head is an exact prefix of the local active chain. If the protected checkpoint is ahead of local generation, P2-R treats local state as obsolete rollback and does not decrement the protected record.

`CheckpointBoundAuthorizationReplica` and `CheckpointBoundSyntheticEffectService` enforce the protected generation/head fence while preserving the complete P2-P/P2-O/P2-N provenance, key-epoch, freshness, binding, denial-tombstone, and first-effect checks. The protected checkpoint is modeled as a third local SQLite file only to keep the lab deterministic and offline; the security claim is explicitly conditional on that store being in a genuinely separate protected rollback domain in production.

An already-recorded idempotent effect is checked by the inner P2-O service before provenance/freshness validation. This preserves P2-L crash recovery: if an effect was validly authorized and committed before a worker crashed, later key/version/generation changes do not duplicate the already-executed outcome.

The intentionally weak P2-R comparison uses the full P2-Q local coordinator but no protected checkpoint. Its intended defect is only the trust assumption under test: both authoritative local databases are restored together to an old generation, so their local equality checks agree on obsolete authority and the comparison can record a first effect.

## Run in Codespaces

P11-B deterministic validation and its resource-bounded live gate:

```bash
python -m pytest -q tests/security/test_p11b_kubernetes_security.py
python -m evals.p11b_kubernetes_security
python scripts/verify_phase11.py --focused-p11b
```

The verifier attempts a real single-server k3d/K3s cluster. Tooling or cluster-creation failure is deferred, never a pass; local evidence makes no production Kubernetes, cloud IAM, multi-node, kernel/container-escape, GPU, or production SOC/IR claim.

P11-C extends this with a provider-neutral live-local cloud identity and cryptographic control plane:

```bash
python -m pytest -q tests/security/test_p11c_cloud_security.py
python -m evals.p11c_cloud_security
python scripts/verify_phase11.py --focused-p11c
```

The live lab uses a real short-lived K3s ServiceAccount token and TokenReview API, then exercises local IAM, AES-GCM envelope encryption, encrypted secret rotation, metadata capabilities, identity fencing, key rotation, replacement identity, recovery, and a sanitized hash-chained audit trail. It does not contact cloud metadata or claim AWS, GCP, Azure, production-cloud, or HSM validation.

```bash
python -m pip install -e ".[dev]"
pytest
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

The hardened API stores local synthetic approval/workflow/outbox state at `.aegisdesk/state.sqlite3` and its separate synthetic downstream effect/authorization state at `.aegisdesk/synthetic-effects.sqlite3` by default. P2-P through P2-R's generation, recovery-journal, and protected-checkpoint components are currently evaluation/control-plane primitives rather than new default API runtime files. Override the existing state/effect paths with `AEGISDESK_STATE_DB` and `AEGISDESK_EFFECT_DB` when needed.

The separate intentionally vulnerable HTTP lab from earlier Phase 2 exercises is launched only through its explicit factory:

```bash
uvicorn apps.vulnerable_api.main:create_intentionally_vulnerable_lab_app \
  --factory --host 127.0.0.1 --port 8001
```

Never expose the vulnerable lab publicly and never point attack examples at third-party systems.

## Deterministic security comparisons

```bash
python -m evals.p2a_tenant_boundary
python -m evals.p2b_indirect_prompt_injection
python -m evals.p2c_mcp_tool_poisoning
python -m evals.p2d_token_passthrough
python -m evals.p2e_ssrf_redirects
python -m evals.p2f_durable_memory_poisoning
python -m evals.p2g_resource_exhaustion
python -m evals.p2h_telemetry_leakage
python -m evals.p2i_artifact_handling
python -m evals.p2j_browser_prompt_injection
python -m evals.p2k_durable_approval_workflow
python -m evals.p2l_transactional_outbox
python -m evals.p2m_execution_time_authorization
python -m evals.p2n_authorization_freshness
python -m evals.p2o_authorization_provenance
python -m evals.p2p_rollback_resistant_anchor
python -m evals.p2q_control_plane_recovery
python -m evals.p2r_protected_checkpoint
```

P2-R uses two fixed adversarial attempts and two benign attempts per variant. A1 advances a subject revocation from generation 1 to generation 2; A2 rotates the authorization signing key from epoch 1 to epoch 2 while advancing the generation. After each change is fully checkpointed, the evaluator restores **both** rollback-restorable local control-plane databases to their generation-1 snapshots while leaving the protected checkpoint at generation 2. The local-only comparison accepts the obsolete state and records a first synthetic effect. The hardened P2-R variant detects that the protected generation is ahead, records no effect, and leaves the outbox retryable. The benign set verifies current generation-1 authority and a correctly protected generation-2 key rotation still complete exactly once.

Reports include raw ASR/FPR/SafeTaskRate numerators and denominators plus code/dependency/model/prompt/policy/dataset evidence. P2-R reports only non-sensitive protocol status, generations/epochs, effect counts, outbox status, and rejection reason codes. Raw change payloads, signatures, private-key bytes, approval IDs, idempotency keys, database contents, raw effect arguments, credentials, and real external side effects are excluded.

Threat-model evidence:

- `docs/threat-model/p2a-tenant-boundary.md`
- `docs/threat-model/p2b-indirect-prompt-injection.md`
- `docs/threat-model/p2c-mcp-tool-poisoning.md`
- `docs/threat-model/p2d-token-passthrough.md`
- `docs/threat-model/p2e-ssrf-redirects.md`
- `docs/threat-model/p2f-durable-memory-poisoning.md`
- `docs/threat-model/p2g-resource-exhaustion.md`
- `docs/threat-model/p2h-telemetry-redaction.md`
- `docs/threat-model/p2i-malicious-artifacts.md`
- `docs/threat-model/p2j-browser-prompt-injection.md`
- `docs/threat-model/p2k-durable-approval-workflow.md`
- `docs/threat-model/p2l-transactional-outbox.md`
- `docs/threat-model/p2m-execution-time-authorization.md`
- `docs/threat-model/p2n-authorization-freshness.md`
- `docs/threat-model/p2o-authorization-provenance.md`
- `docs/threat-model/p2p-rollback-resistant-trust-anchor.md`
- `docs/threat-model/p2q-control-plane-recovery.md`
- `docs/threat-model/p2r-protected-recovery-checkpoint.md`

### Prototype limitations

P2-R is a deterministic protected-checkpoint proof, not a production external trust service. The repository's `SyntheticProtectedCheckpointAuthority` is another SQLite file so the entire lab remains local and reproducible. It models a distinct protected rollback domain by excluding that file from the two-database restore attack; merely placing three SQLite files on the same production host would not provide the claimed independence.

If an attacker can roll back, delete, equivocate, or compromise the protected checkpoint authority together with both local databases, this lab has no fourth independent fact with which to detect that coordinated restore. Production needs an authenticated and operationally independent monotonic authority appropriate to the deployment, plus provisioning, compromise recovery, backup/restore, and availability procedures.

All covered authorization-state writers must use the P2-Q/P2-R coordinator path. Direct database writes can violate the prepared/applied/active journal and protected-head invariant. Production needs write-path exclusivity, database permissions, authenticated administrative APIs, auditable change identity, and reliable startup/failure recovery.

P2-R does not implement distributed consensus, multi-region generation allocation, quorum replication, cross-host fencing leases, Byzantine-fault tolerance, hardware attestation, a TPM/HSM/cloud-KMS integration, or a remote transparency/checkpoint service. Protected-authority unavailability or inconsistency intentionally stops new authorization issuance and first-effect execution, so availability is traded for safety.

Only the subject-state, password-reset-policy, and authorization-signing-key mutations routed through the covered coordinator receive the execution-marker and protected-checkpoint guarantee. Future authorization tables or trust roots must use the same protocol rather than being updated independently. The local `BEGIN IMMEDIATE` locking strategy prioritizes a simple safety invariant over production concurrency and throughput.

P2-O remains a local signed-evidence proof, not a production PKI or distributed authorization platform. Production still needs protected issuer private-key custody, authenticated trust-root/public-key distribution, compromise recovery, secure rotation and revocation procedures, clock guarantees, algorithm agility, multi-region authoritative version allocation, and point-of-use enforcement at the real side-effecting service.

P2-L's exactly-once limitation still applies: a transactional outbox, signed freshness fence, rollback anchor, crash-safe recovery protocol, and protected checkpoint cannot guarantee exactly-once business outcomes. The real side-effecting system must provide a durable idempotency contract whose retention exceeds all plausible replay windows.

The downstream effect service intentionally records only a synthetic local ledger entry. AegisDesk does not grant real access or reset real credentials.

P2-J is a synthetic fetch-and-model trust-boundary proof, not a production browser. It does not execute JavaScript or model a full DOM, cookies, authenticated browser sessions, cross-origin policy, extensions, downloads, form submission, service workers, renderer sandbox escapes, or real Internet navigation.

P2-I is a local stdlib-only ingestion proof, not a malware scanner or document-sanitization platform. Production artifact handling still needs authenticated object storage, per-tenant access control, quarantine and scanning where appropriate, retention/deletion rules, storage quotas, media-specific parser sandboxing, and browser response hardening.

P2-H proves application-side telemetry minimization before an in-memory sink. A production observability pipeline still needs protected HMAC-key storage and rotation, transport encryption, collector/backend access control, retention limits, tenant-aware query authorization, and periodic secret scanning.

P2-G remains an in-process resource-control proof. A production agent still needs provider-side token/cost limits, cancellation for hung tools, streaming byte caps, distributed quotas, concurrency/load shedding, and operating-system/container CPU and memory isolation.

## Synthetic identities

- Employee, Dynamics: `alice@northstar-dynamics.test`
- Approver, Dynamics: `carol.approver@northstar-dynamics.test`
- Employee, Digital: `bob@northstar-digital.test`
- Approver, Digital: `dave.approver@northstar-digital.test`

`X-Aegis-User` is a synthetic lab authentication handle, not a production authentication design.

All organizations, identities, records, credentials, canaries, poison documents, MCP servers, network routes, browser pages, memory records, resource-exhaustion workloads, telemetry records, artifacts, archives, approval workflows, outbox messages, authorization replicas, policy/revocation version counters, authorization-signing key labels, trusted public keys, signing-key epochs, control-plane generations, control-plane change journals, execution-generation markers, protected checkpoint generations, protected journal-head hashes, current authorization-state rows, policy changes, downstream effect ledger rows, database snapshots, crash injections, recovery operations, and side effects in this repository are synthetic.
