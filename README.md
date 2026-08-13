# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P2-P

P2-P adds a **rollback-resistant authorization trust anchor**. P2-O authenticated authorization evidence, but its signing-key epoch, authorization versions, and trusted public-key state all lived in the same execution database. Restoring that whole database to an older internally consistent snapshot could therefore make obsolete signed evidence look current again. P2-P introduces an independently durable monotonic control-plane generation and cryptographically binds each authorization envelope to it.

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
- the independent generation lock is held from generation read through the first effect commit, giving the local lab a total order between generation advancement and effect execution;
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

An already-recorded idempotent effect is checked by the inner P2-O service before provenance/freshness validation. This preserves P2-L crash recovery: if an effect was validly authorized and committed before a worker crashed, later key/version/generation changes do not duplicate the already-executed outcome.

The intentionally vulnerable P2-P comparison inherits the full P2-O signed-provenance service. It still verifies the inner Ed25519 decision, current local signing-key epoch, current local policy/revocation versions, tenant/outbox binding, validity window, and the `allowed` result. Its intended defect is only that it ignores the independent control-plane generation and the outer envelope signature, so an old but internally self-consistent execution-database snapshot can restore authorization authority.

## Run in Codespaces

```bash
python -m pip install -e ".[dev]"
pytest
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

The hardened API stores local synthetic approval/workflow/outbox state at `.aegisdesk/state.sqlite3` and its separate synthetic downstream effect/authorization state at `.aegisdesk/synthetic-effects.sqlite3` by default. P2-P's independent control-plane generation is currently an evaluation/control-plane primitive rather than a new default API runtime file. Override the existing state/effect paths with `AEGISDESK_STATE_DB` and `AEGISDESK_EFFECT_DB` when needed.

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
```

P2-P uses two fixed adversarial attempts and two benign attempts per variant. A1 snapshots generation-1 execution state, revokes the synthetic subject and advances the independent anchor to generation 2, then restores only the execution database and replays the generation-1 envelope. A2 repeats the pattern around signing-key rotation from epoch 1 to epoch 2. In both cases the vulnerable P2-O-only service sees locally self-consistent old state and executes, while the hardened P2-P service rejects `control_plane_generation_mismatch`. The benign set verifies current generation-1/key-epoch-1 and generation-2/key-epoch-2 effects still complete exactly once.

Reports include raw ASR/FPR/SafeTaskRate numerators and denominators plus code/dependency/model/prompt/policy/dataset evidence. P2-P reports only non-sensitive generations, key/version epochs, effect counts, outbox status, and rejection reason codes. Signatures, private-key bytes, deterministic seed labels, approval IDs, idempotency keys, authorization binding hashes, database contents, raw effect arguments, effect references, credentials, and real external side effects are excluded.

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

### Prototype limitations

P2-P is a local rollback-detection proof, not a production rollback-resistant control plane. The independent anchor is another SQLite file on the same host. If an attacker can atomically restore **both** the execution database and the anchor database, this prototype has no external fact with which to detect that rollback. Production needs an independently protected, authenticated, rollback-resistant generation authority appropriate to the deployment.

The local P2-P anchor lock orders local generation advancement and effect commits only when every participant uses `ControlPlaneGenerationStore`; it is not distributed consensus and does not cover multi-host split brain, bypassing the store, compromised host administration, or storage snapshots that include the anchor.

P2-P also does not make execution-database security-state mutation and independent generation advancement one atomic cross-database commit. Production needs a control-plane commit/recovery protocol that prevents or safely recovers from partial state/generation updates.

P2-O remains a local signed-evidence proof, not a production PKI or distributed authorization platform. Production still needs protected issuer private-key custody, authenticated trust-root/public-key distribution, compromise recovery, secure rotation and revocation procedures, clock guarantees, algorithm agility, multi-region authoritative version allocation, and point-of-use enforcement at the real side-effecting service.

P2-L's exactly-once limitation still applies: a transactional outbox, signed freshness fence, and rollback anchor cannot guarantee exactly-once business outcomes. The real side-effecting system must provide a durable idempotency contract whose retention exceeds all plausible replay windows.

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

All organizations, identities, records, credentials, canaries, poison documents, MCP servers, network routes, browser pages, memory records, resource-exhaustion workloads, telemetry records, artifacts, archives, approval workflows, outbox messages, authorization replicas, policy/revocation version counters, authorization-signing key labels, trusted public keys, signing-key epochs, control-plane generations, current authorization-state rows, policy changes, downstream effect ledger rows, database snapshots, and side effects in this repository are synthetic.
