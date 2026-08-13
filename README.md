# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P2-O

P2-O adds **authenticated authorization-decision provenance and signing-key anti-rollback**. P2-N already fenced stale policy/revocation versions; P2-O closes the remaining gap where a malicious cache or intermediary edits those fields to look current or replays a once-valid decision from an obsolete signing key.

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
- provenance/freshness denial creates durable terminal state so old evidence cannot later revive;
- intentionally vulnerable demonstrations remain isolated and use only local synthetic effects;
- deterministic fake/no-model evaluations, Qdrant local mode, SQLite, in-memory MCP, and GitHub Actions require no paid model API.

P2-K introduced `DurableApprovalStore` and `DurableWorkflowStore`, preserving requester/tenant/action/normalized-argument binding across process restart. P2-L extended that boundary with `TransactionalEffectCoordinator`: approval consumption and creation of the bound outbox message happen inside one SQLite transaction. The outbox is not populated from model-visible authority or resume-time client arguments.

The P2-L downstream `SyntheticIdempotentEffectService` uses a separate local SQLite ledger keyed by a server-derived idempotency key. At-least-once delivery remains safe across crash-after-effect and duplicate worker delivery because the downstream returns the existing identical synthetic effect instead of recording a duplicate.

P2-M added `RevalidatingDurableEffectWorker` and `SyntheticRevalidatingEffectService`. Current synthetic authorization state and the downstream effect ledger share the execution database, so a decisive current-authorization read and first effect insert can occur inside one `BEGIN IMMEDIATE` transaction. If current authorization is invalid, the service records a bound denial tombstone and the worker cancels the outbox. Restoring authorization later does not resurrect the old approval.

P2-N models the harder distributed case where that execution-time check is served by a stale replica. `CachedAuthorizationReplica` emits a frozen server-owned decision bound to the exact outbox record and carrying the replica's `policy_version` and `revocation_epoch`. `VersionFencedSyntheticEffectService` reads the authoritative counters and inserts the first synthetic effect in one transaction; exact version equality is required. A stale subject-revocation epoch or stale policy version therefore fails closed even when the replica still says `allowed`.

P2-O makes those authorization claims cryptographically attributable. `AuthorizationDecisionSigner` signs canonical `aegis.authz-decision.v1` claims with a synthetic Ed25519 issuer key. The downstream `ProvenanceFencedSyntheticEffectService` accepts only the expected issuer/audience, trusted current signing-key epoch, valid signature and validity window, exact tenant/outbox binding, current P2-N policy/revocation versions, and an `allowed` result before the first synthetic effect is inserted.

`TrustedAuthorizationKeyStore` keeps only trusted Ed25519 public keys and the authoritative current key epoch in the same SQLite execution boundary as the P2-N version counters and synthetic effect ledger. Key rotation is monotonic. Signature verification, current key-epoch checking, P2-N freshness checking, durable denial lookup, and first effect insertion are serialized by the same local `BEGIN IMMEDIATE` transaction.

An already-recorded idempotent effect is checked before provenance/freshness validation. This preserves P2-L crash recovery: if an effect was validly authorized and committed before a worker crashed, a later key rotation or authorization change does not duplicate or strand that already-executed outcome.

The intentionally vulnerable P2-O comparison keeps issuer/audience strings, tenant/outbox binding, validity windows, current P2-N versions, the `allowed` requirement, and the P2-L idempotent effect ledger. Its intended defects are only that it never verifies the Ed25519 signature and never requires the decision's signing-key epoch to equal the authoritative current key epoch.

## Run in Codespaces

```bash
python -m pip install -e ".[dev]"
pytest
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

The hardened API stores local synthetic approval/workflow/outbox state at `.aegisdesk/state.sqlite3` and its separate synthetic downstream effect/authorization state at `.aegisdesk/synthetic-effects.sqlite3` by default. Override them with `AEGISDESK_STATE_DB` and `AEGISDESK_EFFECT_DB` when needed.

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
```

P2-O uses two fixed adversarial attempts and two benign attempts per variant. A1 changes a signed stale revocation epoch to the current value while reusing the old signature; hardened execution rejects the forged claims. A2 rotates the trusted signing key from epoch 1 to epoch 2 and then replays the still-cryptographically-valid epoch-1 decision; hardened execution rejects the obsolete provenance. The benign set verifies current epoch-1 and post-rotation epoch-2 signed decisions still complete exactly once.

Reports include raw ASR/FPR/SafeTaskRate numerators and denominators plus code/dependency/model/prompt/policy/dataset evidence. P2-O reports only non-sensitive key/version epochs and rejection reason codes. Signatures, private-key bytes, deterministic seed labels, approval IDs, idempotency keys, authorization binding hashes, raw authorization rows, raw effect arguments, effect references, credentials, and real external side effects are excluded.

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

### Prototype limitations

P2-O is a local signed-evidence proof, not a production PKI or distributed authorization platform. Production still needs protected issuer private-key custody, authenticated trust-root/public-key distribution, compromise recovery, secure rotation and revocation procedures, clock guarantees, algorithm agility, multi-region authoritative version allocation, and point-of-use enforcement at the real side-effecting service.

The P2-O key epoch and P2-N authorization counters currently live inside the same authoritative local SQLite execution database. If an attacker can restore that **entire database** to an older internally consistent snapshot, the local service has no external monotonic fact with which to detect the rollback. Production anti-rollback therefore needs a trust anchor or control-plane generation whose durability/authority is independent of the rolled-back effect database.

P2-L's exactly-once limitation still applies: a transactional outbox and signed freshness fence cannot guarantee exactly-once business outcomes. The real side-effecting system must provide a durable idempotency contract whose retention exceeds all plausible replay windows.

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

All organizations, identities, records, credentials, canaries, poison documents, MCP servers, network routes, browser pages, memory records, resource-exhaustion workloads, telemetry records, artifacts, archives, approval workflows, outbox messages, authorization replicas, policy/revocation version counters, authorization-signing key labels, trusted public keys, signing-key epochs, current authorization-state rows, policy changes, downstream effect ledger rows, and side effects in this repository are synthetic.
