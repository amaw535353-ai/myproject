# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P2-M

P2-M adds **execution-time authorization revalidation for approved high-impact effects**. A historical human approval remains necessary, but it is no longer treated as permanent authority: the first synthetic effect is allowed only when current server-owned subject, tenant, role, resource, ownership, and tenant-policy state still authorize it.

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
- current authorization is revalidated atomically with the first synthetic effect insert;
- execution-time denial creates durable terminal state so old approval cannot revive after authorization restoration;
- intentionally vulnerable demonstrations remain isolated and use only local synthetic effects;
- deterministic fake/no-model evaluations, Qdrant local mode, SQLite, in-memory MCP, and GitHub Actions require no paid model API.

P2-K introduced `DurableApprovalStore` and `DurableWorkflowStore`, preserving requester/tenant/action/normalized-argument binding across process restart. P2-L extended that boundary with `TransactionalEffectCoordinator`: approval consumption and creation of the bound outbox message happen inside one SQLite transaction. The outbox is not populated from model-visible authority or resume-time client arguments.

The P2-L downstream `SyntheticIdempotentEffectService` uses a separate local SQLite ledger keyed by a server-derived idempotency key. At-least-once delivery remains safe across crash-after-effect and duplicate worker delivery because the downstream returns the existing identical synthetic effect instead of recording a duplicate.

P2-M replaces the hardened downstream worker/service with `RevalidatingDurableEffectWorker` and `SyntheticRevalidatingEffectService`. Current synthetic authorization state and the downstream effect ledger share the execution database, so the decisive current-authorization read and first effect insert occur inside one `BEGIN IMMEDIATE` transaction. If current authorization is invalid, the service records a bound denial tombstone and the worker cancels the outbox. Restoring authorization later does not resurrect the old approval.

An already-recorded idempotent effect is checked before revalidation. This preserves P2-L crash recovery: if an effect was validly authorized and committed before a worker crashed, a later revocation does not cause retry to duplicate or strand that already-executed outcome.

The intentionally vulnerable P2-M comparison retains P2-L's transactional outbox and idempotent downstream ledger but ignores the same current authorization state. Its only intended defect is treating historical approval as sufficient execution authority.

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
```

P2-M uses two fixed adversarial attempts and two benign attempts per variant. The adversarial set disables the requester after approval and changes a resource owner after approval. The benign set verifies unchanged authorized access and password-reset policy still complete exactly once.

Reports include raw ASR/FPR/SafeTaskRate numerators and denominators plus code/dependency/model/prompt/policy/dataset evidence. Approval IDs, idempotency keys, raw authorization rows, raw effect arguments, effect references, credentials, and real external side effects are excluded.

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

### Prototype limitations

P2-M is a single-node SQLite authorization-freshness proof. Production effect delivery still needs an authoritative identity/policy service, explicit policy-version and revocation semantics, cache-consistency guarantees, worker leasing and retry controls, shared transactional durability, downstream independent authorization, remediation/reconciliation, and disaster recovery. In a distributed system, an application-side authorization check can itself be stale; the side-effecting system should enforce current least privilege or validate a short-lived, tightly scoped capability at the point of use.

P2-L's exactly-once limitation still applies: a transactional outbox alone cannot guarantee exactly-once business outcomes. The real side-effecting system must provide a durable idempotency contract whose retention exceeds all plausible replay windows.

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

All organizations, identities, records, credentials, canaries, poison documents, MCP servers, network routes, browser pages, memory records, resource-exhaustion workloads, telemetry records, artifacts, archives, approval workflows, outbox messages, current authorization-state rows, policy changes, downstream effect ledger rows, and side effects in this repository are synthetic.
