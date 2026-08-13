# AegisDesk: Zero-Trust Agentic RAG Security Lab

AegisDesk is a production-style AI security portfolio lab for building, attacking, and hardening a multi-tenant help-desk agent.

## Current milestone: P2-K

P2-K adds **durable approval/workflow persistence with restart-safe anti-replay**. High-impact tools still create pending approval records only; they never directly grant access or reset a password.

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
- intentionally vulnerable demonstrations remain isolated and use only local synthetic effects;
- deterministic fake/no-model evaluations, Qdrant local mode, SQLite, in-memory MCP, and GitHub Actions require no paid model API.

P2-K replaces the application approval ledger with `DurableApprovalStore`, backed by local SQLite. Approval records preserve the existing nonce/requester/tenant/action/normalized-argument binding and use atomic state transitions. A server-owned `DurableWorkflowStore` persists the exact resume context required after a restart. When a high-impact MCP request is created inside an agent workflow, the approval record and pending workflow row are inserted in the same SQLite transaction.

The restart rules are intentionally strict. Repeating the same already-recorded reviewer decision is accepted only as crash recovery while the durable workflow is still pending. This allows recovery after a crash between review and consumption, or between consumption and workflow completion. Once the workflow journal is marked `completed`, every later resume attempt is rejected. Conflicting reviewers, decisions, tenants, requesters, actions, or argument sets are rejected.

The P2-K vulnerable comparison persists only a coarse approved/rejected status, trusts caller-supplied authority at resume time, and never consumes approved state. This makes approvals replayable and transferable after synthetic restarts.

## Run in Codespaces

```bash
python -m pip install -e ".[dev]"
pytest
uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
```

The hardened API stores its local synthetic approval/workflow state at `.aegisdesk/state.sqlite3` by default. Override this with `AEGISDESK_STATE_DB=/path/to/state.sqlite3` when needed.

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
```

P2-K uses two fixed adversarial attempts and two benign attempts per variant. The adversarial set tests replay after restart and requester/tenant/argument rebinding. The benign set verifies that legitimate access and password-reset approval workflows survive restart and complete exactly once.

Reports include raw ASR/FPR/SafeTaskRate numerators and denominators plus code/dependency/model/prompt/policy/dataset evidence. Approval IDs, nonces, binding hashes, raw workflow arguments, credentials, and real external side effects are excluded.

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

### Prototype limitations

P2-K uses SQLite as a single-node local durability proof. Production approval orchestration still needs a transactional shared database, migrations and backup/restore procedures, HA/failover behavior, storage access controls, concurrency testing for multiple reviewers and workers, retention/deletion policy, and an idempotent outbox/idempotency-key pattern around any future real downstream side effect. The current high-impact tools intentionally stop at approval state and never perform a real grant or password reset.

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

All organizations, identities, records, credentials, canaries, poison documents, MCP servers, network routes, browser pages, memory records, resource-exhaustion workloads, telemetry records, artifacts, archives, approval workflows, and side effects in this repository are synthetic.
