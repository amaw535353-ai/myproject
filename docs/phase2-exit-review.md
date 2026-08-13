# Phase 2 exit review: authoritative control and evidence registry

## Decision

Phase 2 is **evidence-complete but not production-wired-complete**.

The repository now has one machine-readable source of truth for P2-A through P2-S in `aegis/security/phase2_controls.py`. The deterministic exit gate `python -m evals.phase2_exit_gate` fails if a Phase 2 milestone disappears, its threat model or evaluation is missing, CI stops running its evaluation, a declared runtime evidence path disappears, or a non-default control has no explicit Phase 3 gap.

Passing this gate means the laboratory evidence set is coherent. It does **not** mean that every hardened control is active in the default FastAPI runtime, nor does it turn local synthetic proofs into production guarantees.

## Runtime posture

The registry distinguishes three states:

- `default_api`: the control is on a path constructed by `apps/api/dependencies.py` or directly enforced by a default FastAPI route.
- `partial_default_api`: part of the property is enforced in the default API, but the full Phase 2 control proved by the matched evaluation is not yet wired.
- `lab_only`: the hardened implementation and matched evaluation exist, but the default API does not construct that control path.

Current classification: **7 default API, 1 partial default API, 11 lab-only**. This distinction prevents a green laboratory evaluation from being mistaken for a default-runtime guarantee.

## Control and evidence matrix

| Control | Security property | Runtime posture | Threat/eval evidence | Phase 3 gap |
|---|---|---|---|---|
| P2-A | Server-derived tenant plus mandatory tenant-filtered RAG | default API | `p2a-tenant-boundary.md` / `evals.p2a_tenant_boundary` | — |
| P2-B | Retrieved text cannot grant tool authority | default API | `p2b-indirect-prompt-injection.md` / `evals.p2b_indirect_prompt_injection` | — |
| P2-C | Host-owned MCP server/tool binding | default API | `p2c-mcp-tool-poisoning.md` / `evals.p2c_mcp_tool_poisoning` | — |
| P2-D | No inbound bearer passthrough; brokered downstream authority | lab only | `p2d-token-passthrough.md` / `evals.p2d_token_passthrough` | P3-G04 |
| P2-E | DNS/redirect revalidation before outbound connection | lab only | `p2e-ssrf-redirects.md` / `evals.p2e_ssrf_redirects` | P3-G03 |
| P2-F | Durable memory is data, never identity/tenant/role/approval authority | lab only | `p2f-durable-memory-poisoning.md` / `evals.p2f_durable_memory_poisoning` | P3-G05 |
| P2-G | Server-owned step/model/tool/retry/byte/time budgets | partial default API | `p2g-resource-exhaustion.md` / `evals.p2g_resource_exhaustion` | P3-G02 |
| P2-H | Typed allowlisted pseudonymized telemetry | default API | `p2h-telemetry-redaction.md` / `evals.p2h_telemetry_leakage` | — |
| P2-I | Server-owned artifact paths, passive rendering, bounded extraction | lab only | `p2i-malicious-artifacts.md` / `evals.p2i_artifact_handling` | P3-G03 |
| P2-J | Webpage content cannot grant tool authority | lab only | `p2j-browser-prompt-injection.md` / `evals.p2j_browser_prompt_injection` | P3-G03 |
| P2-K | Restart-safe bound human approval and one-time workflow completion | default API | `p2k-durable-approval-workflow.md` / `evals.p2k_durable_approval_workflow` | — |
| P2-L | Atomic approval-to-outbox handoff and idempotent synthetic effect | default API | `p2l-transactional-outbox.md` / `evals.p2l_transactional_outbox` | — |
| P2-M | Current authorization revalidated at first effect | default API | `p2m-execution-time-authorization.md` / `evals.p2m_execution_time_authorization` | — |
| P2-N | Authoritative policy/revocation version freshness fence | lab only | `p2n-authorization-freshness.md` / `evals.p2n_authorization_freshness` | P3-G01 |
| P2-O | Signed issuer/audience/binding/key-epoch provenance | lab only | `p2o-authorization-provenance.md` / `evals.p2o_authorization_provenance` | P3-G01, P3-G06 |
| P2-P | Independent monotonic generation rollback fence | lab only | `p2p-rollback-resistant-trust-anchor.md` / `evals.p2p_rollback_resistant_anchor` | P3-G01, P3-G06 |
| P2-Q | Crash-safe prepared/applied/active control-plane convergence | lab only | `p2q-control-plane-recovery.md` / `evals.p2q_control_plane_recovery` | P3-G01 |
| P2-R | Protected checkpoint outside the local rollback set | lab only | `p2r-protected-recovery-checkpoint.md` / `evals.p2r_protected_checkpoint` | P3-G01, P3-G06 |
| P2-S | Authenticated predecessor-linked checkpoint history plus equivocation detection | lab only | `p2s-checkpoint-authenticity.md` / `evals.p2s_checkpoint_authenticity` | P3-G01, P3-G06 |

All threat-model files above live under `docs/threat-model/`.

## Phase 3 gap register

**P3-G01 — consolidate the high-impact authorization/effect chain.** The default API constructs P2-K, P2-L, and P2-M. P2-N through P2-S are hardened local control-plane primitives and evaluations, but they are not instantiated by `apps/api/dependencies.py`. Phase 3 should make one authoritative server-owned path instead of stacking alternative workers and services in parallel.

**P3-G02 — wire the complete execution budget.** The default `AgentRunner` has a coarse single-tool-call guard. The full P2-G budget covers steps, model/tool calls, retries, input/context/result bytes, repeated calls, and elapsed time. Phase 3 should make that budget the normal runner contract rather than an evaluation-only loop.

**P3-G03 — make optional edge surfaces explicit.** Browser, artifact ingestion, and outbound fetch controls are hardened lab components but are not default API routes. Phase 3 must either compose those boundaries into an intentional runtime surface or keep the surfaces isolated and state that they are not part of the default product.

**P3-G04 — preserve credential termination when a downstream service is introduced.** The default API asset lookup is an in-process synthetic store, so it does not exercise the P2-D credential broker. Any future downstream adapter must terminate inbound credentials and use server-owned least-privilege service authority.

**P3-G05 — choose a memory posture before adding memory.** The default API has no durable-memory feature. If memory becomes a runtime feature, it must enter only as untrusted data and must not mutate principal, tenant, roles, or approval authority.

**P3-G06 — replace synthetic trust anchors before production claims.** P2-O through P2-S intentionally use deterministic local keys and SQLite trust abstractions. Production needs deployment-appropriate protected key custody, authenticated trust distribution, durable rollback-resistant checkpoint/witness state, recovery, and availability procedures. The local lab does not claim consensus or global split-view detection.

## Phase 3 entry invariant

The first Phase 3 implementation milestone should not add another parallel security worker. It should consolidate the default high-impact request path so that one server-owned composition carries approval binding, transactional outbox/idempotency, execution-time authorization, freshness, provenance, generation recovery, protected checkpoint, and authenticated checkpoint-history validation in one explicit dependency graph.

High-impact tools remain request/approval workflows only. The consolidation must continue to use synthetic local effects and must not grant real access, issue credentials, or reset real passwords.
