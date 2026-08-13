# Phase 2 Exit Review — P3-A

**Decision:** PASS for deterministic local lab objectives.  
**Phase 3 entry:** READY WITH OPEN INTEGRATION GAPS.  
**Production readiness:** No.

`docs/security/phase2-control-evidence.json` is the machine-checked source of truth for the P2-A through P2-S control inventory, evidence paths, runtime status, and Phase 3 actions.

## Runtime promotion summary

The registry deliberately distinguishes proven controls from default runtime authority:

- `default_api` — directly composed into the relevant default FastAPI path.
- `component_only` — hardened reusable component exists, while the corresponding optional feature is not default wiring.
- `evaluation_only` — hardened control-plane primitive is proven deterministically but is not default application authority.

At exit there are **6 `default_api`**, **7 `component_only`**, and **6 `evaluation_only`** controls. The default high-impact workflow currently carries durable approval, transactional delivery, and execution-time revalidation through P2-M. P2-N through P2-S remain control-plane proofs awaiting Phase 3 consolidation.

## Control/evidence matrix

| Control | Boundary | Status | Hardened evidence | Evaluation |
|---|---|---|---|---|
| P2-A | Tenant-safe RAG | `default_api` | `aegis/rag/store.py` | `evals.p2a_tenant_boundary` |
| P2-B | Retrieved-content capability boundary | `default_api` | `aegis/rag/answering.py` | `evals.p2b_indirect_prompt_injection` |
| P2-C | MCP host/tool binding | `component_only` | `aegis/mcp_gateway/host_registry.py` | `evals.p2c_mcp_tool_poisoning` |
| P2-D | Credential termination/brokering | `component_only` | `aegis/mcp_gateway/downstream_proxy.py` | `evals.p2d_token_passthrough` |
| P2-E | URL/DNS/redirect policy | `component_only` | `aegis/network/fetcher.py` | `evals.p2e_ssrf_redirects` |
| P2-F | Memory is data, not authority | `component_only` | `aegis/memory/service.py` | `evals.p2f_durable_memory_poisoning` |
| P2-G | Agent resource budgets | `component_only` | `aegis/agent/bounded_loop.py` | `evals.p2g_resource_exhaustion` |
| P2-H | Minimized security telemetry | `default_api` | `aegis/observability/security_events.py` | `evals.p2h_telemetry_leakage` |
| P2-I | Bounded artifact handling | `component_only` | `aegis/artifacts/service.py` | `evals.p2i_artifact_handling` |
| P2-J | Browser content trust boundary | `component_only` | `aegis/browser/answering.py` | `evals.p2j_browser_prompt_injection` |
| P2-K | Durable approval workflow | `default_api` | `aegis/approvals/durable.py` | `evals.p2k_durable_approval_workflow` |
| P2-L | Transactional idempotent effects | `default_api` | `aegis/effects/durable.py` | `evals.p2l_transactional_outbox` |
| P2-M | Execution-time authorization | `default_api` | `aegis/effects/revalidation.py` | `evals.p2m_execution_time_authorization` |
| P2-N | Authorization freshness | `evaluation_only` | `aegis/effects/versioned_revalidation.py` | `evals.p2n_authorization_freshness` |
| P2-O | Authorization provenance | `evaluation_only` | `aegis/effects/signed_authorization.py` | `evals.p2o_authorization_provenance` |
| P2-P | Rollback-resistant generation | `evaluation_only` | `aegis/effects/rollback_anchor.py` | `evals.p2p_rollback_resistant_anchor` |
| P2-Q | Crash-safe control-plane recovery | `evaluation_only` | `aegis/effects/control_plane_recovery.py` | `evals.p2q_control_plane_recovery` |
| P2-R | Protected recovery checkpoint | `evaluation_only` | `aegis/effects/protected_checkpoint.py` | `evals.p2r_protected_checkpoint` |
| P2-S | Authenticated checkpoint history | `evaluation_only` | `aegis/effects/checkpoint_receipt_boundary.py` | `evals.p2s_checkpoint_authenticity` |

## Exit gate

`python -m aegis.security.phase2_exit` validates the exact P2-A→P2-S set, runtime classifications, referenced hardened/comparison/threat/evaluation files, isolated comparison paths, complete Phase 2 threat-model registration, CI evaluation coverage, release-version consistency, required exit artifacts, and the presence of the critical Phase 3 gap records.

P3-A synchronizes the package, FastAPI, and registry release version at `0.23.0`.

Passing this gate means the local Phase 2 security lab is reproducible and its promotion state is explicit. It is not a production-readiness claim. Open integration work is tracked in `phase3-gap-register.md`.
