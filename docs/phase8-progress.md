# Phase 8 progress — agentic trust, delegation, state, goal, observation, resource, and autonomy integrity

Phase 8 broadens AegisDesk into security properties specific to cooperating autonomous agents. P8-A established delegation/authority propagation, P8-B memory/context boundaries, P8-C goal/plan integrity, P8-D tool-result and environment integrity, P8-E execution-budget/runaway-resource security, and P8-F now adds human handoff, approval, and autonomy-boundary security.

## P8-A through P8-E

P8-A through P8-E are complete for the current deterministic synthetic-lab scope. Their established evidence covers multi-agent delegation, stateful memory boundaries, instruction/goal/plan integrity, exact invocation→result→observation/environment binding, and bounded execution/resource consumption.

## P8-F — human handoff, approval, and autonomy-boundary security

Status: **implemented and deterministically exercised in an isolated API-compatible harness; hosted runner execution pending infrastructure**.

P8-F adds `HumanHandoffAutonomySecurityAnalyzer`. Human approval is modeled as evidence, not a caller-owned boolean. The canonical fixture contains **5 approval rules, 5 pending actions, and 5 approval records** spanning low-risk search, tenant ticket mutation, irreversible release deployment, security telemetry mutation, and authorization-policy mutation.

The hardened boundary enforces exact graph and P8-C/P8-D/P8-E evidence binding; policy-pinned autonomy ceilings; mandatory human review for sensitive/irreversible actions; exact argument and plan SHA-256 binding; reviewer identity-to-role/group authorization; self-approval rejection; approval freshness/future-skew; replay detection; explicit approve/reject/edit semantics; edit authorization; independent two-person review where required; an unconditional human stop for irreversible actions; upstream step/observation/budget safety; and rejection of caller outcome/risk summaries that disagree with derived evidence.

Missing required approval yields a deterministic `PAUSE`, preserving a safe waiting state. Stale, replayed, self-approved, rejected, malformed, incorrectly bound, or autonomy-bypassing approval evidence yields `DENY`.

### Free/open-source implementation path

No new runtime dependency was added. P8-F was designed to remain compatible with a free/open-source control stack:

- LangGraph's MIT-licensed `interrupt()` and human-in-the-loop middleware can provide pause/resume mechanics for approve/edit/reject decisions;
- Open Policy Agent (OPA), Apache-2.0, can externalize review-required and reviewer-role policy decisions;
- OpenFGA, Apache-2.0, can provide self-hosted fine-grained reviewer/resource authorization; and
- OpenTelemetry, Apache-2.0, can carry approval request/decision/interrupt/resume events into a vendor-neutral audit pipeline.

These are optional integration paths, not dependencies or production-enforcement claims in P8-F.

### Deterministic evidence

An isolated API-compatible P8-F harness passed **14 tests** and completed **92 adversarial cases**:

- vulnerable ASR: **92/92**;
- hardened ASR: **0/92**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- graph SHA-256: `46292dfaf712acd8f11a1a6ee7d9d75f7f4c63ea1627affc773741b05190321d`;
- dataset SHA-256: `59f114bb2f54ce4089b201b7a51871f19eda70978b169b7a12a02591a5f1d518`;
- fixture SHA-256: `4eed658957e8230d4d5e1478b0d1a34634fef5e52884febeba9f5ea3b1e4b050`;
- clean assessment SHA-256: `e27860604d4d3cda8fa6eeb2c836f7f4714fd489d527a681378898a69c981960`.

This is not a claim that full-repository pytest ran locally or that production approval/identity systems were exercised. GitHub-hosted workflow execution remains subject to the existing account billing/spending-limit runner-provisioning condition.

## Phase 8 status

- P8-A: complete for current deterministic synthetic scope.
- P8-B: complete for current deterministic synthetic scope.
- P8-C: complete for current deterministic synthetic scope.
- P8-D: complete for current deterministic synthetic scope.
- P8-E: complete for current deterministic synthetic scope.
- P8-F: implemented with isolated deterministic evidence; hosted execution remains infrastructure-blocked.

## Next direction

P8-G should broaden into **agent communications, message-bus, and inter-agent protocol security**: authenticated sender/receiver identities, tenant/task/goal correlation, message freshness/replay protection, schema and capability negotiation, prevention of cross-agent command laundering, channel authorization, and safe handling of untrusted or partially trusted agent messages.
