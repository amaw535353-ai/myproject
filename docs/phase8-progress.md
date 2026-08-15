# Phase 8 progress — agentic trust, delegation, state, goal, observation, and resource integrity

Phase 8 broadens AegisDesk into security properties specific to cooperating autonomous agents. P8-A established delegation/authority propagation, P8-B memory/context boundaries, P8-C goal/plan integrity, P8-D tool-result and environment integrity, and P8-E now adds execution-budget and runaway-resource security.

## P8-A through P8-D

P8-A through P8-D are complete for the current deterministic synthetic-lab scope. Their established evidence covers multi-agent delegation, stateful memory boundaries, instruction/goal/plan integrity, and exact invocation→result→observation/environment binding.

## P8-E — agent execution budget, resource, and runaway-execution security

Status: **implemented and deterministically exercised in an isolated byte-for-byte harness; hosted runner execution pending infrastructure**.

P8-E adds `AgentExecutionBudgetSecurityAnalyzer`. The canonical fixture contains **2 model rate records, 8 budget envelopes, 4 delegated budget allocations, 4 execution runs, and 10 execution events** aligned with the search, ticket, release, and telemetry paths established by P8-D.

The hardened boundary enforces exact graph and upstream evidence binding; policy-pinned model rates and budget profiles; delegated-budget non-amplification and additive oversubscription checks; original-principal/tenant/goal continuity; P8-A delegation, P8-C step, and P8-D observation continuity; exact model/tool/token/cost accounting; run elapsed and step ceilings; acyclic event ancestry; recursion and fan-out bounds; retry/repeated-operation limits; and irreversible-action total/rate ceilings.

Model cost is re-derived from policy-pinned synthetic input/output token rates rather than trusting caller-provided cost. These values are deterministic lab estimates, not live provider prices or billing records.

### Open-source/free implementation path

No new runtime dependency was added. P8-E was designed to remain compatible with a free/open-source enforcement and telemetry stack:

- LangGraph's MIT-licensed recursion-limit/step-counter mechanisms map to runtime step/recursion cutoffs;
- LiteLLM's open-source core can provide provider-facing spend tracking and rate limiting;
- OpenTelemetry/OpenTelemetry Python can export vendor-neutral budget/resource traces and metrics;
- OpenLIT can provide Apache-2.0 OpenTelemetry-native LLM usage/cost observability; and
- Langfuse's MIT core can provide optional self-hosted AI observability/metrics, with enterprise folders kept outside the free-core assumption.

These are integration options, not dependencies or production-enforcement claims in P8-E.

### Deterministic evidence

The exact standalone P8-E files were exercised locally before upload:

- P8-E tests: **18 passed**;
- adversarial cases: **129**;
- vulnerable ASR: **129/129**;
- hardened ASR: **0/129**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- graph SHA-256: `6ded859ac55c7bd348313593fa73104fab41b6694482a8b9f764108ac51914e7`;
- dataset SHA-256: `b5abbaa72815e06ce1ddec4577f996a47a13b341cdaacbae7f5f03896de61cd5`;
- fixture SHA-256: `19165ac7dbdaa6437213cc149ecf357351e0d17d76f4027905943599138940c7`;
- clean assessment SHA-256: `7a4b8ca83bae7ef6477f0464b26c064db7db5ea0e2009b42155a46beb40130fb`.

This is not a claim that full-repository pytest ran locally. GitHub-hosted workflow execution remains subject to the existing account billing/spending-limit runner-provisioning condition.

## Phase 8 status

- P8-A: complete for current deterministic synthetic scope.
- P8-B: complete for current deterministic synthetic scope.
- P8-C: complete for current deterministic synthetic scope.
- P8-D: complete for current deterministic synthetic scope.
- P8-E: implemented with exact standalone local evidence; hosted execution remains infrastructure-blocked.

## Next direction

P8-F should broaden into **human handoff, approval, and autonomy-boundary security**: explicit autonomy levels, when an agent must stop for human review, approval freshness/scope, action-vs-approval binding, preventing approval reuse across materially different plans, and preserving safe failure modes when a human decision is unavailable.
