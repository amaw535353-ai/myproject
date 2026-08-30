# Prompt-Injection & Jailbreak Defense Mastery — Table of Contents (2026+)

> **Purpose:** a repository-first curriculum for mastering prompt-injection and jailbreak defense as an AI security engineer.
>
> **Last standards check:** 2026-08-30.
>
> **Core invariant:** model-visible content and model output are untrusted data, not authority. Identity, tenant scope, permissions, approvals, policy, and side effects must remain under deterministic, server-owned control.

This document is a learning index, not evidence that any topic has been mastered. A checkbox is complete only when the required artifact, test result, and explanation exist. The companion visual summaries are the [detailed mind map](mindmaps/prompt-injection-jailbreak-defense.md) and the [compact mind map](../MindMap/prompt-injection-jailbreak-defense.md).

## How to use this curriculum

| Rule | Application |
|---|---|
| One challenge at a time | Finish, submit, and grade one module before beginning another. |
| Passing score | A module passes at 80/100 or higher. Remediate and resubmit below 80. |
| Explicit progression | After a pass, wait for **NEXT** before starting the next challenge. |
| Evidence before claims | Never mark a control effective without raw cases, expected outcomes, observed outcomes, and reproducible commands. |
| Evidence classes | Keep deterministic synthetic, live-local, and production evidence separate. One class does not prove another. |
| Safe scope | Use only authorized, isolated, synthetic AegisDesk labs. Do not test public systems, third-party accounts, real credentials, or real tenant data. |
| Cost boundary | Prefer the repository's free local and GitHub Codespaces paths. Do not require a paid model or API unless explicitly approved. |
| Learning pattern | For each module: understand → threat-model → reproduce safely → harden → evaluate → explain → state residual risk. |

## Current AegisDesk starting point

- The existing [P2-B evaluation](../evals/p2b_indirect_prompt_injection.py) uses three deterministic adversarial attempts and one benign task. Its asserted baseline is vulnerable ASR 3/3, hardened ASR 0/3, hardened FPR 0/1, and hardened SafeTaskRate 1/1.
- Those results are bounded synthetic evidence from a fake deterministic model; they do not establish resistance for real models, adaptive attackers, other modalities, or production deployments.
- The [opt-in real-model RAG/MCP slice](live-model-rag-mcp.md) defines 20 adversarial cases and 5 safe tasks, but the repository currently makes no committed real-model pass claim.
- Multimodal prompt-injection evidence remains an explicit gap. It belongs in the curriculum, but it must not be described as implemented or verified until evidence exists.

## Stage map

| Stage | Modules | Main question | Exit artifact |
|---|---:|---|---|
| 0. Orientation and prerequisites | M00–M02 | What must an AI security engineer understand before attacking or defending? | Architecture map, terminology sheet, safe-lab boundary |
| 1. Threat modeling | M03–M06 | Where can untrusted content cross into authority or effects? | AegisDesk prompt-injection threat model |
| 2. Attack mechanics | M07–M14 | How do direct, indirect, persistent, multimodal, tool, and agentic attacks work? | Authorized synthetic attack corpus and attack-path map |
| 3. Defense engineering | M15–M23 | Which controls prevent influence from becoming impact? | Hardened design, tests, and residual-risk register |
| 4. Evaluation and assurance | M24–M28 | How is defensive performance measured without overclaiming? | Reproducible eval report with negative controls |
| 5. Detection, response, and governance | M29–M31 | How are attacks detected, contained, learned from, and governed? | Detection pack, incident runbook, framework crosswalk |
| 6. Capstones and professional proof | M32–M35 | Can the complete security argument survive technical review? | Portfolio-ready capstones and interview defense |

# Stage 0 — Orientation and prerequisites

## M00 — Mastery contract and safe lab operation

- [ ] Define authorized scope, synthetic assets, prohibited targets, stop conditions, and evidence-handling rules.
- [ ] Distinguish learning progress, implemented code, passing tests, live evidence, and production assurance.
- [ ] Record environment, dependency versions, commit SHA, corpus hashes, and command exit status.
- [ ] Explain why intentionally vulnerable code must remain isolated from the default application.
- **Repository anchors:** [README](../README.md), [Security policy](../SECURITY.md), [contributing guide](../CONTRIBUTING.md).

## M01 — Application-security prerequisites

- [ ] HTTP requests, APIs, authentication, authorization, sessions, and tenant isolation.
- [ ] Data-flow diagrams, trust boundaries, assets, actors, entry points, and effect boundaries.
- [ ] Input validation, typed schemas, output encoding, SSRF, command injection, SQL injection, and unsafe rendering.
- [ ] Least privilege, capabilities, deny-by-default policy, separation of duties, freshness, replay, and fail-closed behavior.
- [ ] Logging, alerting, incident response, regression testing, and secure software lifecycle basics.
- **Repository anchors:** [server-owned identity](../aegis/identity/synthetic_auth.py), [tool capability policy](../aegis/policy/tool_capabilities.py), [MCP gateway](../aegis/mcp_gateway/gateway.py), [network policy](../aegis/network/policy.py).

## M02 — LLM-application and agent fundamentals

- [ ] Tokens, context windows, system/developer/user messages, stochastic output, and model limitations.
- [ ] Embeddings, vector search, chunking, metadata, retrieval, reranking, and RAG data flow.
- [ ] Structured outputs, function/tool calling, MCP hosts and servers, tool descriptions, arguments, and results.
- [ ] Agent loops, goals, plans, memory, delegation, approvals, observations, and multi-agent messages.
- [ ] Model-as-component versus model-as-actor and how agency changes blast radius.
- **Repository anchors:** [RAG runner](../aegis/rag/answering.py), [deterministic RAG model](../aegis/agent/rag_model.py), [MCP models](../aegis/mcp_gateway/models.py), [bounded agent loop](../aegis/agent/bounded_loop.py).

### Stage 0 exit gate

Explain the complete AegisDesk path from authenticated request to retrieval, model proposal, policy decision, tool dispatch, synthetic effect, telemetry, and evidence. Identify every point where attacker-controlled data enters and every point where trusted authority must remain server-owned.

# Stage 1 — Threat modeling and security reasoning

## M03 — Prompt injection, jailbreak, and neighboring risks

- [ ] Define prompt injection as unintended behavior caused by model input.
- [ ] Distinguish direct, indirect, and triggered prompt injection.
- [ ] Define jailbreaking as the subset whose objective is bypassing model safety or alignment behavior.
- [ ] Separate prompt injection from sensitive-information disclosure, excessive agency, hidden-context exposure, vector/embedding weaknesses, and improper output handling.
- [ ] Distinguish model-level safety failure from application-level authorization failure.
- **Repository anchors:** [prompt-injection mind map](mindmaps/prompt-injection-jailbreak-defense.md), [P2-B threat model](threat-model/p2b-indirect-prompt-injection.md).

## M04 — Data, instructions, authority, and effects

- [ ] Explain why current LLM context does not enforce a security boundary between instructions and data.
- [ ] Classify user text, retrieved documents, webpages, tool metadata, tool results, memory, agent messages, and model output as untrusted unless independently verified.
- [ ] Model the path: untrusted content → model influence → proposal → policy → effect.
- [ ] Distinguish controls that reduce attack success from controls that contain impact after model compromise.
- [ ] Identify security invariants that must hold even when the model follows the attacker's instruction.
- **Repository anchors:** [security invariants](../SECURITY.md), [P2-B hardened runner](../aegis/rag/answering.py), [P2-B vulnerable runner](../aegis/vulnerable/indirect_prompt_injection.py).

## M05 — Prompt-injection attack anatomy

- [ ] Delivery surface: direct input, RAG, web, file, email/ticket, tool definition, tool result, memory, image/audio/video, or agent message.
- [ ] Propagation: single-shot, multi-turn, multi-step, cross-session, cross-user, cross-agent, delayed/triggered, or self-replicating.
- [ ] Encoding: plain text, payload splitting, Base64/ROT-style transforms, Unicode controls, homoglyphs, low-resource languages, image/audio hiding, or steganographic representation.
- [ ] Objective: safety bypass, output manipulation, disclosure, exfiltration, unauthorized action, privilege abuse, persistence, denial of service, or lateral movement.
- [ ] Preconditions, attacker capability, reachable assets, trust transitions, impact, detectability, and residual risk.
- **Repository anchors:** [poisoned RAG corpus](../synthetic_data/p2b_poisoned_knowledge.json), [browser corpus](../synthetic_data/p2j_web_pages.json), [adaptive cases](../synthetic_data/adaptive_ai_security_cases.json).

## M06 — Threat-modeling methods for LLM and agent systems

- [ ] Build a data-flow diagram and trust-boundary inventory.
- [ ] Enumerate attacker-controlled channels and authority-bearing components.
- [ ] Write security properties as testable invariants rather than prompt wording.
- [ ] Construct attack trees from influence to impact.
- [ ] Map confidentiality, integrity, availability, privacy, safety, financial, and operational impacts.
- [ ] Define abuse cases, misuse cases, assumptions, non-goals, and accepted risk.
- [ ] Pre-register expected vulnerable and hardened outcomes.
- **Repository anchors:** [threat-model collection](threat-model/), [P2-B model](threat-model/p2b-indirect-prompt-injection.md), [P2-C model](threat-model/p2c-mcp-tool-poisoning.md), [P8-C model](threat-model/p8c-agent-goal-plan-instruction-integrity.md).

### Stage 1 exit gate

Produce a reviewable threat model for AegisDesk covering direct input, RAG, browser content, MCP metadata/results, durable memory, agent messages, approvals, and side effects. Every proposed defense must map to a named threat and a testable invariant.

# Stage 2 — Attack mechanics and authorized reproduction

## M07 — Direct prompt injection

- [ ] Instruction override, role confusion, policy extraction, goal substitution, and output steering.
- [ ] User-authorized versus unauthorized objectives.
- [ ] Single-turn and multi-turn escalation.
- [ ] Direct input that induces a tool proposal versus direct input that only changes text.
- [ ] Unintentional conflicting instructions pasted by a benign user.
- **Repository gap:** no dedicated direct-prompt-injection evaluation currently proves this module. Add only a synthetic, bounded harness before marking it complete.

## M08 — Jailbreak techniques and objectives

- [ ] Safety-policy circumvention, refusal suppression, persona/role-play, hypothetical framing, and instruction-hierarchy attacks.
- [ ] Many-shot, long-context, multi-turn, multilingual, and adversarial-suffix concepts.
- [ ] White-box, gray-box, and black-box attacker knowledge.
- [ ] Universal versus model-specific jailbreaks and transferability limits.
- [ ] Distinguish harmful-content generation from downstream application compromise.
- **Repository gap:** the mind maps cover the taxonomy, but no dedicated jailbreak benchmark is currently committed. Mastery requires an authorized local benchmark and bounded claims.

## M09 — Obfuscation, evasion, and adaptive attacks

- [ ] Unicode zero-width/tag/variation characters, homoglyphs, encoding, whitespace, case, and token-boundary manipulation.
- [ ] Payload splitting across fields, documents, messages, or tool outputs.
- [ ] Semantic rephrasing, multilingual/code-mixed attacks, best-of-N probing, and iterative adaptation.
- [ ] Why static blocklists and known-string detectors fail under distribution shift.
- [ ] Defense-aware testing in which the attacker knows the deployed control.
- **Repository anchors:** [P2-B Unicode case](threat-model/p2b-indirect-prompt-injection.md), [adaptive corpus](../synthetic_data/adaptive_ai_security_cases.json).

## M10 — Indirect and triggered prompt injection

- [ ] Attacker content placed in a source later consumed by another user's model.
- [ ] Trusted, semi-trusted, and untrusted content sources.
- [ ] Delayed activation through schedules, events, user actions, retrieval, or agent workflows.
- [ ] Cross-context and cross-session propagation.
- [ ] Provenance loss and instruction laundering across summaries or agents.
- **Repository anchors:** [P2-B poisoned RAG](threat-model/p2b-indirect-prompt-injection.md), [P2-J browser injection](threat-model/p2j-browser-prompt-injection.md).

## M11 — RAG and corpus poisoning

- [ ] Poisoned document creation, ingestion, chunking, retrieval targeting, and context placement.
- [ ] Vector/embedding weaknesses, metadata manipulation, tenant-scope failure, and source-rank abuse.
- [ ] Persistent cross-user influence through shared corpora.
- [ ] Citation manipulation, answer steering, tool-use steering, and retrieval denial.
- [ ] Difference between trusted provenance and trustworthy content.
- **Repository anchors:** [RAG store](../aegis/rag/store.py), [vulnerable RAG](../aegis/vulnerable/rag.py), [P2-B eval](../evals/p2b_indirect_prompt_injection.py), [cross-tenant RAG tests](../tests/security/test_cross_tenant_rag.py).

## M12 — Web, document, email, and multimodal injection

- [ ] Visible and hidden webpage content, HTML/Markdown rendering, links, image URLs, and outbound exfiltration channels.
- [ ] PDFs, office documents, issue titles, tickets, email, API responses, and external artifacts.
- [ ] OCR, image, audio, and video instruction channels.
- [ ] Modality-specific extraction, provenance, normalization, and filtering limitations.
- [ ] Why sanitization reduces exposure but does not grant or revoke authority.
- **Repository anchors:** [P2-J threat model](threat-model/p2j-browser-prompt-injection.md), [safe fetcher](../aegis/network/fetcher.py), [browser tests](../tests/security/test_browser_prompt_injection.py).
- **Repository gap:** multimodal attack and defense evidence remains unimplemented and unverified.

## M13 — MCP, tool-definition, and tool-result poisoning

- [ ] Tool-name shadowing, malicious descriptions, deceptive schemas, annotation abuse, and server-identity confusion.
- [ ] Tool implementation compromise, runtime-response poisoning, and tool-result prompt injection.
- [ ] Discovery-time versus invocation-time trust.
- [ ] Bare tool name versus server-and-tool binding.
- [ ] Tool supply-chain, version pinning, provenance, and runtime composition.
- **Repository anchors:** [P2-C threat model](threat-model/p2c-mcp-tool-poisoning.md), [host registry](../aegis/mcp_gateway/host_registry.py), [MCP catalog model](../aegis/agent/mcp_catalog_model.py), [P2-C tests](../tests/security/test_mcp_tool_poisoning.py).

## M14 — Memory, agent, and multi-agent propagation

- [ ] Memory poisoning, delayed execution, cross-session persistence, trust-label laundering, expiry, revocation, and supersession.
- [ ] Goal hijacking, plan mutation, termination bypass, and rollback bypass.
- [ ] Tool-observation replay, swapping, spoofing, and stale-state use.
- [ ] Delegation drift, capability escalation, principal loss, and cross-agent command laundering.
- [ ] Message authentication versus message authority.
- [ ] Cascading failure and blast-radius growth across agent graphs.
- **Repository anchors:** [P2-F memory poisoning](threat-model/p2f-durable-memory-poisoning.md), [P8-B memory security](threat-model/p8b-agent-memory-context-boundary-security.md), [P8-C goal integrity](threat-model/p8c-agent-goal-plan-instruction-integrity.md), [P8-D observations](threat-model/p8d-agent-tool-observation-environment-integrity.md), [P8-G messages](threat-model/p8g-agent-communications-message-protocol-security.md).

### Stage 2 exit gate

Build a synthetic attack catalog that covers at least direct, indirect, obfuscated, RAG, browser/document, MCP/tool, memory, and agent-message families. For every case, document source, trigger, objective, preconditions, vulnerable behavior, intended hardened behavior, and safe stop condition. Do not claim multimodal or real-model coverage without executing and preserving that evidence.

# Stage 3 — Defense engineering

## M15 — Defense assumptions, hierarchy, and limits

- [ ] Assume the model can be influenced; design so influence does not automatically become impact.
- [ ] Separate prevention, detection, containment, recovery, and assurance.
- [ ] Rank deterministic effect-boundary controls above prompt wording and heuristic detection for authorization decisions.
- [ ] Use defense in depth; do not describe any single guardrail as complete prevention.
- [ ] Define fail-open versus fail-closed behavior and availability tradeoffs.
- **Repository anchors:** [security invariants](../SECURITY.md), [P2-B controls](threat-model/p2b-indirect-prompt-injection.md).

## M16 — Prompt, context, and model-layer controls

- [ ] Clear role/task constraints, instruction ordering, delimiters, structured prompt formats, and minimal context.
- [ ] Separate system-owned instructions from external content and attach source/trust labels.
- [ ] Normalize or flag suspicious encodings while preserving required user functionality.
- [ ] Input classifiers, prompt-injection detectors, output classifiers, and second-model review.
- [ ] Understand adaptive-bypass, false-positive, latency, privacy, and cost limitations.
- [ ] Never use a detector verdict as the sole authorization decision for a privileged effect.
- **Repository anchors:** [RAG prompt/model](../aegis/agent/rag_model.py), [mind map defense stack](mindmaps/prompt-injection-jailbreak-defense.md).

## M17 — Secure RAG ingestion and retrieval

- [ ] Source authentication, provenance, review, quarantine, and immutable document identity.
- [ ] Tenant-scoped ingestion, indexing, retrieval filters, and post-retrieval validation.
- [ ] Chunk/metadata controls, source allowlists, versioning, revocation, and re-indexing.
- [ ] Context minimization, trust labels, citations, and safe answer-only modes.
- [ ] Poisoned-corpus regression tests and retrieval-quality versus security tradeoffs.
- **Repository anchors:** [RAG models](../aegis/rag/models.py), [RAG store](../aegis/rag/store.py), [P2-B corpus](../synthetic_data/p2b_poisoned_knowledge.json), [P2-B tests](../tests/security/test_indirect_prompt_injection.py).

## M18 — Identity, tenant, privilege, and capability boundaries

- [ ] Derive principal and tenant from authenticated server context.
- [ ] Keep credentials and authorization state outside prompts, memory, tool metadata, and model output.
- [ ] Apply least privilege per request, agent, task, tool, resource, and effect.
- [ ] Separate read and write capabilities and avoid ambient authority.
- [ ] Preserve original-principal and delegation constraints across agent hops.
- **Repository anchors:** [identity models](../aegis/identity/models.py), [synthetic authentication](../aegis/identity/synthetic_auth.py), [tool capabilities](../aegis/policy/tool_capabilities.py), [identity-substitution tests](../tests/security/test_identity_substitution.py).

## M19 — Typed tools and effect-boundary authorization

- [ ] Treat model output as a proposal, never a command.
- [ ] Resolve an immutable server-and-tool identity.
- [ ] Validate strict schemas, types, enums, lengths, destinations, and server-owned fields.
- [ ] Authorize the exact principal, tenant, action, resource, arguments, and current state immediately before execution.
- [ ] Revalidate after delays, retries, queues, plan changes, or approval.
- [ ] Use idempotency, bounded retries, transactional effects, and auditable receipts.
- **Repository anchors:** [gateway](../aegis/mcp_gateway/gateway.py), [gateway models](../aegis/mcp_gateway/models.py), [execution-time revalidation](../aegis/effects/revalidation.py), [tool gateway tests](../tests/security/test_tool_gateway.py).

## M20 — Human approval, freshness, and replay resistance

- [ ] Identify which actions require human review.
- [ ] Bind approval to principal, tenant, exact action, exact resource, exact arguments, plan, evidence, and policy version.
- [ ] Enforce reviewer authority, separation of duties, expiry, nonce, one-time use, and rejection semantics.
- [ ] Display the exact rendered action rather than an attacker-influenced summary.
- [ ] Model pause, deny, timeout, restart, cancellation, and stale-authorization paths.
- **Repository anchors:** [P8-F threat model](threat-model/p8f-human-handoff-approval-autonomy-boundary-security.md), [approval models](../aegis/approvals/models.py), [durable approval](../aegis/approvals/durable.py), [approval tests](../tests/integration/test_approval_flow.py).

## M21 — Agent, memory, and inter-agent containment

- [ ] Validate memory writes as privileged operations with provenance, scope, retention, and trust.
- [ ] Bind goals, plans, mutations, termination, and rollback to authorized objectives.
- [ ] Bind tool results and observations to invocation, arguments, state, freshness, and provenance.
- [ ] Preserve principal, tenant, task, goal, capability, and parent-chain continuity across messages.
- [ ] Bound loops, tokens, time, retries, tool calls, spend, and delegation depth.
- [ ] Isolate agent workspaces and generated artifacts.
- **Repository anchors:** [agentic security package](../aegis/agentic/), [memory service](../aegis/memory/service.py), [bounded loop](../aegis/agent/bounded_loop.py), [Phase 8 tests](../tests/security/test_p8l_phase8_exit_gate.py).

## M22 — Egress, sandboxing, output, and rendering controls

- [ ] Restrict network destinations, protocols, redirects, DNS resolution, and private-address access.
- [ ] Prevent model text from becoming raw shell, SQL, template, browser, or code execution.
- [ ] Validate structured output and separately validate semantic authorization.
- [ ] Escape untrusted HTML/Markdown and constrain URLs and rendered external resources.
- [ ] Sandbox generated code and tools with minimal filesystem, network, process, and secret access.
- [ ] Redact sensitive data and detect covert exfiltration channels.
- **Repository anchors:** [network policy](../aegis/network/policy.py), [safe fetcher](../aegis/network/fetcher.py), [artifact tests](../tests/security/test_artifact_handling.py), [SSRF tests](../tests/security/test_ssrf_redirects.py), [workload lab](labs/p11a-linux-workload-security-lab.md).

## M23 — Safety, usability, and residual-risk design

- [ ] Pair every attack test with representative benign tasks.
- [ ] Distinguish secure denial, unnecessary refusal, degraded completion, and unsafe completion.
- [ ] Design user-visible explanations and recovery paths without exposing secrets or detector internals.
- [ ] Analyze latency, cost, privacy, accessibility, multilingual, and operational tradeoffs.
- [ ] Document what the control prevents, contains, detects, does not cover, and depends on.
- **Repository anchors:** [portfolio claim boundary](../README.md), [framework crosswalk](framework-crosswalk.md), [release readiness](release-readiness.md).

### Stage 3 exit gate

Demonstrate a security delta: the same synthetic attack reaches an unauthorized effect in an intentionally vulnerable path and is blocked at a deterministic boundary in the hardened path, while matched benign tasks still complete. Include a weakened-control negative test and a residual-risk statement.

# Stage 4 — Evaluation, red teaming, and assurance

## M24 — Evaluation corpus design

- [ ] Define threat-model-derived attack families and representative benign tasks.
- [ ] Separate seed, development, validation, regression, and holdout cases.
- [ ] Include direct, indirect, triggered, obfuscated, multilingual, multi-turn, long-context, RAG, tool, memory, agent, and supported multimodal cases.
- [ ] Record source, expected outcome, validity conditions, duplicates, transformations, and coverage tags.
- [ ] Prevent benchmark contamination and case leakage.
- [ ] Hash and version corpora.
- **Repository anchors:** [P2-B corpus](../synthetic_data/p2b_poisoned_knowledge.json), [real-model corpus](../real_model_evals/data/real_model_rag_mcp_cases.json), [corpus evolution](../aegis/assurance/corpus_evolution.py).

## M25 — Metrics and decision quality

- [ ] ASR = successful policy violations / valid adversarial attempts.
- [ ] FPR = benign tasks incorrectly blocked / valid benign attempts.
- [ ] SafeTaskRate = benign tasks completed safely / valid benign attempts.
- [ ] Unauthorized-effect count, sensitive-disclosure rate, tool-violation rate, detection precision/recall, latency, and cost.
- [ ] Report raw numerator, denominator, exclusions, uncertainty, and per-family results beside percentages.
- [ ] Do not compare percentages from materially different models, corpora, policies, or validity rules without qualification.
- **Repository anchors:** [P2-B evaluation definitions](../evals/p2b_indirect_prompt_injection.py), [metric tests](../tests/security/test_p2a_metrics.py).

## M26 — Evaluation harnesses and negative controls

- [ ] Deterministic fixtures with stable expected behavior.
- [ ] Vulnerable and hardened variants over the same cases.
- [ ] Precondition validation so invalid attempts do not silently enter denominators.
- [ ] Raw per-case observations, sanitized logs, policy versions, hashes, and commit identity.
- [ ] Mutation or weakened-control tests proving the gate can fail.
- [ ] Reproducible commands, exit codes, machine-readable output, and CI isolation.
- **Repository anchors:** [P2-B eval](../evals/p2b_indirect_prompt_injection.py), [P2-B tests](../tests/evals/test_p2b_eval.py), [portfolio evidence tests](../tests/security/test_portfolio_demo_evidence.py).

## M27 — Real-model and adaptive evaluation

- [ ] Explicit opt-in, endpoint allowlisting, secret handling, token/cost budget, timeouts, and no hidden fallback.
- [ ] Record provider, model ID, model version when available, parameters, prompt/policy hash, and timestamps.
- [ ] Repeat trials where stochasticity matters and preserve trial-level data.
- [ ] Evaluate attack transfer across models and defense-aware adaptive attacks.
- [ ] Separate model refusal from application containment and unauthorized-effect prevention.
- [ ] State when evidence is blocked, failed, deterministic, live-local, or production.
- **Repository anchors:** [real-model guide](live-model-rag-mcp.md), [real-model runner](../real_model_evals/rag_mcp.py), [real-model tests](../tests/security/test_real_model_rag_mcp.py).

## M28 — Regression, drift, and evidence integrity

- [ ] Re-run after model, system prompt, retrieval, corpus, tool, policy, dependency, or architecture changes.
- [ ] Track attack-family coverage and regression history.
- [ ] Detect corpus drift, prompt drift, policy drift, model drift, and evidence-schema drift.
- [ ] Protect artifacts from caller-declared upgrades or fabricated pass status.
- [ ] Separate deterministic, live-local, staging, and production claims.
- [ ] Govern waivers with owner, scope, rationale, expiry, compensating controls, and revalidation.
- **Repository anchors:** [assurance regression](../aegis/assurance/regression.py), [waiver governance](../aegis/assurance/waiver_governance.py), [portfolio gap closure](portfolio-gap-closure.md).

### Stage 4 exit gate

Produce a machine-readable and human-readable report containing raw cases, validity rules, observed outcomes, ASR/FPR/SafeTaskRate with numerators and denominators, versions and hashes, a failing negative control, and a bounded claim that matches the evidence class.

# Stage 5 — Detection, incident response, and governance

## M29 — Detection engineering and privacy-preserving telemetry

- [ ] Log source/provenance, retrieval IDs, model/prompt/policy versions, tool proposal, normalized arguments, decision, reason, approval, and effect receipt.
- [ ] Avoid secrets, raw sensitive prompts, personal data, and unnecessary reasoning traces.
- [ ] Detect repeated jailbreak attempts, encoding anomalies, cross-agent propagation, abnormal tool sequences, privilege probes, egress attempts, memory poisoning, and tenant-boundary probes.
- [ ] Build correlation across prompt, retrieval, model, policy, tool, effect, and identity events.
- [ ] Test missing-stage, wrong-tenant, replay, out-of-window, out-of-order, benign-flood, and tampering cases.
- [ ] Measure precision, recall, coverage, alert volume, and time to detect.
- **Repository anchors:** [P11-F threat model](threat-model/p11f-detection-engineering.md), [security events](../aegis/observability/security_events.py), [analytics](../aegis/detection/security_analytics.py), [detection rules](../detections/p11f/).

## M30 — Incident response and recovery

- [ ] Triage: injection source, affected sessions/users/tenants, tools, actions, data, and persistence.
- [ ] Contain: disable or narrow tools, block egress, quarantine content, revoke credentials, freeze memory writes, and fence affected agents.
- [ ] Eradicate: remove poisoned content/memory, patch policy, rotate affected trust material, and invalidate stale approvals.
- [ ] Recover: restore clean state, re-index, re-evaluate, monitor, and reopen capabilities gradually.
- [ ] Preserve evidence with provenance and chain-of-custody appropriate to the lab.
- [ ] Feed incident findings into threat models, corpora, detections, tests, and risk decisions.
- **Repository anchors:** [incident package](../aegis/incidents/), [incident feedback](../aegis/assurance/incident_feedback.py), [local IR lab](labs/p10i-incident-response-lab.md), [incident forensics](../aegis/agentic/incident_forensics_security.py).

## M31 — Standards, governance, and secure lifecycle

- [ ] OWASP LLM01:2026 Prompt Injection and its relationships to LLM02, LLM03, LLM08, LLM09, and LLM10.
- [ ] OWASP Agentic Top 10: goal hijack, tool misuse, identity/privilege abuse, agentic supply chain, code execution, memory/context poisoning, insecure inter-agent communication, cascading failures, human-agent trust exploitation, and rogue agents.
- [ ] MITRE ATLAS AML.T0051 with Direct, Indirect, and Triggered sub-techniques; AML.T0054 LLM Jailbreak; AML.T0053 AI Agent Tool Invocation; and AML.T0110 AI Agent Tool Poisoning.
- [ ] NIST AI 100-2e2025 adversarial-ML taxonomy and NIST AI 600-1 Generative AI Profile.
- [ ] Governance across Govern, Map, Measure, and Manage; ownership, risk acceptance, TEVV, change control, and incident learning.
- [ ] Convert framework labels into repository-specific threats, controls, tests, owners, evidence, and residual risks.
- **Repository anchors:** [framework crosswalk](framework-crosswalk.md), [security policy](../SECURITY.md), [release readiness](release-readiness.md).

### Stage 5 exit gate

Run a synthetic prompt-injection incident from detection through containment, evidence preservation, recovery, corpus update, and regression testing. Produce a framework crosswalk that points to actual code, tests, and evidence rather than framework names alone.

# Stage 6 — Capstones and professional proof

## M32 — Capstone A: P2-B indirect prompt injection

- [ ] Reproduce the three current poisoned-RAG attempts and the benign task.
- [ ] Trace the exact vulnerable side effect and hardened block.
- [ ] Explain why the Unicode case tests containment rather than universal detection.
- [ ] Recalculate ASR, FPR, and SafeTaskRate from raw observations.
- [ ] Add a justified new attack family and a matched benign case.
- [ ] Add a weakened-control negative test.
- [ ] Write a bounded evidence statement suitable for a portfolio review.
- **Repository anchors:** [P2-B threat model](threat-model/p2b-indirect-prompt-injection.md), [eval](../evals/p2b_indirect_prompt_injection.py), [security tests](../tests/security/test_indirect_prompt_injection.py).

## M33 — Capstone B: RAG → MCP → memory chained defense

- [ ] Model a poisoned document that induces a tool proposal and attempts persistence.
- [ ] Demonstrate the intentionally vulnerable chain using only synthetic effects.
- [ ] Enforce server-derived identity, tenant scope, server-and-tool binding, capability policy, argument validation, and memory-write policy.
- [ ] Test tool-definition poisoning, tool-result injection, memory replay, stale state, and cross-tenant cases.
- [ ] Report per-stage prevention, detection, containment, and residual risk.
- **Repository anchors:** [P2-B](threat-model/p2b-indirect-prompt-injection.md), [P2-C](threat-model/p2c-mcp-tool-poisoning.md), [P2-F](threat-model/p2f-durable-memory-poisoning.md).

## M34 — Capstone C: Agentic prompt-injection containment

- [ ] Create a threat model for goal hijacking across retrieval, memory, plan mutation, tool observation, approval, and inter-agent messaging.
- [ ] Preserve original principal, tenant, task, goal, delegation, capability, and evidence bindings.
- [ ] Require exact human approval for a high-impact action and deny replay or substitution.
- [ ] Bound execution budgets, retries, delegation depth, network, workspace, and artifacts.
- [ ] Test cascading failure and clean containment.
- [ ] Produce deterministic evidence first; add live-local evidence only when explicitly configured and observed.
- **Repository anchors:** [Phase 8 threat models](threat-model/p8a-multi-agent-delegation-authority-propagation.md), [Phase 8 implementation](../aegis/agentic/), [Phase 8 exit eval](../evals/p8l_phase8_exit_gate.py).

## M35 — Capstone D: Defense operations and interview-ready portfolio

- [ ] Create a detection rule and correlation for a prompt-injection-to-tool-use chain.
- [ ] Execute a contained incident-response scenario and update the regression corpus.
- [ ] Present the architecture, threat model, vulnerable comparison, hardened control, evaluation, evidence class, and residual risk.
- [ ] Defend why prompt filtering is insufficient and why authorization belongs at the effect boundary.
- [ ] Explain all metric calculations from raw counts.
- [ ] Identify unverified areas honestly: real-model breadth, adaptive robustness, multimodal coverage, production IAM/KMS/HSM, multi-node infrastructure, and production SIEM/SOC evidence.
- [ ] Deliver a concise design review, portfolio walkthrough, and interview explanation without claiming production proof.
- **Repository anchors:** [portfolio walkthrough](portfolio-walkthrough.md), [P11-F detection](threat-model/p11f-detection-engineering.md), [portfolio evidence](evidence/portfolio-demo-report.md).

## Mastery rubric

| Dimension | Points | Required evidence |
|---|---:|---|
| Concepts and terminology | 15 | Precise explanation and correct distinctions |
| Threat modeling | 15 | Assets, actors, boundaries, attack paths, invariants, residual risk |
| Safe attack reproduction | 15 | Authorized synthetic vulnerable case with preconditions and observed effect |
| Defense engineering | 20 | Deterministic server-owned control at the relevant boundary |
| Evaluation quality | 20 | Attack and benign cases, metrics, negative control, reproducibility |
| Detection and response | 5 | Useful telemetry, detection logic, and containment path |
| Evidence and communication | 10 | Raw counts, versions/hashes, bounded claim, clear technical defense |
| **Total** | **100** | **Pass at 80; remediate below 80** |

A passing score is necessary but not sufficient for overall mastery. Final mastery requires passing all stage exit gates and capstones, explaining the design under review, and preserving evidence that another engineer can reproduce.

## Primary standards and authoritative references

Checked on 2026-08-30:

1. [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) — LLM01:2026 Prompt Injection and related application risks.
2. [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — agent goal, tool, identity, memory, communication, cascading, and human-trust risks.
3. [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) — layered implementation and testing guidance.
4. [OWASP guide for third-party MCP servers](https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/) — MCP trust, poisoning, and operational controls.
5. [MITRE ATLAS](https://atlas.mitre.org/) and [ATLAS data](https://github.com/mitre-atlas/atlas-data) — current adversary techniques, mitigations, and case studies.
6. [NIST AI 100-2e2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final) — adversarial machine-learning taxonomy and terminology.
7. [NIST AI 600-1](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence) — Generative AI Profile for the AI Risk Management Framework.

## Completion definition

You understand and can defend this domain when you can independently:

1. distinguish prompt injection, jailbreaking, agency, disclosure, and output-handling failures;
2. threat-model every model-visible input and every authority/effect boundary;
3. reproduce representative attacks safely in an isolated lab;
4. implement deterministic containment that survives model compromise;
5. evaluate attack resistance and benign utility with transparent metrics;
6. detect, contain, recover from, and learn from an incident;
7. map controls to current standards and repository evidence; and
8. state limitations without upgrading deterministic or live-local evidence into a production claim.
