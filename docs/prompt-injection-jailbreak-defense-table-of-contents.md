# Prompt-Injection & Jailbreak Defense — Mastery Table of Contents (2026+)

> **Goal:** build job-ready AI security engineering skill for understanding, threat-modeling, reproducing safely, detecting, evaluating, and containing prompt-injection and jailbreak attacks in LLM, RAG, tool-using, multimodal, and agentic systems.
>
> **Repository anchor:** use AegisDesk as the authorized synthetic lab. Treat all model-visible attacker-controlled text as **untrusted data**. Never allow natural-language content or model output to become identity, permission, policy, or authorization.
>
> **Evidence rule:** every practical module should end with reproducible evidence: threat model, vulnerable comparison, hardened implementation, adversarial + benign tests, raw metric numerators/denominators, versions/hashes, and residual-risk notes.

## How to use this curriculum

Progress in order. Do not consider a topic mastered because you can define it; mastery requires that you can **explain it, exploit it safely in the local synthetic lab, design a defense, implement the defense, evaluate it, and explain the residual risk**.

Recommended evidence locations in this repository:

- Threat models: `docs/threat-model/`
- Hands-on lab guides: `docs/labs/`
- Security evaluations: `evals/`
- Security regression tests: `tests/security/`
- Detection logic: `detections/`
- Hardened implementation: `aegis/`
- Intentionally vulnerable comparisons: `aegis/vulnerable/` and the local vulnerable API
- Portfolio evidence: `docs/evidence/`

---

# Table of Contents

## 0. Prerequisites for Prompt-Injection Security Engineering

### 0.1 LLM application architecture
- Tokenization, context windows, inference, sampling, and structured outputs
- System/developer/user/tool messages and application-controlled context
- Why an LLM is not a traditional parser or authorization engine
- Deterministic code versus probabilistic model behavior

### 0.2 Security foundations
- Assets, actors, trust boundaries, attack surfaces, entry points, and effects
- Authentication versus authorization
- Least privilege and capability security
- Confused-deputy problems
- Input validation versus authorization
- Fail-open versus fail-closed behavior
- TOCTOU and approval replay concepts

### 0.3 AI application components
- RAG and vector retrieval
- Function/tool calling
- MCP-style tool gateways
- Agents and multi-agent delegation
- Persistent memory
- Web/file/email/connectors
- Multimodal inputs

### 0.4 Lab discipline
- Authorized synthetic targets only
- Reproducible local or bounded test environments
- Version pinning and dependency capture
- Secrets hygiene
- Evidence labeling: deterministic synthetic vs live-local vs production

**Mastery gate:** draw the complete AegisDesk trust-boundary diagram and identify which components are allowed to possess authority.

---

## 1. Core Mental Model: Data Is Not Authority

### 1.1 The central security invariant
- User text is untrusted
- Retrieved text is untrusted
- Web/file/email content is untrusted
- Tool descriptions and tool results may be untrusted
- Memory content may be untrusted
- Model output is untrusted

### 1.2 Why prompt injection is a trust-boundary problem
- Instructions and data share the model context
- Model compliance is not authorization
- Natural-language priority rules are not a security boundary
- Model refusal is not an effect-control mechanism

### 1.3 Authority ownership
- Server-derived identity
- Server-derived tenant
- Server-owned capability policy
- Trusted approval channels
- Exact action/resource binding
- Deterministic effect boundary

### 1.4 Defense-in-depth versus security invariants
- Model instructions as behavioral guidance
- Classifiers/detectors as exposure reduction
- Deterministic controls as containment
- Why no single prompt filter proves security

**Mastery gate:** explain why a perfectly detected attack is useful but a missed attack must still be unable to create an unauthorized side effect.

---

## 2. Terminology and Taxonomy

### 2.1 Prompt injection
- Direct prompt injection
- Indirect prompt injection
- Instruction hierarchy manipulation
- Context manipulation
- Prompt obfuscation
- Payload splitting/composition
- Adversarial suffixes

### 2.2 Jailbreaking
- Safety-policy bypass
- Refusal suppression
- Role/persona attacks
- Multi-turn escalation
- Context saturation
- Model-specific jailbreaks
- Universal/transferable attack concepts

### 2.3 Related but distinct classes
- Prompt extraction/system-prompt leakage
- Sensitive-information disclosure
- Improper output handling
- Excessive agency
- RAG poisoning
- Memory poisoning
- Tool poisoning
- Training-data/model poisoning
- Hallucination/misinformation

### 2.4 Framework mapping
- OWASP GenAI LLM01:2025 Prompt Injection
- MITRE ATLAS LLM Prompt Injection
- MITRE ATLAS LLM Jailbreak
- MITRE ATLAS agentic techniques relevant to tool invocation and context poisoning
- NIST AI 100-2e2025 adversarial ML taxonomy
- NIST AI 600-1 Generative AI Profile

**Mastery gate:** classify ten synthetic scenarios without confusing injection, jailbreak, data poisoning, output-handling, and excessive-agency failures.

---

## 3. Threat Modeling Prompt-Injection Systems

### 3.1 Identify attacker-controlled sources
- Direct user input
- Retrieved documents
- Websites
- Uploaded files
- Email/messages/tickets
- Tool metadata and tool results
- Connector content
- Memory
- Agent-to-agent messages
- Images/audio/video

### 3.2 Identify security-relevant sinks
- Tool invocation
- Data retrieval
- Data writes
- Shell/process execution
- SQL/database operations
- Network requests
- Email/messages
- Purchases/payments
- Permission changes
- Secrets exposure
- Browser rendering
- Memory writes

### 3.3 Map authority flow
- Principal
- Tenant
- Role
- Capability
- Requested action
- Resource
- Approval
- Effect

### 3.4 Abuse cases
- Unauthorized action
- Cross-tenant access
- Privilege escalation
- Sensitive-data disclosure
- Persistent compromise through memory/RAG
- Lateral influence between agents
- Manipulated user decisions

### 3.5 Security properties and invariants
- Write explicit statements that must remain true even if the model is fully manipulated

**Repository anchor:** `docs/threat-model/p2b-indirect-prompt-injection.md`.

**Mastery gate:** produce a threat model where every attacker-controlled source has a path to a model and every model-controlled path to an effect has a deterministic boundary.

---

## 4. Direct Prompt Injection

### 4.1 Attack mechanics
- Instruction replacement
- Priority-confusion attempts
- Role/identity claims
- Policy reinterpretation
- Data-versus-instruction ambiguity

### 4.2 Security impact analysis
- Output manipulation only
- Sensitive-data access attempts
- Tool-use attempts
- Privilege-change attempts

### 4.3 Defensive design
- Strong system constraints
- Explicit task scope
- Structured outputs
- Capability isolation
- Server-side policy checks
- Output validation

### 4.4 Evaluation
- Attack corpus
- Benign corpus
- Deterministic vulnerable/hardened comparison
- Regression tests across prompt/model changes

**Mastery gate:** demonstrate that a direct injection can influence model text but cannot alter server-derived identity, tenant, or capabilities.

---

## 5. Jailbreak Attacks and Safety-Policy Bypass

### 5.1 Jailbreak objectives
- Bypass refusal behavior
- Circumvent safety policy
- Elicit disallowed or hidden behavior
- Degrade policy adherence over multiple turns

### 5.2 Common strategy families
- Persona/role-play
- Instruction indirection
- Hypothetical framing
- Encoding/obfuscation
- Multi-turn escalation
- Context flooding/saturation
- Adversarial suffix concepts

### 5.3 Model-layer defenses
- Safety training/alignment
- Policy prompts
- Input/output moderation
- Secondary classifiers
- Refusal consistency checks
- Model ensembles/judges where justified

### 5.4 Application-layer containment
- Separate safety behavior from authorization
- Minimize high-impact capabilities
- High-risk approval gates
- Safe output handling

### 5.5 Evaluation principles
- Measure bypass rate, not anecdotal prompts
- Maintain benign utility tests
- Record model/version dependence
- Re-test after model updates

**Mastery gate:** explain the difference between reducing jailbreak success and preventing a jailbroken model from gaining application authority.

---

## 6. Indirect Prompt Injection

### 6.1 Indirect attack channels
- Poisoned web pages
- Uploaded documents
- Knowledge-base entries
- Email/ticket content
- Search results
- Tool outputs
- Connector metadata
- Shared documents

### 6.2 Attack lifecycle
- Attacker places instruction
- Trusted application retrieves/ingests it
- Model interprets it as instruction-like context
- Model output or plan changes
- Downstream component acts on the manipulated output

### 6.3 Hidden and obfuscated instructions
- Unicode control/zero-width characters
- Encodings
- Invisible text/markup
- Split payloads
- Cross-document composition

### 6.4 Defenses
- External-content labeling and separation
- Provenance tracking
- Retrieval minimization
- Read-only execution contexts
- No implicit authority from retrieved text
- Boundary authorization before side effects

**Repository anchor:** P2-B poisoned RAG case and Unicode-obfuscated case.

**Mastery gate:** reproduce the synthetic indirect injection in the vulnerable path and show the hardened path blocks the side effect without claiming universal detection.

---

## 7. RAG-Specific Prompt-Injection Defense

### 7.1 RAG attack surface
- Ingestion pipeline
- Chunking
- Embeddings
- Vector database
- Metadata
- Retrieval filters
- Re-ranking
- Context assembly
- Citations

### 7.2 RAG poisoning versus prompt injection
- Poisoning the corpus
- Injecting instructions into otherwise retrievable data
- Integrity versus authorization consequences

### 7.3 Retrieval security controls
- Tenant filters
- Source allowlists
- Document provenance
- Trust labels
- Ingestion validation
- Quarantine workflows
- Read/write separation

### 7.4 Context-construction controls
- Minimal necessary retrieval
- Clear provenance boundaries
- Context ordering
- Structured evidence fields
- Citation constraints

### 7.5 Effect containment
- RAG answers should not silently inherit mutation capabilities
- Tool capabilities must be execution-context specific

### 7.6 RAG evaluation
- Poisoned docs
- Benign docs
- Cross-tenant negatives
- Obfuscated content
- Conflicting sources
- Source-provenance tests

**Repository anchors:** `evals/p2b_indirect_prompt_injection.py`, `docs/live-model-rag-mcp.md`.

**Mastery gate:** build an evaluation that measures both attack success and benign safe-task completion.

---

## 8. Tool-Calling and MCP Security

### 8.1 The model-to-tool trust boundary
- Model proposes; server decides
- Tool schemas are not authorization
- Tool descriptions may influence model behavior

### 8.2 Typed tool interfaces
- Strict schemas
- Enumerations
- Bounds
- Canonicalization
- Server-injected trusted fields

### 8.3 Capability policy
- Explicit allowlists
- Per-context capabilities
- Per-principal constraints
- Per-tenant constraints
- Per-resource constraints

### 8.4 High-impact actions
- Human approval
- Exact action/resource binding
- Nonce/expiry
- Non-replayability
- Idempotency where appropriate

### 8.5 Tool-poisoning risks
- Malicious tool description
- Malicious tool result
- Cross-tool instruction propagation

### 8.6 Egress and destination controls
- Domain/URL allowlists
- Network policy
- Sensitive-data egress filtering

**Mastery gate:** prove that a malicious model proposal containing valid typed arguments is still denied when capability policy does not authorize the effect.

---

## 9. Agentic AI and Multi-Step Prompt Injection

### 9.1 Agent attack surface
- Planner
- Executor
- Tool router
- Delegation
- Scratchpad/state
- Memory
- Agent-to-agent messages
- Long-running loops

### 9.2 Multi-step escalation
- Benign first step → privileged later step
- Goal drift
- Delegated authority expansion
- Tool chaining
- Cross-agent laundering of malicious instructions

### 9.3 Bounded-agent design
- Step limits
- Time limits
- Token/cost limits
- Tool budgets
- Allowed transition graph
- Explicit stop conditions

### 9.4 Delegation security
- Preserve original principal
- Preserve tenant
- Constrain delegated scope
- Do not accept model-declared identity

### 9.5 Approval boundaries
- Human handoff
- Trusted approval channel
- Exact-action binding
- Re-check authorization immediately before effect

**Repository anchor:** existing multi-agent delegation and human-approval case studies in AegisDesk.

**Mastery gate:** show that a delegated/jailbroken sub-agent cannot expand the original caller’s capabilities.

---

## 10. Memory and Persistent Context Poisoning

### 10.1 Memory types
- Conversation history
- User profile memory
- Agent scratch memory
- Shared/team memory
- Long-term semantic memory

### 10.2 Threats
- Persistent malicious instructions
- Cross-session influence
- Cross-user/tenant contamination
- Stored false authorization claims
- Poisoned summaries

### 10.3 Secure memory writes
- Separate facts from instructions
- Provenance
- Writer identity
- Tenant binding
- Schema constraints
- Risk-based write approval

### 10.4 Secure memory reads
- Minimum necessary retrieval
- Trust labels
- Expiry/retention
- Do not treat stored text as policy

### 10.5 Evaluation
- Write-time injection
- Read-time injection
- Persistence across sessions
- Cross-tenant negatives

**Mastery gate:** demonstrate that poisoned memory can affect text generation but cannot create durable authorization or cross-tenant influence.

---

## 11. Multimodal Prompt Injection

### 11.1 Multimodal attack surfaces
- Images
- PDFs
- Screenshots
- Audio
- Video
- OCR-derived text
- Metadata

### 11.2 Cross-modal attacks
- Hidden instructions inside visual content
- Benign text + malicious image
- Document-layer versus rendered-layer discrepancies

### 11.3 Defensive controls
- Provenance per modality
- Content extraction isolation
- Risk labeling
- Restrict actions triggered by multimodal content
- Human verification for sensitive effects

### 11.4 Evaluation
- Synthetic hidden-text image cases
- PDF/document cases
- Benign accessibility content
- False-positive testing

**Mastery gate:** design the evaluation even if the current repo cannot yet claim verified multimodal-model evidence; clearly label deferred/unverified evidence.

---

## 12. Obfuscation, Normalization, and Detector Evasion

### 12.1 Obfuscation classes
- Unicode/zero-width characters
- Homoglyphs
- Encoding
- Whitespace/punctuation transformations
- Token-boundary manipulation
- Payload splitting
- Multilingual variants

### 12.2 Normalization
- Unicode normalization
- Invisible-character handling
- Canonicalization
- Where normalization helps
- Where normalization can corrupt legitimate data

### 12.3 Detector limitations
- Pattern matching brittleness
- Semantic ambiguity
- Model/version dependence
- Adaptive attackers

### 12.4 Design rule
- Detector miss must not imply authorization success

**Mastery gate:** compare raw, normalized, and detector outputs while proving the authorization boundary stays invariant across all three.

---

## 13. Prompt and Context Engineering as Defense-in-Depth

### 13.1 System instruction design
- Clear role and scope
- Explicit untrusted-content rules
- Tool-use rules
- Data/instruction separation

### 13.2 Delimiters and structured context
- Tagged retrieved content
- Typed sections
- Provenance fields
- Separate trusted policy from untrusted evidence

### 13.3 Context minimization
- Reduce unnecessary tool descriptions
- Reduce unnecessary retrieved content
- Avoid leaking secrets into context

### 13.4 What prompting cannot guarantee
- No prompt text creates a cryptographic or authorization boundary
- Prompt robustness must be evaluated empirically

**Mastery gate:** harden the prompt, then deliberately weaken the application authorization control and prove prompt hardening alone is insufficient.

---

## 14. Detection and Classification

### 14.1 Detection layers
- Lexical/rule-based
- Normalization-aware rules
- Embedding/semantic classifiers
- LLM-based classifiers
- Output-policy classifiers
- Sequence/anomaly detection

### 14.2 Detection inputs
- User prompt
- Retrieved chunks
- Tool descriptions/results
- Memory writes
- Agent plans
- Final outputs

### 14.3 Detection outputs
- Allow
- Block
- Sanitize
- Quarantine
- Require approval
- Reduce capabilities
- Log/alert

### 14.4 Detector evaluation
- Precision
- Recall
- FPR
- FNR
- ROC/threshold concepts
- Latency and cost
- Adaptive bypass testing

### 14.5 Safe detector integration
- Detector does not grant authority
- Fail-closed behavior for critical uncertainty where justified
- Avoid logging secrets/prompt bodies unnecessarily

**Mastery gate:** tune a detector against both adversarial and benign corpora and justify the operating threshold with raw confusion-matrix counts.

---

## 15. Output Handling and Downstream Injection

### 15.1 Model output as untrusted data
- HTML/Markdown
- URLs
- SQL
- Shell commands
- Code
- Templates
- JSON/tool arguments

### 15.2 Safe rendering
- Escaping
- Sanitization
- Content Security Policy concepts
- Safe link handling

### 15.3 Safe execution
- No direct shell execution from model text
- Parameterized database operations
- Typed API calls
- Sandboxing where appropriate

### 15.4 Exfiltration paths
- Markdown/image URLs
- Browser requests
- Tool-based egress
- Logging/telemetry leakage

**Mastery gate:** demonstrate that manipulated model output cannot become executable code or an unauthorized network destination without deterministic validation.

---

## 16. Security Evaluation Engineering

### 16.1 Evaluation corpus design
- Direct attacks
- Indirect attacks
- Jailbreaks
- Obfuscation
- Multi-turn cases
- Tool poisoning
- Memory poisoning
- Agentic chains
- Benign tasks

### 16.2 Metrics
- Attack Success Rate (ASR)
- False Positive Rate (FPR)
- False Negative Rate (FNR)
- SafeTaskRate
- Unauthorized-effect count
- Sensitive-disclosure count
- Approval-replay denial rate

### 16.3 Required raw counts
- `ASR = successful policy violations / valid adversarial attempts`
- `FPR = benign tasks incorrectly blocked / valid benign attempts`
- `SafeTaskRate = benign tasks completed safely / valid benign attempts`

### 16.4 Reproducibility
- Model ID/version
- Prompt version/hash
- Policy version/hash
- Corpus hash
- Eval-code hash/commit
- Dependency versions
- Random seeds where meaningful

### 16.5 Negative controls
- Weaken or remove a control
- Prove the evaluation detects the regression

### 16.6 Evidence boundaries
- Deterministic synthetic evidence
- Live-local model evidence
- Production evidence
- Never claim one level proves another

**Repository anchor:** AegisDesk portfolio demo and P2-B evaluation pattern.

**Mastery gate:** create an eval where the hardened system passes, the vulnerable comparison fails, and a deliberately weakened control causes the gate to fail.

---

## 17. AI Red Teaming for Prompt Injection and Jailbreaks

### 17.1 Engagement setup
- Scope
- Authorization
- Assets
- Threat actors
- Rules of engagement
- Evidence handling

### 17.2 Attack methodology
- Enumerate model-visible inputs
- Enumerate authority-bearing outputs/effects
- Construct minimal safe exploit
- Escalate only inside the authorized synthetic lab
- Record preconditions and exact reproduction

### 17.3 Adaptive testing
- Prompt variants
- Multi-turn variants
- Encodings/obfuscations
- Different retrieval sources
- Tool/agent combinations

### 17.4 Root-cause analysis
- Was the failure model behavior?
- Context construction?
- Missing authorization?
- Excessive capability?
- Unsafe output handling?
- Memory/provenance failure?

### 17.5 Fix validation
- Patch deterministic boundary first
- Re-run exploit
- Re-run benign cases
- Add regression test
- Document residual risk

**Mastery gate:** produce a professional red-team finding with reproduction, impact, root cause, remediation, regression evidence, and residual risk.

---

## 18. Telemetry, Monitoring, and Incident Response

### 18.1 Security telemetry
- Attack category
- Source/provenance ID
- Model/prompt/policy version
- Proposed tool
- Normalized non-secret arguments
- Policy decision
- Approval status
- Effect result

### 18.2 Privacy-aware logging
- Do not log secrets
- Avoid unnecessary full prompt bodies
- Pseudonymize identifiers where appropriate
- Retention controls

### 18.3 Detection patterns
- Repeated override attempts
- Repeated blocked tools
- Privilege/tenant probes
- Anomalous tool sequences
- Suspicious memory writes

### 18.4 Incident response
- Contain capabilities
- Revoke/rotate credentials if exposed
- Disable affected tools/connectors
- Quarantine poisoned documents/memory
- Preserve evidence
- Identify affected tenants/users
- Re-evaluate corpus and controls

### 18.5 Post-incident improvement
- Add eval case
- Add regression test
- Update threat model
- Update detection
- Update runbook

**Mastery gate:** write and exercise a synthetic prompt-injection incident runbook.

---

## 19. Secure SDLC and CI/CD for Prompt-Injection Defenses

### 19.1 Security requirements
- Explicit trust-boundary invariants
- Capability requirements
- Approval requirements
- Evaluation thresholds

### 19.2 Code review checklist
- New model-visible input?
- New tool?
- New permission?
- New memory write?
- New renderer/interpreter?
- New external connector?

### 19.3 CI security gates
- Unit tests
- Security regression tests
- Adversarial evals
- Benign evals
- Negative controls
- Dependency/security scans

### 19.4 Model/prompt change management
- Version changes are security-relevant changes
- Re-run attack corpus after model/prompt/tool changes
- Track metric drift

### 19.5 Release evidence
- Signed/immutable evidence where appropriate
- Exact commit
- Eval summary
- Known limitations
- Residual-risk acceptance

**Mastery gate:** make a prompt or tool-description change and prove CI detects any security regression before release.

---

## 20. Governance, Risk, and Framework Crosswalk

### 20.1 OWASP GenAI Security Project
- LLM01:2025 Prompt Injection
- Related risks: sensitive information disclosure, excessive agency, improper output handling, vector/embedding weaknesses, system prompt leakage

### 20.2 MITRE ATLAS
- LLM Prompt Injection
- Direct and indirect subtechniques
- LLM Jailbreak
- AI Agent Tool Invocation
- Agent context/tool poisoning concepts

### 20.3 NIST
- NIST AI RMF 1.0 concepts
- NIST AI 600-1 Generative AI Profile
- NIST AI 100-2e2025 adversarial ML taxonomy

### 20.4 Risk statements
- Likelihood
- Impact
- Existing controls
- Residual risk
- Evidence quality
- Risk owner

### 20.5 Security claims
- Avoid “prompt injection proof” claims
- State exactly what is prevented, detected, contained, or unverified

**Mastery gate:** map one AegisDesk control and one residual risk to OWASP, MITRE ATLAS, and NIST terminology without overstating compliance.

---

## 21. Research Literacy and 2026+ Emerging Techniques

### 21.1 Reading security papers critically
- Threat model
- Attacker knowledge/access
- Model family/version
- Dataset
- Success metric
- Baseline
- Reproducibility
- Limitations

### 21.2 Attack research themes to track
- Automated jailbreak generation
- Transferable adversarial prompts
- Agentic prompt injection
- Tool poisoning
- Memory poisoning
- Multimodal injection
- Long-context attacks
- Self-replicating prompt attacks

### 21.3 Defense research themes to track
- Robust instruction/data separation
- Model-based detection
- Constrained decoding/structured generation
- Capability-safe agent architectures
- Provenance-aware RAG
- Formal or deterministic policy enforcement around stochastic models

### 21.4 Reproduction discipline
- Reproduce only in authorized environments
- Do not equate one model result with universal behavior
- Record failed reproductions too

**Mastery gate:** summarize one current paper as attack assumptions → method → evidence → limitations → implications for AegisDesk.

---

## 22. Capstone 1 — Direct Injection to Unauthorized Tool Proposal

Build an intentionally vulnerable synthetic path where a direct user instruction influences a model/tool proposal, then harden it.

Required evidence:
- Threat model
- Vulnerable reproduction
- Server-owned capability fix
- Typed validation
- Adversarial and benign corpus
- ASR/FPR/SafeTaskRate
- Negative control
- Regression tests
- Residual risk

---

## 23. Capstone 2 — Indirect RAG Injection and Poisoned Retrieval

Extend the existing P2-B case beyond the current deterministic corpus.

Required coverage:
- Multiple poisoned-document styles
- Unicode/obfuscation variants
- Benign retrieval cases
- Provenance metadata
- Read-only capability invariant
- Optional bounded live-model run
- Clear deterministic-versus-live evidence labels

---

## 24. Capstone 3 — Jailbroken Agent with High-Impact Tools

Assume the agent becomes fully instruction-compromised and prove that application controls still contain the impact.

Required controls:
- Least-privilege tool capabilities
- Principal/tenant binding
- High-impact human approval
- Exact action/resource binding
- Anti-replay
- Budget/step limits
- Egress restrictions

Required evidence:
- Jailbreak success at model-behavior layer may be allowed in the synthetic comparison
- Unauthorized side-effect success must remain zero in the hardened path for covered cases
- Benign authorized tasks must remain usable

---

## 25. Capstone 4 — Persistent Memory/Agent Context Poisoning

Build a synthetic memory poisoning scenario spanning multiple turns/sessions.

Required controls:
- Trusted memory schema
- Provenance
- Tenant binding
- Restricted writes
- Safe reads
- Capability isolation

Required evidence:
- Persistence demonstrated in vulnerable path
- Unauthorized effect contained in hardened path
- Cross-tenant negative tests

---

## 26. Capstone 5 — Prompt-Injection Security Evaluation Platform

Turn individual cases into a reusable security evaluation framework.

Required capabilities:
- Attack-case schema
- Benign-case schema
- Model adapter interface
- Deterministic fake adapter
- Optional live-local adapter
- Metrics engine
- Raw counts
- Artifact hashing
- Version capture
- Negative-control support
- CI exit gates
- Machine-readable evidence
- Human-readable report

---

## 27. Capstone 6 — Blue-Team Detection and Incident Response

Create operational defenses around prompt-injection events.

Required components:
- Detection rules/classifier
- Sanitized telemetry
- Alert logic
- Quarantine mechanism for poisoned content
- Tool-capability kill switch
- Incident-response runbook
- Post-incident regression test

---

## 28. Portfolio and Interview Readiness

### 28.1 Explain the fundamentals
- Prompt injection versus jailbreak
- Direct versus indirect injection
- Why RAG does not eliminate injection
- Why system prompts are not authorization
- Why model output is untrusted

### 28.2 Explain the engineering controls
- Capability boundaries
- Typed tools
- Server-derived principal/tenant
- Human approval
- Anti-replay
- Provenance
- Safe output handling

### 28.3 Explain the evaluation
- ASR
- FPR
- SafeTaskRate
- Negative controls
- Deterministic versus live-model evidence

### 28.4 Explain limitations
- Detection bypasses remain possible
- A contained injection may still manipulate answer text
- Model/version behavior changes
- Covered tests do not prove universal security

### 28.5 Show portfolio evidence
- Threat-model document
- Vulnerable/hardened diff
- Automated tests
- Evaluation artifact
- CI result
- Incident runbook
- Framework crosswalk

**Final mastery gate:** given a new LLM/RAG/agent architecture, independently threat-model it, identify all prompt-injection paths, design effect-boundary controls, implement a minimal secure prototype, build adversarial + benign evals, quantify results, and communicate residual risk accurately.

---

# Suggested repository implementation order

1. Keep `MindMap/prompt-injection-jailbreak-defense.md` as the compact mental model.
2. Use this file as the long-form mastery index.
3. Expand modules into focused lab guides under `docs/labs/` only when you are ready to implement them.
4. Add one evaluation per meaningful security property under `evals/`.
5. Add regression coverage under `tests/security/`.
6. Add detector experiments under `detections/` without treating them as authorization controls.
7. Keep vulnerable demonstrations isolated from hardened code and bound to local synthetic use.
8. Update `docs/framework-crosswalk.md` only when a concrete implemented control has evidence.

# Current primary references

Verified on **2026-08-30**:

1. OWASP GenAI Security Project — **LLM01:2025 Prompt Injection**  
   https://genai.owasp.org/llmrisk/llm01-prompt-injection/

2. MITRE ATLAS — **Threat Matrix for AI Systems**  
   https://atlas.mitre.org/

3. NIST — **Adversarial Machine Learning: A Taxonomy and Terminology of Attacks and Mitigations, NIST AI 100-2e2025**  
   https://doi.org/10.6028/NIST.AI.100-2e2025

4. NIST — **Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile, NIST AI 600-1**  
   https://doi.org/10.6028/NIST.AI.600-1

# Existing AegisDesk anchors

- `MindMap/prompt-injection-jailbreak-defense.md`
- `docs/threat-model/p2b-indirect-prompt-injection.md`
- `evals/p2b_indirect_prompt_injection.py`
- `docs/live-model-rag-mcp.md`
- `README.md`

The existing P2-B design is the correct architectural starting point: poisoned retrieved content may influence a model proposal, while the hardened application blocks unauthorized effects at a server-owned capability boundary. The goal of the curriculum above is to generalize that invariant across direct injection, jailbreaking, RAG, tools, agents, memory, multimodal inputs, and operational security.
