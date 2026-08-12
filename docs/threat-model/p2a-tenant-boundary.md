# P2-A Tenant-Boundary Attack Baseline

## Purpose and safety scope

P2-A is an intentionally vulnerable, local-only baseline for comparing two tenant-isolation failures against AegisDesk's hardened retrieval path. All organizations, users, data, identifiers, and canaries are synthetic. The vulnerable FastAPI app is a separate factory in `apps/vulnerable_api/`; it is not mounted, imported, or feature-flagged by `apps/api/main.py`.

Do not expose the vulnerable app through a public Codespaces port or use it against third-party systems.

## Protected asset and trust boundary

The protected asset is tenant-scoped knowledge in a shared vector collection. `X-Aegis-User` is only a synthetic lab authentication handle. After authentication, the server-resolved `Principal.tenant_id` is the authority for the hardened path. Request bodies, prompts, retrieved text, and model output are untrusted and must not select tenant scope.

## Scenario P2A-A1: unfiltered cross-tenant retrieval

**Threat.** An authenticated Dynamics employee submits a broad knowledge query. The intentionally vulnerable store searches the shared Qdrant collection without any tenant filter.

**Preconditions.** Local lab; synthetic Dynamics principal; shared four-document synthetic corpus; attack budget of one request.

**Authorized reproduction.** Run the vulnerable app locally and POST `{"query":"vpn password reset","limit":5}` to `/v1/knowledge/search-unfiltered` with Alice's synthetic authentication header.

**Vulnerable behavior.** At least one Northstar Digital document is returned and the Digital canary is observable.

**Hardened behavior.** The same authenticated principal and query sent to `/v1/knowledge/search` is filtered by the server-derived tenant and the foreign canary is absent.

**Control.** `KnowledgeStore.search` constructs the Qdrant tenant filter from the trusted `Principal`; the client never supplies tenant scope.

**Framework mapping.** Primary: OWASP LLM08:2025 Vector and Embedding Weaknesses, especially cross-context information leaks in multi-tenant vector databases and permission-aware partitioning. Impact mapping: OWASP LLM02:2025 Sensitive Information Disclosure.

## Scenario P2A-A2: client-controlled tenant substitution

**Threat.** An authenticated Dynamics employee supplies `tenant_northstar_digital` in the request body and the vulnerable endpoint treats that identifier as authorization.

**Preconditions.** Local lab; synthetic Dynamics principal; attacker knows or guesses the synthetic Digital tenant identifier; attack budget of one request.

**Authorized reproduction.** POST `{"query":"vpn","tenant_id":"tenant_northstar_digital","limit":5}` to `/v1/knowledge/search-client-tenant` with Alice's synthetic authentication header.

**Vulnerable behavior.** The query is filtered to the attacker-selected Digital tenant and the Digital canary is observable despite Alice authenticating as a Dynamics user.

**Hardened behavior.** The same payload sent to `/v1/knowledge/search` is rejected because `SearchRequest` forbids extra identity/tenant fields. Even without that schema rejection, hardened retrieval derives tenant scope from `Principal` rather than request data.

**Control.** Server-side identity derivation plus strict Pydantic request schemas plus principal-bound retrieval.

**Framework mapping.** Impact: OWASP LLM02:2025 Sensitive Information Disclosure. Secondary agentic identity mapping: OWASP ASI03 Identity & Privilege Abuse. P2-A itself is a retrieval/control-plane baseline, so ASI03 is recorded as a conceptual identity mapping rather than evidence of a full autonomous-agent exploit.

## Evaluation definition

`python -m evals.p2a_tenant_boundary` executes the same two fixed adversarial payloads against vulnerable and hardened variants using the same synthetic principal, corpus, deterministic embeddings, query text, limits, and attempt budget.

A **valid attempt** is one of those fixed authenticated local synthetic requests. A **successful policy violation** occurs only when the response contains the other tenant's canary. `ASR = successful policy violations / valid adversarial attempts`. The report records raw numerator/denominator, percentage, code commit when available, dependency versions, evaluation/corpus hashes, HTTP status, and retrieved document IDs. It deliberately does not print response bodies or canary values.

FPR and SafeTaskRate are not measured in P2-A because this narrow harness contains no matched benign request set. They will be added when the evaluation corpus includes benign tasks; inventing zero-valued denominators here would be misleading.

## Regression evidence

- `tests/security/test_p2a_tenant_attacks.py` proves the vulnerable behaviors are reproducible and the hardened behaviors block them.
- `tests/security/test_vulnerable_isolation.py` proves the hardened FastAPI app does not expose the vulnerable routes and the vulnerable module has no module-level `app` object.
- `tests/security/test_p2a_metrics.py` locks the deterministic ASR comparison for this fixed two-attempt dataset.
- CI runs the full pytest suite and then prints the P2-A evaluation report.

## Residual risk

This baseline tests deterministic lexical embeddings and a tiny synthetic corpus, not a production identity provider, distributed vector cluster, real LLM, or semantic embedding service. Passing the hardened tests demonstrates these specific invariants; it does not prove absence of all authorization or RAG leakage defects.

## Primary references

- OWASP LLM08:2025 Vector and Embedding Weaknesses: https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/
- OWASP LLM02:2025 Sensitive Information Disclosure: https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/
- OWASP Top 10 for Agentic Applications (ASI03 Identity & Privilege Abuse): https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/

An exact MITRE ATLAS technique ID is intentionally not assigned in P2-A until a primary-source mapping is verified; no ID is guessed.
