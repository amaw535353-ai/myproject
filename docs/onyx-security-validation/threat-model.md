# O1 Threat Model — Onyx RAG Authorization

## 1. Security objective

Validate that Onyx enforces document retrieval authorization using server-derived user/group state and that untrusted prompt, retrieval, metadata, or model content cannot expand access.

## 2. Assets

- synthetic private document content and canaries
- authenticated user identity
- group membership
- document/document-set ACL state
- tenant context where applicable
- retrieval/index state
- evidence integrity

## 3. Actors

- `alice`: synthetic engineering user
- `bob`: synthetic HR user
- `attacker`: synthetic low-privilege user
- synthetic administrator used only for fixture provisioning
- AegisDesk evaluator

## 4. Trust boundaries

- external harness to local target identity
- request to authenticated Onyx principal
- principal to ACL construction
- ACL state to index/search filtering
- search result to evidence classification

## 5. Entry points

- authenticated search/query APIs used by the selected local Onyx revision
- document/document-set APIs required to create deterministic fixtures
- direct document retrieval endpoint if the current revision exposes one
- conversation/chat retrieval path where it can surface indexed documents

Paths and payloads must be discovered from the pinned revision; stale documentation is not an API contract.

## 6. Preconditions

- exact Onyx and AegisDesk commits recorded
- local target positively validated
- synthetic credentials only
- deterministic fixture organization provisioned
- expected ACL matrix recorded before execution

## 7. Attack paths

O1 must cover, where executable on the selected local build:

1. cross-user retrieval
2. cross-group retrieval
3. direct document-ID guessing
4. caller-manipulated metadata/document-set filters
5. semantic near-duplicate query intended to pull a forbidden document
6. revoked document retrieval
7. reproducible stale authorization/index state
8. cached retrieval state
9. conversation-context leakage after authorization changes
10. poisoned public document instructing the system to retrieve forbidden content

## 8. Expected vulnerable behavior

A weakened comparison is vulnerable if an unauthorized principal receives a forbidden document ID or the document's unique sensitive synthetic canary because authorization filtering was omitted, stale state was treated as authoritative, or caller/model-controlled data expanded scope.

## 9. Hardened invariant

Authorization is evaluated using current server-owned identity and permission state at the relevant retrieval/effect boundary. Model or document text may influence a query but cannot grant access.

## 10. Detection

O1 evidence should be capable of emitting sanitized structured events for repeated denied retrieval and cross-scope enumeration. Full detection implementation is later scope; no O1 result depends on model prose alone.

## 11. Test methodology

Each important control requires:

- attack case
- safe case
- negative assertion
- weakened-control regression proof where a safe isolated test double can model omission of the ACL check
- server-side or retrieval-result evidence

A live-local case is executable only after target validation. Missing group support, missing endpoint support, or missing live configuration returns `BLOCKED`.

## 12. Evidence

Per case record:

```json
{
  "case_id": "ONYX-O1-RAG-...",
  "category": "rag_auth",
  "target": "onyx",
  "onyx_commit": "...",
  "aegis_commit": "...",
  "mode": "deterministic|live-local",
  "attack": true,
  "expected": "deny",
  "observed": "...",
  "security_effect": "unauthorized_document_returned|blocked|authorized_document_returned",
  "status": "PASS|FAIL|BLOCKED",
  "duration_ms": 0,
  "evidence": {},
  "sanitized": true
}
```

Sensitive values are represented only by synthetic canary identifiers or sanitized hashes. Credentials, bearer tokens, OAuth secrets, full private prompts containing secrets, and chain-of-thought are forbidden evidence fields.

## 13. Residual risk

A passing O1 result does not prove production behavior, distributed revocation consistency, every connector's external-permission synchronization, every deployment mode, or every Onyx edition. Live-local evidence is scoped to the pinned revision and exact lab configuration.

## 14. Framework mapping

Defensible high-level mappings only:

- OWASP GenAI/LLM Top 10: sensitive information disclosure and prompt-injection relevance where untrusted retrieved content attempts to expand access.
- OWASP Agentic Applications: authorization/context risks are relevant, but O1 does not claim complete agentic coverage.
- MITRE ATLAS: prompt-injection and RAG/context poisoning concepts are relevant; no locally invented technique identifiers are asserted.
- NIST AI RMF / NIST AI 600-1: mapping, measuring, and managing security/privacy boundaries and adversarial evaluation are relevant.
- CWE-862 (Missing Authorization) and CWE-863 (Incorrect Authorization) are applicable when an executable retrieval path lacks or misapplies access control.

These mappings are engineering references, not compliance claims.