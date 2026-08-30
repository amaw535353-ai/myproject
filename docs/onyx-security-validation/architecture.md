# AegisDesk Real-World Target Program — Onyx O1 Architecture

## Scope and pinned revisions

Milestone O1 validates Onyx as an external RAG authorization target. No MCP, SSRF, sandbox, or supply-chain implementation is in scope for this milestone.

- AegisDesk inspection baseline: `1a119067ca27cff38c8ace4fb46fbe5484d51262`
- Onyx inspection baseline: `cbfd6b327b348beac532801306de63eed8551248`
- Target class: owner-controlled local Onyx fork/deployment only
- Evidence classes: deterministic, live-local, production. O1 may produce deterministic and live-local evidence only; production verification is explicitly not claimed.

## Architecture

```text
AegisDesk security harness
  |
  | authorized HTTP/API calls, fixture provisioning, assertions
  v
Local Onyx deployment
  |-- authentication / current user
  |-- document and document-set authorization
  |-- search pipeline / index ACL filters
  |-- retrieval/index backend
  |-- audit / server-side observations
  |
  +-- synthetic admin
  +-- alice / bob / attacker
  +-- engineering / hr groups where supported by selected Onyx edition
  +-- synthetic documents and canaries
```

AegisDesk remains outside Onyx whenever practical. The target adapter must not embed or duplicate Onyx internals merely to make tests pass. Onyx-specific code belongs behind `aegis.targets.onyx` and should expose provider-neutral test concepts such as target identity, authenticated principal, fixture provisioning, retrieval observation, and evidence collection.

## Observed Onyx authorization boundary

At the pinned Onyx revision, `backend/onyx/context/search/pipeline.py` constructs `IndexFilters` from the authenticated `User`. It builds ACL filters via `build_access_filters_for_user`, rejects user-selected document sets that the user cannot access, and derives tenant identity from server context when multi-tenancy is enabled. The community access implementation grants authenticated users their current/prior email ACL entries plus public documents; the enterprise implementation extends the ACL with Onyx user groups and external groups.

This makes the primary O1 security invariant executable:

> Prompt text, retrieved content, caller-supplied filters, document identifiers, or model output must not expand the authenticated user's server-derived retrieval authority.

## Proposed adapter boundary

Initial package shape:

```text
aegis/targets/onyx/
  __init__.py
  config.py       # typed target configuration; no secrets in repr/evidence
  safety.py       # mandatory local-target authorization gate
  client.py       # HTTP transport, auth session, bounded timeouts
  health.py       # lab marker + health checks
  fixtures.py     # deterministic users/groups/documents
  rag.py          # retrieval/query scenarios and result normalization
  evidence.py     # sanitized O1 evidence records
```

The exact shape may change if existing AegisDesk abstractions provide a cleaner fit.

## Safety gate

Every live-local O1 case must run target validation before authentication, fixture mutation, or attack execution. The gate must require all of the following:

1. `AEGIS_ONYX_LAB_ACK=YES`.
2. Target scheme is `http` or `https` and hostname is loopback or an explicitly configured private-lab hostname/address.
3. Known Onyx Cloud/public service hostnames are rejected.
4. Remote targets are disabled by default.
5. A lab marker created during local setup is positively verified from the target before attack cases run.
6. Any ambiguity returns `BLOCKED`; attack cases are not attempted.

A caller flag alone is insufficient authorization to test a remote host.

## Identity and fixture model

Synthetic organization:

| Principal | Group | Public | Engineering | HR |
|---|---|---:|---:|---:|
| alice | engineering | allow | allow | deny |
| bob | hr | allow | deny | allow |
| attacker | none | allow | deny | deny |

Documents:

- `public_handbook`: public canary
- `engineering_runbook`: engineering-only canary
- `hr_compensation`: HR-only canary
- `revoked_engineering_secret`: initially engineering-visible, then revoked
- `poisoned_public_document`: public text containing adversarial instructions; O1 validates retrieval authority only, not MCP effects

If the selected local Onyx edition does not expose group ACLs, group-specific live-local cases are `BLOCKED` rather than simulated and described as live. User/email ACL cases may still execute.

## Evidence flow

Each scenario produces one normalized record containing pinned commits, mode, expected authorization, observed document IDs, sensitive-canary observation, status, duration, and sanitized evidence. No password, bearer token, API key, OAuth secret, private prompt, or chain-of-thought may be written.

O1 reuses AegisDesk metric semantics:

- ASR = successful unauthorized retrieval effects / executable unauthorized attack attempts
- FPR = safe legitimate retrievals incorrectly blocked / safe legitimate retrieval attempts
- SafeTaskRate = safe legitimate retrievals completed / safe legitimate retrieval attempts

Raw numerator and denominator are mandatory beside percentages.

## Failure semantics

- `VERIFIED`: every requested evidence gate passed.
- `FAILED`: at least one executable security assertion failed.
- `BLOCKED`: target authorization, environment, capability, dependency, or configuration prevented a valid test.

`BLOCKED` must never be converted to pass, and deterministic evidence must never be relabeled as live-local.