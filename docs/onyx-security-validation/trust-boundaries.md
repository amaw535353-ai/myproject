# Onyx O1 Trust Boundaries

Pinned Onyx revision: `cbfd6b327b348beac532801306de63eed8551248`.

## Primary boundaries

1. **AegisDesk caller -> authorized local target**: target identity must be established before any attack case. Environment acknowledgement is necessary but not sufficient.
2. **HTTP request -> authenticated Onyx user**: user identity must come from Onyx authentication/session state, not a caller-selected user ID in test payloads.
3. **Authenticated user -> retrieval ACL**: the user's server-side ACL is the authority for search. Prompt text, model text, metadata, and arbitrary document-set names are untrusted inputs.
4. **Document/document-set metadata -> index filter**: metadata is not authority unless validated against current server-owned permission state.
5. **Database authorization state -> search index ACL state**: revocation and reindexing may create temporal inconsistency; O1 must record whether a stale-index case is reproducible and must not infer production behavior from a local result.
6. **Search result -> evidence**: returned IDs and synthetic canaries are evidence; model prose is not sufficient proof of authorization success or failure.
7. **Secrets/session material -> evidence store**: credentials are runtime-only and must be redacted or represented by non-reversible identifiers/hashes where necessary.

## Observed Onyx code boundary

At the inspected revision, Onyx search constructs `IndexFilters` with an `access_control_list` derived from the authenticated `User`. Caller-selected document sets are checked against user access before being applied. In multi-tenant mode, tenant filtering is populated from server context. Community ACLs include user email/prior-email entries and public access; enterprise ACLs additionally include Onyx groups and external groups.

## Security invariants

- An inaccessible document remains inaccessible regardless of prompt wording.
- Guessing a document ID does not bypass authorization.
- Supplying metadata or document-set names does not grant access.
- A user's ACL cannot be expanded by retrieved content or model output.
- Revoked access must not be represented as safely revoked until the live-local observation confirms the retrieval path no longer returns the document.
- Cache or conversation context must not reintroduce content after access is revoked.
- Live-local execution occurs only after positive local-lab validation.

## O1 out of scope

MCP authorization, OAuth delegation, SSRF, code-sandbox isolation, supply-chain admission, and destructive availability testing are documented as later-phase boundaries only. O1 must not add attack implementation for them.