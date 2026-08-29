# O1 Assumptions and Non-Claims

## Pinned inspection state

- AegisDesk: `1a119067ca27cff38c8ace4fb46fbe5484d51262`
- Onyx: `cbfd6b327b348beac532801306de63eed8551248`

All implementation must re-check paths/APIs against the pinned target revision rather than assuming current documentation remains accurate.

## Assumptions to validate during implementation

1. The owner-controlled Onyx fork can be built/run locally from the pinned revision using its repository deployment assets.
2. A deterministic synthetic user/document fixture can be provisioned through supported local APIs or narrowly scoped local setup helpers.
3. The local edition selected for O1 exposes enough authorization capability for user ACL tests. Group ACL tests require an edition/configuration that actually supports Onyx groups; otherwise those live cases are `BLOCKED`.
4. The selected retrieval endpoint exposes enough result metadata to identify returned document IDs or synthetic canaries without depending on model prose.
5. Live-local tests can obtain or create a lab marker that is not present on public Onyx services.
6. Revocation/index synchronization behavior may require explicit polling with a bounded timeout. Timeout is `BLOCKED` or `FAIL` according to whether the security assertion became executable; it is never silently passed.

## Non-assumptions

- Authentication does not imply authorization.
- Prompt instructions do not constitute an access-control mechanism.
- Onyx Cloud behavior is not inferred from local source or local execution.
- Community and enterprise ACL behavior are not treated as identical.
- A passing search query does not prove every direct-document or chat-file endpoint is safe.
- A synthetic weakened test double is not evidence that upstream Onyx is vulnerable.
- No production credentials, employee data, customer data, or third-party MCP/infrastructure are required or permitted.

## Explicit non-claims

O1 does not claim production verification, comprehensive Onyx security, MCP safety, SSRF safety, sandbox escape resistance, supply-chain assurance, distributed revocation consistency, or authorization correctness for every connector and deployment topology.