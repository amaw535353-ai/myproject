# P10-A — inference tenant, request, and runtime-state isolation

## Scope

P10-A starts Phase 10: secure inference runtime and multi-tenant serving. It adds a deterministic admission boundary for one inference request before model execution. The boundary binds an opaque deployment-attestation handle and the exact P9-H promotion assessment into immutable serving-route evidence, then derives tenant/session isolation for request identity, batching, KV/prefix-cache ownership, adapter/draft-model routing, output delivery, and replay state.

This milestone is intentionally distinct from Phase 5's inference-privacy and abuse-response controls. P5-G limits oracle/output exposure and query budgets; P5-I binds post-deployment telemetry and response decisions. P10-A instead secures internal serving state so one tenant cannot obtain another tenant's request, batch, cache, model-composition, or output route merely because the deployed model itself is trusted.

## Hardened boundary

`InferenceTenantIsolationAnalyzer` requires:

- exact policy/manifest SHA-256 and freshness binding;
- exact deployment-attestation identity/digest and exact P9-H promotion assessment SHA-256;
- immutable deployment, endpoint, model revision, model artifact and tokenizer digest pins;
- exact adapter and speculative draft-model identity/digest pins;
- tenant allowlisting plus tenant-owned principal and authorization-context binding;
- tenant-namespaced session and conversation identity;
- same-tenant batch membership, tenant partition key, and scheduler allowlisting;
- exact KV-cache tenant/session/epoch namespace ownership;
- tenant-scoped prefix-cache ownership with cross-tenant reuse disabled;
- tenant/session-bound output channel and response-object routing;
- deterministic prior-request ledger binding with current-request replay rejection; and
- zero modeled network operations.

Caller-declared route/isolation booleans must agree with the evidence-derived result. They cannot convert unsafe evidence into an allow decision.

## Threats modeled

The adversarial corpus covers upstream deployment/promotion evidence substitution, endpoint/model/tokenizer swaps, mutable model references, adapter and speculative-draft swaps, tenant/principal/authz confused-deputy routing, cross-tenant sessions, batch partition and scheduler substitution, mixed-tenant batching, KV-cache namespace/owner/session/epoch substitution, prefix-cache cross-tenant reuse, output recipient/channel substitution, replay/ledger tampering, request freshness manipulation, and caller-summary lies.

## Security invariants

A request is admitted only when its immutable serving route, tenant/principal/session identity, batch partition, cache ownership, model composition, output route, and replay state all agree with policy. A benign same-tenant batch may contain multiple requests. A second allowlisted tenant may also be admitted when every tenant-derived namespace and authorization binding changes consistently.

SHA-256 values provide deterministic integrity binding inside the lab; they do not authenticate the source of evidence.

## Claim boundary

P10-A does **not** claim that a real inference server, scheduler, GPU, KV-cache implementation, prefix-cache implementation, adapter loader, speculative decoder, or streaming transport executed. It does not prove physical GPU-memory zeroization, process/container isolation, timing/cache side-channel resistance, production distributed replay prevention, hardware attestation, scheduler fairness, autoscaling correctness, or protection against a compromised serving host. It also does not establish semantic model safety or a privacy guarantee.

The deployment-attestation and P9-H values are policy-bound evidence handles. P10-A does not re-run Phase 5 or Phase 9 verification and does not upgrade synthetic evidence into production attestation.
