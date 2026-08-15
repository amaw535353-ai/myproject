# P7-H threat model — security control-plane and administrative change paths

## Scope

P7-H models who and what can mutate AegisDesk security-critical control-plane state. The milestone covers authorization policy, model deployment gates, telemetry configuration, service-egress policy, fallback policy, provider/server trust stores, and assurance settings.

The analysis is deterministic and synthetic. It does not execute administrative operations. Instead, it verifies that a policy-owned control-plane manifest is exactly bound to previously verified P7-B privilege, P7-E dependency, P7-F resilience, P7-G telemetry, and P6-D posture evidence.

## Security objective

A caller must not be able to convert a dangerous administrative path into a green result by declaring a change “admin approved,” “safe,” or “fully audited.” A valid assessment must derive the administrative principal, target resource, operation, approvals, execution identity, control state, audit/detection coverage, and affected upstream evidence from exact policy-pinned objects.

## Assets

Security-critical mutable resources include:

- authorization/capability policy;
- model deployment and release-security gates;
- security telemetry routing and detection configuration;
- external service-egress policy;
- graceful-degradation and fallback policy;
- provider/server identity trust stores; and
- assurance, waiver, and release-security settings.

## Trust assumptions

P7-H assumes the supplied P7-B, P7-E, P7-F, P7-G, and P6-D objects are already verified evidence objects and therefore treats their evidence digests and verification flags as the trust anchor for their contents. P7-H does not independently re-run those phases.

Trusted owners, approvers, and execution identities are explicit policy inputs. Their presence in the fixture is not a production IAM attestation.

## Administrative path model

Each path contains:

1. a policy-pinned administrative principal;
2. one or more exact P7-B privilege paths that justify that principal's administrative reach;
3. a policy-pinned control-plane resource and sensitivity;
4. exact upstream bindings such as `p7b:<path>`, `p7e:<path>`, `p7f:<scenario>`, `p7g:<requirement>`, or `p6d:<control>`;
5. an administrative operation;
6. a trusted execution identity;
7. exact independent approvers;
8. exact required controls;
9. exact P7-G telemetry requirements for the administrative change;
10. an expected target version and SHA-256 state digest;
11. a fresh verification timestamp and non-empty change reference; and
12. optional break-glass metadata only when both the principal and resource permit it.

## Fail-closed validation

The analyzer rejects malformed or substituted evidence for:

- request/manifest identity and SHA-256 binding;
- stale/future manifests and route observations;
- missing, duplicate, or untrusted principals/resources/routes;
- principal type, P7-B path, or break-glass drift;
- resource type, sensitivity, upstream binding, control, telemetry, separation-of-duties, or break-glass drift;
- unknown upstream evidence objects;
- route principal/resource/operation/execution identity drift;
- missing, substituted, untrusted, duplicate, or self approvals;
- missing resource controls or resource-required change telemetry;
- target version or target-state digest substitution;
- invalid break-glass use;
- missing change references;
- P7-B/P7-E/P7-F/P7-G/P6-D verification or digest substitution; and
- inconsistent P6-D per-control summaries.

## Derived exposure conditions

Structurally valid paths can still be exposed. P7-H derives exposure when:

- the administrative principal's P7-B privilege path is exposed;
- the target resource is bound to an exposed P7-B/P7-E/P7-F/P7-G/P6-D object;
- a required administrative control is exceptioned or not evaluated;
- the administrative change's required P7-G telemetry currently has a blind spot;
- an authorization administrator can mutate the exact P7-B path that grants its own authority;
- telemetry configuration can mutate the same P7-G requirement used to audit that change; or
- a critical control-plane resource is subject to a destructive `DISABLE` or `DELETE` route.

These conditions remain visible even when other controls are satisfied; satisfied controls are retained as mitigating counterevidence rather than being treated as proof that the path is safe.

## Separation of duties and break glass

Every required route has policy-owned approver identities that cannot include the acting principal. The policy itself is rejected if its expected approval set encodes self-approval.

Break-glass use is explicit rather than implicit. A break-glass route requires a break-glass-capable principal, a resource that permits emergency mutation, an emergency reason, trusted independent approvers, the normal route controls, and the normal change telemetry. Break glass is not modeled as a bypass around logging or authorization.

## Intentionally vulnerable baseline

`VulnerableAdminApprovedChangeReporter` trusts caller-owned aggregate declarations that a change is admin approved, safe, has zero exposed routes, and has zero risk. It does not bind the caller's statement to identity, approvals, execution identity, target resource, control posture, telemetry, or upstream evidence.

## Deterministic evidence

The canonical fixture contains 6 administrative principals, 7 control-plane resources, and 8 administrative change routes, including a policy-constrained emergency trust-store rotation.

The adversarial evaluator contains 92 cases. It covers request/manifest substitution, principal/resource/route coverage and definition drift, untrusted ownership, sensitivity downgrade, upstream-binding substitution, control and telemetry substitution, self approval, execution-identity substitution, version/target digest changes, break-glass abuse, stale/future observations, P7-B/P7-E/P7-F/P7-G/P6-D evidence substitution, control-summary inconsistency, caller masking of exposed upstream evidence, caller masking of change-telemetry blind spots and degraded controls, coherent self-authorization mutation, coherent self-audit mutation, and a coherent critical destructive route.

An isolated API-compatible harness executed the exact P7-H module/evaluator/test files against synthetic upstream objects, passed 14 pytest tests, and completed the deterministic evaluator with vulnerable ASR 92/92, hardened ASR 0/92, hardened FPR 0/3, and SafeTaskRate 3/3.

Exact hashes:

- control-plane manifest SHA-256: `c7a3e96a0227eabe57ae56326047d583af46e95decf49a8d8a958cd3e76f9525`;
- adversarial dataset SHA-256: `96a007b13658518dfe5d0b507114b71111300ecef30bbdabf8d91493daac177d`;
- fixture SHA-256: `b0c8732204c57e29f517ac69fa55e9168d999d8b8a96897a30f1165f200a82f0`.

## Claim boundary

P7-H does not claim production IAM/RBAC enforcement, actual cloud/admin API interception, live change-ticket validation, cryptographic human approval, hardware-backed administrative identity, real trust-store rotation, production configuration deployment, rollback-resistant configuration history, formal authorization proof, control-plane exploitability proof, or compliance certification.

It can claim deterministic synthetic evidence that modeled administrative changes are bound to exact privilege, resource, approval, execution, control, telemetry, and upstream-security evidence, with explicit self-authorization and self-audit takeover-path detection.
