# P8-F threat model — human handoff, approval, and autonomy-boundary security

## Scope

P8-F models human approval as security evidence rather than as a caller-owned boolean. A proposed agent action is bound to a policy-pinned autonomy boundary, an exact argument digest, an exact plan digest, a reviewer identity/role/group, freshness limits, and exact P8-C/P8-D/P8-E upstream evidence.

The milestone is deterministic and synthetic. It does not call a production identity provider, approval service, policy engine, ticketing platform, or agent runtime.

## Security objective

An action that requires human review must not execute merely because an agent reports `approved=true`. Approval must be attributable to an authorized reviewer, fresh, scoped to the exact action and plan, non-replayed, independent where policy requires multiple reviewers, and consistent with the current autonomy level and upstream plan/observation/resource evidence.

## Canonical fixture

The fixture contains **5 approval rules**, **5 pending actions**, and **5 approval records**. It covers read-only search, tenant ticket mutation, irreversible release deployment, security telemetry mutation, and authorization-policy mutation.

The release action requires two independent reviewers from distinct reviewer groups. Ticket, telemetry, and policy mutations require explicit human review; low-risk search may run without a human under its policy-pinned autonomy boundary.

## Hardened properties

`HumanHandoffAutonomySecurityAnalyzer` enforces exact graph ID/version/SHA-256 and freshness; exact P8-C goal/plan, P8-D tool-observation, and P8-E execution-budget evidence binding; exact rule/action/approval coverage; trusted evidence owners; policy-pinned action risk, maximum autonomy, reviewer roles/count/separation/edit policy/lifetime; exact run/goal/step/delegation/principal/tenant/agent/action bindings; exact argument and plan SHA-256 binding; reviewer identity-to-role/group authorization; self-approval rejection; approval freshness and future-skew checks; nonce replay detection; explicit rejection semantics; edit authorization; independent two-person control where required; irreversible-action human-stop protection; upstream safety checks; and rejection of caller summaries that disagree with derived evidence.

A missing-but-required approval is represented as `PAUSE`, not as a fabricated approval or automatic approval. Malformed, stale, replayed, self-approved, rejected, or incorrectly bound approval evidence produces `DENY`.

## Intentionally vulnerable baseline

`VulnerableDeclaredHumanApprovalSafety` trusts caller-owned declarations that approval exists, is fresh, the action is unchanged, at least one approval exists, and no denial exists. It does not bind approval to reviewer authority, arguments, plans, autonomy limits, upstream evidence, separation-of-duties, or replay state.

## Deterministic evidence

An isolated API-compatible P8-F harness passed **14 tests** and evaluated **92 adversarial cases** with vulnerable ASR **92/92**, hardened ASR **0/92**, hardened FPR **0/3**, and SafeTaskRate **3/3**.

Exact deterministic hashes from that harness:

- approval graph SHA-256: `46292dfaf712acd8f11a1a6ee7d9d75f7f4c63ea1627affc773741b05190321d`;
- adversarial dataset SHA-256: `59f114bb2f54ce4089b201b7a51871f19eda70978b169b7a12a02591a5f1d518`;
- fixture SHA-256: `4eed658957e8230d4d5e1478b0d1a34634fef5e52884febeba9f5ea3b1e4b050`;
- clean assessment SHA-256: `e27860604d4d3cda8fa6eeb2c836f7f4714fd489d527a681378898a69c981960`.

This is not a claim that full-repository pytest ran locally or that production agent/runtime integrations were exercised.

## Free/open-source integration paths

P8-F adds no runtime dependency. Free/open-source integration options reviewed for later production-oriented work include:

- **LangGraph (MIT):** dynamic `interrupt()` and human-in-the-loop middleware can pause execution and resume after approve/edit/reject decisions. P8-F can provide the evidence boundary around such interrupts rather than treating the resume payload as sufficient authorization.
- **Open Policy Agent / OPA (Apache-2.0):** a general-purpose policy engine suitable for externalizing when an action requires human review and which reviewer roles are acceptable.
- **OpenFGA (Apache-2.0):** a self-hostable fine-grained authorization engine suitable for checking reviewer-to-resource/action relationships before accepting approval evidence.
- **OpenTelemetry (Apache-2.0):** vendor-neutral traces, metrics, and logs can carry approval request IDs, interrupt/resume events, reviewer decisions, and denial reasons into an auditable telemetry pipeline.

These are optional integration paths, not executed evidence sources for P8-F.

## Claim boundary

P8-F can claim deterministic synthetic human-approval and autonomy-boundary analysis with exact action/plan binding, freshness/replay checks, reviewer separation, self-approval rejection, and upstream evidence binding.

P8-F does **not** claim production human identity attestation, production approval-workflow enforcement, real IAM/PAM integration, cryptographic human signatures, non-repudiation, legal consent, regulatory/compliance certification, production ticket/change-management enforcement, or live agent interruption.
