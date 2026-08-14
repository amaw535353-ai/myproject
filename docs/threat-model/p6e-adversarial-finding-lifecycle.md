# P6-E threat model — adversarial finding lifecycle and closure evidence

## Scope

P6-E turns red-team/adversarial findings into deterministic, release-bound assurance objects. The protected decision is whether a finding may advance through remediation states and, in particular, whether it may be represented as `closed`.

The lab does not operate a ticketing platform or deploy patches. It verifies synthetic lifecycle records and retest evidence and returns an inert verified transition.

## Assets and trust boundaries

Protected assets:

- immutable finding identity and version history;
- exact P6-A assurance-case links;
- exact P6-B invariant owner and severity bindings;
- discovery release identity;
- fix-target release identity;
- state-transition ordering;
- exact retest runner, corpus, case-definition, result, and freshness evidence;
- closure evidence digest.

Trusted policy inputs are the exact P6-A corpus digest, exact P6-B invariant-registry digest, trusted finding owner IDs, trusted deterministic retest runner IDs, and retest freshness window.

## Security properties

The hardened `AdversarialFindingLifecycleGate` requires:

1. a structurally valid, policy-pinned P6-A corpus;
2. a policy-pinned P6-B invariant registry with exact one-to-one corpus coverage;
3. exact invariant case-definition and severity binding;
4. a trusted finding owner;
5. only attack-blocking assurance cases may be linked to an adversarial finding;
6. affected boundary identifiers must be exactly derived from linked cases;
7. invariant-owner IDs must be exactly derived from the P6-B registry;
8. finding severity must equal the highest severity of its linked cases, preventing severity downgrade;
9. immutable finding identity, linked scope, discovery identity, owner, title, tracking reference, and opened timestamp across transitions;
10. finding version increments by exactly one;
11. only `open -> fix_in_progress -> ready_for_retest -> closed` transitions are accepted;
12. monotonic non-future finding timestamps;
13. an exact fix-target release/commit/package-version identity from remediation onward, immutable once remediation begins;
14. closure evidence is forbidden before `closed`;
15. closure requires a retest bound to the exact finding ID and exact `ready_for_retest` record digest;
16. retest release identity must equal the fix target;
17. retest corpus digest must equal the current policy-pinned corpus;
18. retest runner must be trusted;
19. retest evidence must contain exact one-to-one corpus case coverage with no duplicates or unknown cases;
20. every retest result is bound to the immutable case-definition digest;
21. every finding-linked case must satisfy its P6-A expectation on the target release;
22. retest evidence must be fresh, non-future, and executed after the finding entered `ready_for_retest`;
23. the closed record must bind the exact retest SHA-256;
24. the returned transition evidence digest binds previous/proposed records, corpus, invariant registry, retest evidence, policy version, and evaluation time.

## Threats modeled

The deterministic evaluation covers:

- corpus and invariant-registry digest substitution;
- registry case omission under a repinned digest;
- invariant case-definition and severity drift;
- untrusted finding-owner substitution;
- linking a benign safe-task case as a vulnerability finding;
- unknown assurance-case links;
- affected-boundary and invariant-owner substitution;
- severity downgrade;
- finding ID and immutable-scope mutation;
- skipped finding versions;
- timestamp rollback;
- illegal direct `open -> closed` transitions;
- fix-target substitution after remediation begins;
- closure without retest evidence;
- retest evidence attached before closure;
- untrusted retest runners;
- retest finding, ready-record, target-release, and corpus substitution;
- omitted, duplicate, and unknown retest cases;
- case-definition substitution;
- a finding-linked case that still fails after the purported fix;
- stale and future-dated retest evidence;
- closure retest digest substitution;
- request-level previous/proposed record digest substitution;
- invalid retest outcome types;
- closure evidence attached to a non-closed record.

## Vulnerable baseline

`VulnerableCallerDeclaredFindingLifecycle` trusts caller-supplied finding status and a caller-declared `retest_passed` flag. It does not bind state transitions to assurance cases, invariant owners, release identity, retest evidence, freshness, or case results.

## Claim boundary

P6-E can claim deterministic finding-state and closure-evidence validation over the modeled P6-A/P6-B assurance data.

P6-E does **not** claim:

- production Jira, Linear, GitHub Issues, or vulnerability-management integration;
- real red-team platform integration;
- real patch deployment or remediation execution;
- cryptographic human remediation approval;
- rollback-resistant or tamper-proof finding storage;
- proof that all vulnerabilities or adversarial findings have been discovered;
- official CVE/CVSS assignment;
- production scanner/vendor integration;
- vulnerability disclosure-process compliance;
- secure distributed time;
- formal verification;
- automatic cloud/Kubernetes control-plane changes;
- network operations.

The returned `VerifiedFindingTransition` records these non-claims explicitly.
