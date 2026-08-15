# P9-I — integrated training compromise exercise and Phase 9 exit gate

## Objective

P9-I closes the current Phase 9 deterministic synthetic scope with a verification-aware exit gate that composes P9-A through P9-H without re-implementing those controls. The gate binds exact historical milestone manifests and clean assessments, preserves predecessor/state lineage, exercises cross-boundary compromise paths, and emits a machine-readable Phase 9 exit decision.

## Protected invariants

The gate requires exact P9-A-through-P9-H milestone order, control-domain identity, policy-pinned manifest/assessment SHA-256 values, assessment schemas/modes, predecessor-assessment chaining, state continuity, safe upstream decisions, caller-declared-safety distrust, and zero modeled network operations.

Eight deterministic compromise exercises cover poisoning propagation, unauthorized tuning/base substitution, training-job privilege escalation, checkpoint rollback/state substitution, benchmark contamination/score inflation, sensitive-data/canary reproduction, registry artifact/reference substitution, and upstream-assessment replay at promotion. Each scenario is policy-pinned to its attack class, entry milestone, ordered propagation path, attack-input digest, detection milestone, and recovery-state digest. Every scenario must be detected and must block promotion.

Local verification evidence is bound to the focused P9-A-through-P9-H evaluator evidence. Hosted CI is classified by execution facts: a pass requires a runner to start and execute steps; a blocked run requires no runner start, zero steps, and a policy-recognized external reason; an executed failure is a Phase 9 exit failure.

## Fail-closed cases

The exit gate rejects or fails on milestone omission/reordering, schema/mode or digest substitution, predecessor/state-chain breaks, unsafe upstream evidence, caller-safety trust, compromise-scenario omission/reordering/substitution, undetected compromise, promotion fail-open behavior, missing local execution evidence, malformed hosted-CI claims, unexpected network activity, missing synthetic assumptions, unsupported production claims, stale/replayed requests, or caller-declared exit summaries that differ from evidence.

## Claim boundary

P9-I is deterministic synthetic evidence. SHA-256 provides integrity binding inside the lab, not origin authentication. It does not claim production data-platform integration, real training-runtime execution, scheduler/IAM/KMS enforcement, production checkpoint-store durability, hidden-benchmark service integrity, comprehensive privacy/DLP/legal compliance, a real model-registry write, deployment execution, cryptographic workload attestation, or semantic model safety.

`PASS_WITH_EXTERNAL_CI_LIMITATION` means the modeled Phase 9 security evidence is internally consistent while hosted CI remains externally blocked before runner execution. It is neither a hosted CI pass nor a security-test failure.
