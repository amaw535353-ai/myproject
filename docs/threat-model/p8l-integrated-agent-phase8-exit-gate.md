# P8-L threat model — integrated multi-agent compromise exercise and Phase 8 exit gate

## Security objective

P8-L closes Phase 8 by checking whether the deterministic evidence produced for P8-A through P8-K belongs to one policy-pinned execution lineage and whether the available verification evidence supports the claim being made. The gate must distinguish **security validation that actually executed** from **hosted CI that was requested but never started**.

The intended exit states are:

- `PASS`: local security validation is complete and remote CI evidence proves a runner actually started and executed steps;
- `PASS_WITH_EXTERNAL_CI_LIMITATION`: the synthetic/local security evidence is complete, but hosted CI is externally blocked before runner execution for a policy-recognized infrastructure reason;
- `FAIL`: evidence is missing/tampered/unsafe, local verification did not execute successfully, a remote CI job actually executed and failed, or an unsupported production claim is asserted.

`PASS_WITH_EXTERNAL_CI_LIMITATION` is deliberately not an alias for hosted CI success.

## Integrated attack lineage

The canonical deterministic exercise models one chain across all Phase 8 control domains:

1. P8-A — delegation and authority propagation;
2. P8-B — memory/context boundary;
3. P8-C — goal/plan and instruction integrity;
4. P8-D — tool-result/environment observation integrity;
5. P8-E — execution-budget/runaway-resource control;
6. P8-F — human approval/autonomy boundary;
7. P8-G — inter-agent messaging/protocol security;
8. P8-H — state-machine concurrency/race security;
9. P8-I — generated artifact/workspace integrity;
10. P8-J — rollback/recovery/persistence security;
11. P8-K — incident containment, evidence preservation, forensic reconstruction, and controlled re-entry.

Each milestone envelope carries the same execution-lineage ID, an exact milestone manifest digest, exact assessment digest, policy-pinned assessment schema/mode, predecessor assessment digest, and input/output state digests. The next milestone must consume the exact previous output-state digest. This provides deterministic continuity for the lab exercise without claiming a production distributed trace.

## Verification evidence model

Local verification records require an execution marker (`runner_started=true`) and a positive executed-step count. A record labeled `LOCAL_FOCUSED_PASS` or `LOCAL_FULL_PASS` without execution is invalid.

Remote CI evidence is deliberately stricter:

- `REMOTE_CI_PASS` requires a started runner, at least one executed step, and no block reason;
- `REMOTE_CI_BLOCKED` requires no started runner, exactly zero executed steps, and a policy-recognized external block reason;
- `REMOTE_CI_FAIL` represents an actually started/executed remote run that failed and therefore makes the exit decision `FAIL`.

The canonical P8-L fixture uses `REMOTE_CI_BLOCKED` with reason code `github-hosted-runner-account-billing-or-spending-limit`. This models the observed account/billing infrastructure condition while preventing it from being reported as either a security-test failure or a CI pass.

## Threats covered

The hardened gate rejects or fails closed on:

- missing, duplicate, substituted, or reordered P8-A through P8-K evidence;
- control-domain or step-index substitution;
- execution-lineage drift;
- predecessor assessment-chain breaks;
- cross-milestone input/output-state discontinuity;
- milestone manifest/assessment digest substitution;
- assessment schema/mode drift;
- unsafe upstream milestone results;
- upstream designs that trust caller-declared safety;
- unexpected network side effects in the synthetic evidence envelope;
- missing/nonexecuted local verification;
- remote CI pass claims with no runner or zero executed steps;
- blocked CI records that nevertheless claim executed steps;
- unknown/unapproved block reasons;
- actually executed remote CI failures;
- incomplete synthetic/local assumptions;
- production runtime, distributed-system, SIEM/EDR, secret-rotation, or cryptographic-attestation claims unsupported by the lab; and
- caller-declared exit/evidence/verification summaries that disagree with derived evidence.

## Trust boundaries and limitations

P8-L is an evidence-composition gate for the deterministic lab. It does not independently re-run every P8-A through P8-K analyzer inside the P8-L analyzer itself, digitally sign prior assessments, or prove that a distributed production agent runtime emitted the evidence. Exact SHA-256 binding is tamper-evidence inside the deterministic model, not origin authentication.

The following assumptions remain explicit and machine-enforced: deterministic synthetic fixtures, single-process local evaluation, no production agent orchestrator, no production secret rotation, no production SIEM/EDR, no production distributed event log, no trusted distributed clock, and no cryptographic attestation.

## Reproducible local practice path

`scripts/verify_phase8.py` provides an explicit local verification path. `--focused-p8l` runs only the P8-L focused tests/evaluator; the default runs full pytest plus all P8-A through P8-L evaluators. Its report marks hosted CI verification as false because local execution cannot substitute for GitHub-hosted runner evidence.

## Claim boundary

P8-L may claim only deterministic synthetic/local evidence integrity and verification-state separation. It does not claim production compromise containment, production workload isolation, production credential rotation, independently witnessed logs, trusted timestamps, legal chain of custody, production CI availability, or production distributed-system validation.
