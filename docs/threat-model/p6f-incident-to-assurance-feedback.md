# P6-F threat model — incident-to-assurance feedback and threat-informed regression coverage

## Objective

P6-F closes a modeled assurance loop between P5-I operational serving-abuse incidents and the Phase 6 adversarial regression corpus. A material verified incident must become an explicit, integrity-bound regression obligation rather than disappearing after incident response.

The control is intentionally deterministic and synthetic. It verifies evidence relationships; it does not discover incidents, generate tests, operate a SIEM, or prove that a regression case is semantically equivalent to a real-world failure.

## Security boundary

Inputs are:

- a P5-I `VerifiedIncidentDecision`;
- an exact P6-A baseline and candidate `AssuranceCorpus`;
- the P6-C `CorpusChangeManifest` and `VerifiedCorpusEvolution` for that corpus transition;
- an append-only incident coverage ledger;
- an incident feedback record with exact case/change links; and
- a caller request binding all of the above by SHA-256.

Output is inert `VerifiedIncidentFeedback`. No model, network, SIEM, ticketing, deployment, or remediation action is executed.

## Material incident threshold

By default, only P5-I `QUARANTINE` and `REVOKE_DEPLOYMENT` decisions create durable regression obligations. `QUARANTINE` maps to at least `HIGH` assurance severity and `REVOKE_DEPLOYMENT` maps to at least `CRITICAL`.

This deliberately avoids pretending that every low-risk observation or throttle event should permanently expand the corpus.

## Strong properties

The hardened gate requires:

1. intact P5-I telemetry signature, chain, completeness, and no-network evidence;
2. exact incident ID, deployment, batch SHA-256, action, risk score, and signal-count binding;
3. an exact policy-pinned baseline corpus identity and SHA-256;
4. intact P6-C evolution verification flags plus exact baseline/candidate/change-manifest/count binding;
5. an exact policy-pinned previous incident coverage ledger;
6. a candidate ledger that advances by exactly one version and names the exact previous ledger digest;
7. immutable carry-forward of every historical incident coverage obligation;
8. exactly one new obligation for the current material incident;
9. a deterministic incident trace digest binding action, deployment, batch, risk, signal counts, and minimum severity;
10. explicit candidate assurance cases carrying that trace digest in the invariant text;
11. `BLOCK` expectation and action-derived minimum severity for every linked incident case;
12. an allowlisted target boundary and the policy-required `incident_derived_serving_abuse` attack class;
13. exact case-definition SHA-256 binding;
14. exact P6-C `ADD` or `MODIFY` change records for linked cases;
15. trusted change ownership and a deterministic change reason tied to feedback ID, incident ID, and batch digest;
16. exact coverage of every material P5-I signal across the linked cases;
17. qualifying candidate-corpus coverage for every historical ledger obligation; and
18. request-level binding to feedback, candidate corpus, candidate ledger, incident batch, and P6-C evolution evidence.

The in-memory gate also rejects duplicate feedback IDs within one process lifetime.

## Why the incident coverage ledger exists

P6-C already governs corpus removal and weakening, but P6-F adds a separate append-only operational obligation ledger so a known incident cannot be silently forgotten merely by changing which cases are present. Existing obligations must be preserved byte-for-byte in the next ledger version, and the candidate corpus must still contain qualifying trace-bound coverage for every active obligation.

This is evidence-level continuity only. The lab does not provide rollback-resistant or distributed durable storage for the ledger.

## Modeled attacks

The deterministic evaluation covers:

- degraded or malformed P5-I incident evidence;
- non-material incident substitution;
- baseline/candidate corpus substitution;
- degraded or mismatched P6-C evolution evidence;
- previous-ledger digest substitution;
- ledger rollback, fork, dropped obligations, and obligation mutation;
- omission or downgrade of the current incident obligation;
- feedback identity/action/risk/signal substitution;
- request digest substitution;
- case-definition and signal-scope substitution;
- `BLOCK` to `ALLOW` weakening;
- severity, boundary, and attack-class substitution;
- incident trace removal;
- missing, deprecated, untrusted-owner, or unbound P6-C change records; and
- deletion of historical incident regression coverage.

## Explicit non-claims

P6-F does **not** claim:

- production SIEM/SOAR or incident-management integration;
- automatic test generation from incidents;
- semantic equivalence between a production incident and the linked regression case;
- automatic root-cause analysis;
- production remediation or deployment actions;
- cryptographic human approval;
- rollback-resistant or distributed incident-ledger storage;
- complete threat-intelligence or MITRE ATT&CK/ATLAS coverage;
- proof that all incident signals have been converted into sufficient tests;
- formal verification;
- external auditor evidence; or
- compliance certification.

## Residual risk

A trusted operator can still create a poor regression case that contains the correct incident trace but does not faithfully reproduce the real failure. The gate proves exact evidence and governance linkage, not semantic test quality. A compromised policy administrator can also change trusted owners, allowed boundaries, material-action thresholds, or severity mappings. Durable anti-rollback storage remains outside the synthetic-lab scope.
