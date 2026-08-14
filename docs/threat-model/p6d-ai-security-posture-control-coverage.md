# P6-D threat model — AI security posture and control-coverage reporting

## Scope

P6-D converts exact Phase 6 assurance evidence into a deterministic, release-scoped security posture report. It is a reporting and evidence-binding layer, not a compliance product or production GRC integration.

The protected decision is whether a release posture can be represented as green, amber, or red without hiding control exceptions, missing evaluation coverage, or upstream-evidence substitution.

## Assets and trust boundaries

Protected assets:

- exact release identity: release ID, commit SHA, and package version;
- exact current P6-A assurance corpus digest;
- exact P6-B waiver-governance evidence digest;
- exact P6-C corpus-evolution evidence digest;
- versioned control-catalog definitions and mappings;
- per-control status and overall posture rating;
- deterministic posture evidence digest.

Trusted inputs are limited to already verified P6-B and P6-C handles plus the policy-pinned control catalog. Caller-declared posture labels are never treated as authoritative.

## Security properties

The hardened `AISecurityPostureReporter` requires:

1. a canonical, versioned control catalog whose SHA-256 exactly matches policy;
2. unique control IDs and unique mapped case/boundary identifiers;
3. all policy-required controls and risk domains;
4. a structurally valid P6-A corpus;
5. an intact P6-B `VerifiedWaiverGovernance` handle with exact regression/waiver scope and consistent summary counts;
6. an intact P6-C `VerifiedCorpusEvolution` handle with exact candidate corpus binding and consistent case/severity counts;
7. exact release identity binding to P6-B governance evidence;
8. exact request binding to corpus, catalog, P6-B evidence, and P6-C evidence SHA-256 values;
9. fail-closed rejection when upstream regression or waiver scope refers to cases outside the current corpus;
10. evidence-derived control states:
   - `satisfied` when mapped cases and required boundaries are present with no approved waiver affecting the control;
   - `exceptioned` when one or more mapped cases are under approved P6-B waiver governance;
   - `not_evaluated` when mapped cases or required boundaries are absent;
11. deterministic overall posture:
   - `green` only when every control is satisfied;
   - `amber` for non-critical permitted exceptions or lower-severity missing evaluation;
   - `red` for critical/non-permitted exceptions or high/critical missing evaluation under policy;
12. rejection when a caller-declared posture disagrees with the evidence-derived posture.

## Threats modeled

The deterministic evaluation covers:

- policy/control-catalog digest substitution;
- control-definition substitution;
- duplicate control IDs and duplicate case mappings;
- omission of required controls or risk domains;
- release/commit/package-version substitution;
- corpus, catalog, P6-B evidence, and P6-C evidence digest substitution;
- degraded P6-B verification flags;
- P6-B corpus substitution, waiver-scope substitution, unknown waived cases, and summary-count inconsistencies;
- degraded P6-C verification flags;
- P6-C candidate-corpus and summary-count substitution;
- caller-declared green posture attempting to hide high or critical exceptions;
- caller-declared green posture attempting to hide missing critical case coverage or an absent high-severity boundary;
- caller-declared non-green posture that disagrees with fully green evidence.

## Vulnerable baseline

`VulnerableDeclaredPostureReporter` accepts caller-supplied posture labels and aggregate satisfied/exceptioned/not-evaluated counts without binding them to any release identity, assurance corpus, waiver evidence, corpus-evolution evidence, or control definitions.

## Claim boundary

P6-D can claim deterministic evidence-derived posture over the modeled P5/P6 controls and exact upstream evidence digests.

P6-D does **not** claim:

- regulatory or standards certification;
- SOC 2, ISO 27001, NIST AI RMF, EU AI Act, PCI DSS, FedRAMP, or other framework compliance;
- production GRC platform integration;
- external auditor evidence or auditor sign-off;
- production IAM/RBAC enforcement;
- cryptographic human approval attestation;
- independent verification that P6-B/P6-C evidence was produced by uncompromised infrastructure;
- exhaustive control coverage or proof that the selected control catalog is sufficient;
- real-time cloud, Kubernetes, SIEM, ticketing, or CMDB integration;
- rollback-resistant evidence storage or transparency logging;
- formal verification;
- network operations.

The returned `VerifiedSecurityPosture` explicitly records these non-claims.
