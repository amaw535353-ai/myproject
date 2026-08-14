# P7-A threat model — trust-boundary graph and attack-path assurance

## Objective

P7-A broadens AegisDesk from continuous assurance operations into AI security architecture analysis. It models assets, owners, trust zones, directed data/control flows, attacker footholds, sensitive targets, and the P6-D security controls attached to each flow. The analyzer then deterministically enumerates simple topology paths and distinguishes controlled paths from paths with exceptioned, not-evaluated, or explicitly unguarded trust-boundary segments.

This is a synthetic architecture-evidence model. It does not discover real cloud assets, execute attacks, prove exploitability, or provide formal graph reachability.

## Assets and attacker scope

The deterministic lab architecture represents:

- an untrusted external user;
- API ingress;
- an agent orchestrator;
- retrieval and vector-data services;
- a privileged tool gateway;
- a synthetic secret boundary;
- a model registry;
- a model runtime; and
- serving-abuse security telemetry.

The policy pins two attacker entry conditions: untrusted external user access and a modeled compromised model-registry foothold. The sensitive targets are the synthetic secret store and model runtime. Entry and target sets are policy-owned rather than caller-selected.

## Strong properties

`TrustBoundaryAttackPathAnalyzer` requires:

1. a canonical versioned architecture manifest with exact SHA-256 policy and request binding;
2. manifest freshness and bounded future skew;
3. unique, typed assets and flows;
4. trusted asset and flow ownership;
5. allowlisted trust zones;
6. policy-required assets and flows that cannot be silently deleted;
7. policy-pinned trust-zone identity for required assets;
8. minimum sensitivity for protected targets;
9. valid directed flow references and no self-loops;
10. policy-pinned endpoints and control mappings for required flows;
11. explicit handling of cross-zone flows without controls;
12. intact P6-D `VerifiedSecurityPosture` evidence;
13. exact P6-D posture-evidence and control-catalog SHA-256 binding;
14. unique control assessments with valid evidence digests and internally consistent status lists;
15. rejection of architecture controls absent from P6-D evidence;
16. policy-owned attacker profile, entry assets, and target assets;
17. bounded deterministic simple-path enumeration with fail-closed truncation detection;
18. per-path trust-zone sequences and derived boundary-crossing counts;
19. per-path satisfied controls as counterevidence and exceptioned/not-evaluated controls as explicit gaps;
20. deterministic exposure/risk calculation from target sensitivity, trust-boundary crossings, control gaps, and path length; and
21. rejection when caller-declared exposed paths or maximum risk do not match the evidence-derived result.

## Exposure semantics

Topology existence and control state are deliberately separated. A legitimate directed data/control flow can exist even when its controls are satisfied. P7-A therefore enumerates topology paths first and marks a path `exposed` only when at least one mapped control is `exceptioned` or `not_evaluated`, or when a policy-explicit unguarded cross-zone flow is present.

A satisfied control is retained on the path as mitigating counterevidence; it does not erase the topology. This avoids the unrealistic claim that a security control makes a legitimate service-to-service edge physically unreachable.

## Deterministic fixture

The fixture has three source-to-sensitive-target topology paths:

- external user → API → agent → tool gateway → secret store;
- external user → API → agent → model runtime; and
- modeled compromised model registry → model runtime.

The default posture marks `CTRL-TOOL-AUTH` as exceptioned while other mapped controls are satisfied. The secret-store path is therefore exposed, while the two model-runtime paths remain controlled. Alternate benign fixtures show both an all-satisfied posture and a not-evaluated tool-authorization posture without treating valid analysis results as input failures.

## Modeled attacks

The evaluation covers:

- architecture digest, schema, freshness, and future-time substitution;
- asset deletion, duplication, owner substitution, invalid types, trust-zone drift, and target-sensitivity downgrade;
- flow deletion, duplication, owner substitution, unknown references, self-loops, endpoint substitution, invalid types, duplicated controls, control substitution, and unguarded cross-zone flow creation;
- architecture controls missing from P6-D posture evidence;
- degraded P6-D verification flags, network-operation claims, posture-digest substitution, control-catalog substitution, duplicate assessments, invalid evidence digests, aggregate status inconsistency, count inconsistency, missing assessments, and invalid status types;
- attacker-profile, entry-scope, target-scope, architecture identity/version, posture request digest, and evaluation-time substitution;
- caller omission/addition/duplication of exposed paths and forged maximum risk;
- path-hop and path-count truncation; and
- malformed policy invariants for entry/target separation, trust-zone pins, endpoint pins, control pins, and allowed trust zones.

## Counterevidence and severity

Every path records satisfied controls as `mitigating_control_ids`, making counterevidence explicit rather than silently discarding it. Exposure reasons separately identify exceptioned controls, not-evaluated controls, and explicitly unguarded flows. The synthetic risk score is deterministic and prioritization-oriented; it is not CVSS, exploit probability, or a calibrated production loss model.

## Explicit non-claims

P7-A does **not** claim:

- production cloud/Kubernetes/SaaS asset discovery;
- live network reachability testing;
- exploit execution or proof of exploitability;
- formal graph reachability proof;
- complete attack-path enumeration for an unbounded real architecture;
- automatic identity/IAM entitlement discovery;
- secret scanning or real credential access;
- external red-team evidence;
- complete MITRE ATT&CK or ATLAS coverage;
- calibrated likelihood or loss estimates;
- production CMDB/GRC integration; or
- compliance certification.

## Residual risk

The model is only as complete as the policy-pinned architecture manifest and P6-D control evidence. A trusted architecture-policy administrator can approve an incomplete graph or incorrect trust-zone/control assumptions. A satisfied control can also be ineffective in reality even though the posture evidence says it is satisfied. P7-A makes those assumptions explicit and integrity-bound; it does not independently prove their real-world truth.
