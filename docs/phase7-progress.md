# Phase 7 progress — AI security architecture and attack-path analysis

Phase 7 broadens AegisDesk from continuous assurance operations into explicit security architecture analysis: assets, trust zones, directed data/control flows, attacker preconditions, sensitive targets, evidence-backed controls, counterevidence, and prioritized cross-boundary paths.

## P7-A — trust-boundary graph and attack-path assurance

Status: **implemented and deterministically evaluated**.

P7-A adds `TrustBoundaryAttackPathAnalyzer`, a deterministic graph-analysis boundary that accepts a canonical architecture manifest plus P6-D control-posture evidence and derives attack-path facts rather than trusting caller-supplied path/risk summaries.

The hardened analyzer requires:

- exact SHA-256 binding to a policy-pinned architecture ID/version;
- freshness and bounded future skew for the architecture snapshot;
- unique typed assets and flows;
- trusted asset/flow owners and allowlisted trust zones;
- policy-required assets and flows so callers cannot hide a route by deleting graph elements;
- policy-pinned trust-zone assignments for required assets;
- minimum sensitivity floors for critical targets;
- valid directed references, no self-loops, and exact policy-pinned endpoints/control mappings for required flows;
- explicit treatment of cross-zone flows with no control mapping;
- intact P6-D `VerifiedSecurityPosture` verification flags;
- exact P6-D posture-evidence and control-catalog SHA-256 binding;
- unique per-control evidence with consistent `satisfied`, `exceptioned`, and `not_evaluated` aggregate lists;
- rejection of architecture control IDs missing from P6-D posture evidence;
- a policy-owned attacker profile, entry assets, and sensitive targets;
- deterministic simple-path enumeration with path-count and hop bounds that fail closed if they truncate the topology;
- per-path trust-zone sequences, derived boundary-crossing counts, control gaps, and satisfied-control counterevidence;
- deterministic exposure/risk derivation; and
- rejection when a caller omits/adds exposed paths or forges the maximum exposed-path risk score.

### Exposure semantics

Topology existence is separate from control status. P7-A does not pretend that a satisfied security control removes a legitimate service-to-service edge. It enumerates topology first, then marks a path exposed when at least one mapped control is exceptioned/not evaluated or an explicitly policy-allowed unguarded cross-zone segment is present. Satisfied controls remain visible as mitigating counterevidence on the same path.

### Deterministic fixture

The synthetic graph contains 10 assets and 9 directed flows spanning user ingress, agent orchestration, retrieval/data, privileged tools/secrets, model supply chain/runtime, and serving-abuse telemetry.

Policy-owned attacker entries:

- `external-user`;
- `model-registry` (modeled compromised-registry foothold).

Policy-owned sensitive targets:

- `secret-store`;
- `model-runtime`.

The topology yields three source-to-sensitive-target paths. The default P6-D posture marks only `CTRL-TOOL-AUTH` as exceptioned. Therefore:

- total topology paths: **3**;
- exposed paths: **1**;
- controlled paths: **2**;
- critical exposed paths: **1**;
- maximum exposed-path synthetic risk score: **106**.

Two additional benign posture variants verify that an all-satisfied control state yields zero exposed paths and that a not-evaluated tool-authorization control remains visibly exposed without causing the analysis input itself to fail.

### Deterministic security evidence

- adversarial architecture/posture cases: **50**;
- vulnerable ASR: **50/50**;
- hardened ASR: **0/50**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- architecture manifest SHA-256: `ffa183081b4e5d3e6dd1d70677c03a26fbb5120d41fb32d2729ec194496171ab`;
- P6-D posture-evidence SHA-256: `dda6e6aae0638690bfb1bb1adea081a953749244bb23e498af383df5b8a6fcca`;
- control-catalog SHA-256: `201a9551ed2ba92c5e3376fce70170cec9bbc0e8b6edc48498b887f93db78c78`;
- dataset SHA-256: `ec66acf9cabc3bbdaf54534156119c9f82199630b577754aa3e5129a6e71ecfc`;
- fixture SHA-256: `f83a4cd6880364074961667c09a89989c97a848d133eea1279b0ebbe8ddb0e1c`.

An isolated local harness compiled and exercised an API-compatible P7-A implementation/evaluation/test mirror, passed **57 P7-A security-test outcomes**, and completed the deterministic evaluation with the metrics and hashes above. The harness used an API-compatible P6-D `VerifiedSecurityPosture` interface. This is not a claim that full-repository pytest ran locally or that the GitHub-hosted P7-A files were executed byte-for-byte by the harness.

### Adversarial coverage

The 50-case evaluation covers architecture digest/schema/time substitution; asset deletion/duplication/owner/type/trust-zone/sensitivity attacks; flow deletion/duplication/owner/reference/self-loop/endpoint/type/control attacks; unguarded cross-boundary creation; unknown posture controls; degraded P6-D verification and status evidence; posture and control-catalog substitution; attacker-entry/target/profile substitution; caller path/risk summary forgery; bounded-enumeration truncation; and malformed policy invariants.

### Claim boundary

P7-A is deterministic synthetic architecture evidence. It does **not** claim production cloud/Kubernetes/SaaS asset discovery, live network reachability, exploit execution, production exploitability, formal graph reachability proof, automatic IAM entitlement discovery, secret access, external red-team evidence, complete MITRE ATT&CK/ATLAS coverage, calibrated loss/likelihood estimates, production CMDB/GRC integration, or compliance certification.

## Next direction

P7-B should add **identity, privilege, and capability escalation paths**: model principals, delegated identities, tool/model/runtime capabilities, credential transitions, and privilege amplification across the architecture graph, while binding escalation paths to existing authorization/provenance controls and keeping the analysis deterministic and synthetic.
