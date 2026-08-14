# Phase 7 progress — AI security architecture and attack-path analysis

Phase 7 broadens AegisDesk from continuous assurance operations into explicit security architecture analysis: assets, trust zones, directed data/control flows, attacker preconditions, sensitive targets, evidence-backed controls, counterevidence, prioritized cross-boundary paths, and identity/capability escalation chains.

## P7-A — trust-boundary graph and attack-path assurance

Status: **implemented and deterministically evaluated**.

P7-A adds `TrustBoundaryAttackPathAnalyzer`, a deterministic graph-analysis boundary that accepts a canonical architecture manifest plus P6-D control-posture evidence and derives attack-path facts rather than trusting caller-supplied path/risk summaries.

The hardened analyzer requires exact architecture SHA-256 binding, freshness, unique typed assets/flows, trusted ownership, policy-pinned trust zones/endpoints/control mappings, required graph coverage, intact P6-D posture evidence, bounded fail-closed simple-path enumeration, explicit trust-boundary crossings, mitigating counterevidence, and rejection of caller-declared path/risk summaries that disagree with derived evidence.

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

An isolated local harness compiled and exercised an API-compatible P7-A implementation/evaluation/test mirror, passed **57 P7-A security-test outcomes**, and completed the deterministic evaluation with the metrics above. The harness used an API-compatible P6-D `VerifiedSecurityPosture` interface. This is not a claim that full-repository pytest ran locally or that the GitHub-hosted P7-A files were executed byte-for-byte by the harness.

P7-A does **not** claim production asset discovery, live network reachability, exploit execution, production exploitability, formal graph reachability proof, automatic IAM discovery, secret access, external red-team evidence, complete MITRE ATT&CK/ATLAS coverage, calibrated loss/likelihood estimates, production CMDB/GRC integration, or compliance certification.

## P7-B — identity, privilege, and capability escalation paths

Status: **implemented and deterministically evaluated**.

P7-B adds `IdentityPrivilegeCapabilityAnalyzer`, a deterministic identity/capability overlay on the P7-A architecture graph. It models principals, privilege tiers/scopes, native and delegated capabilities, exact architecture routes, and P6-D control evidence, then derives sensitive capability-acquisition paths rather than trusting caller-supplied privilege summaries.

The hardened analyzer requires:

- exact policy/request binding to identity graph ID, version, SHA-256, and the P7-A architecture SHA-256;
- identity evidence freshness and bounded future skew;
- intact P7-A attack-path evidence and exact P7-A assessment SHA-256 binding;
- intact P6-D posture evidence and exact posture/control-catalog SHA-256 binding;
- required unique principals, capabilities, and delegation transitions;
- trusted owners and exact home-asset/type/tier/scope/native-capability pins for principals;
- exact capability target assets plus sensitivity and minimum-tier floors;
- exact transition source/target, P7-A route, control, and capability-grant pins;
- validation that transition routes are contiguous across the P7-A architecture from source-principal home asset to target-principal home asset;
- validation that every transition control exists in P6-D and is mapped to the exact P7-A route used by the delegation;
- policy-owned entry principals and sensitive target capabilities;
- bounded deterministic simple identity-path enumeration with fail-closed truncation;
- first-acquisition tracking so target capabilities are not repeatedly double-counted downstream;
- derived privilege-tier and privilege-scope amplification;
- satisfied controls retained as mitigating counterevidence;
- exceptioned/not-evaluated controls surfaced as explicit privilege-path exposure reasons; and
- rejection when caller-declared exposed privilege paths or maximum risk disagree with the derived result.

### Deterministic fixture

Policy-owned entry principals:

- `external-user-principal`;
- `registry-publisher-principal`.

Policy-owned target capabilities:

- `cap-read-synthetic-secret`;
- `cap-load-model-release`.

The fixture derives two sensitive capability paths:

1. external user → tenant identity → agent service → privileged tool identity → security-scoped secret broker;
2. registry publisher → model runtime.

With only `CTRL-TOOL-AUTH` exceptioned:

- target-capability topology paths: **2**;
- exposed paths: **1**;
- controlled paths: **1**;
- critical exposed paths: **1**;
- maximum exposed-path synthetic risk score: **139**.

With all controls satisfied, both paths remain present but controlled and the maximum exposed risk is **0**. With tool authorization `not_evaluated`, one path remains exposed with maximum synthetic risk **134**.

### Deterministic security evidence

- adversarial identity/privilege cases: **54**;
- vulnerable ASR: **54/54**;
- hardened ASR: **0/54**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- architecture SHA-256: `c5f522823a0311dee21f8aa7ca7afbdca9122e727dc56e2be48003a2be33cc76`;
- identity graph SHA-256: `03ef6adc4aea864e179627592b3175271b603dee665abd1d35282806d0de43bb`;
- P7-A assessment evidence SHA-256: `e46baad54ba104b577e0bcaca3ec7819136868d18de2f63dd140335ca7cccfca`;
- P6-D posture evidence SHA-256: `d699538faf2195514488979788f6cbddf4a0953e55d16534c59723701c16d5a6`;
- control-catalog SHA-256: `9557ca29c037371311ed07180243019bdea041851531229eb5ebff6d5cd83f6e`;
- dataset SHA-256: `1e220679dd5159c03c6c71d926607397531f08650b3d63ef775b6463cf91d508`;
- fixture SHA-256: `0829545e5091403297e30fd4c9ea50e4a2eb22ba09cfcf053e0b061e6c024f81`.

An isolated local harness compiled and exercised the standalone P7-B implementation/evaluation/test logic, passed **62 P7-B security-test outcomes**, and completed the deterministic evaluation with the metrics above. The harness used API-compatible P7-A `VerifiedAttackPathAssessment` and P6-D `VerifiedSecurityPosture` interfaces; this is not a claim that full-repository pytest ran locally or that the GitHub-hosted P7-B files executed byte-for-byte.

### Adversarial coverage

The 54-case evaluation covers identity graph digest/schema/time/architecture substitution; principal deletion/duplication/owner/asset/type/tier/scope/native-capability/enum attacks; capability deletion/duplication/owner/target/sensitivity/tier/enum attacks; transition deletion/duplication/owner/endpoint/self-loop/route/control/grant/enum attacks; unknown flows/controls; degraded or substituted P7-A/P6-D evidence; control-assessment inconsistency; entry/target/request substitution; caller path/risk forgery; path-bound truncation; and incomplete policy pins.

### Claim boundary

P7-B is deterministic synthetic identity/capability evidence. It does **not** claim production IAM/RBAC/ABAC discovery, real credential testing or impersonation, real secret retrieval, production exploitability, formal authorization proof, automatic remediation, external red-team evidence, complete privilege-escalation coverage, production identity-governance integration, or compliance certification.

## Next direction

P7-C should add **data-flow, tenant-isolation, and exfiltration-path analysis**: model data classifications and tenant ownership across retrieval, tools, model inputs/outputs, telemetry, and egress sinks; bind flows to existing isolation/privacy/DLP-like controls; and surface cross-tenant or high-sensitivity egress paths without claiming production data discovery or live exfiltration testing.
