# Phase 7 progress — AI security architecture and attack-path analysis

Phase 7 broadens AegisDesk from continuous assurance operations into explicit security architecture analysis: trust-boundary topology, identity/capability escalation, and data-flow/tenant-isolation/exfiltration paths. Every milestone remains deterministic and synthetic and binds analysis to prior assurance evidence instead of trusting caller summaries.

## P7-A — trust-boundary graph and attack-path assurance

Status: **implemented and deterministically evaluated**.

P7-A adds `TrustBoundaryAttackPathAnalyzer`, which pins a canonical architecture graph, trust zones, sensitive targets, P6-D control posture, bounded path enumeration, per-path control gaps, and mitigating counterevidence.

Deterministic evidence:

- adversarial cases: **50**;
- vulnerable ASR: **50/50**;
- hardened ASR: **0/50**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**.

P7-A is synthetic architecture evidence, not production asset discovery, live reachability/exploit testing, formal graph proof, or compliance certification.

## P7-B — identity, privilege, and capability escalation paths

Status: **implemented and deterministically evaluated**.

P7-B adds `IdentityPrivilegeCapabilityAnalyzer`, overlaying policy-pinned principals, privilege tiers/scopes, delegated capabilities, exact P7-A routes, and P6-D controls. It derives privilege/scope amplification and sensitive capability-acquisition paths while retaining satisfied controls as counterevidence.

Deterministic evidence:

- adversarial cases: **54**;
- vulnerable ASR: **54/54**;
- hardened ASR: **0/54**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**.

P7-B is synthetic identity/capability evidence, not production IAM discovery, real credential testing, impersonation, formal authorization proof, or compliance certification.

## P7-C — data flow, tenant isolation, and exfiltration paths

Status: **implemented and deterministically evaluated in an isolated API-compatible harness**.

P7-C adds `TenantIsolationExfiltrationAnalyzer`. It models classified data objects and tenant ownership across retrieval, model context, privileged tool results, external response egress, and security telemetry. The analyzer binds the exact P7-A architecture, P7-A attack-path evidence, P7-B privilege evidence, and P6-D control posture before deriving data paths.

The hardened boundary requires:

- exact data-graph ID/version/SHA-256 and exact P7-A architecture binding;
- manifest freshness and bounded future skew;
- exact required data-object and edge coverage so routes cannot be hidden or injected silently;
- trusted data/edge owners;
- policy-pinned tenant ownership, data kind, origin asset, and minimum classification floors;
- exact edge data binding, source/target assets, P7-A flow IDs, control IDs, and allowlisted transforms;
- contiguous architecture routing for every data edge;
- exact P7-A, P7-B, P6-D posture, and control-catalog evidence binding;
- consistent P6-D per-control evidence and aggregate status lists;
- policy-owned entry data and sink scope;
- allowed destination-tenant and sink policy per data object;
- sink classification ceilings and final-transform policy;
- external-egress identification;
- bounded deterministic simple-path enumeration with fail-closed truncation;
- explicit cross-tenant, sink, classification, transform, exceptioned-control, and not-evaluated-control exposure reasons;
- satisfied controls retained as mitigating counterevidence; and
- rejection when caller-declared exposed paths or maximum risk disagree with derived evidence.

### Deterministic fixture

The fixture contains three synthetic data objects and eight data-flow edges. It derives four paths:

1. tenant ticket → model runtime;
2. tenant ticket → external user;
3. synthetic platform secret → external user;
4. runtime telemetry → security telemetry.

With `CTRL-TENANT-ISOLATION` exceptioned and the remaining fixture controls satisfied:

- topology paths: **4**;
- exposed paths: **3**;
- controlled paths: **1**;
- cross-tenant exposed paths: **2**;
- external-egress exposed paths: **2**;
- restricted/secret exposed paths: **1**;
- maximum exposed-path synthetic risk score: **157**.

With tenant isolation satisfied, the two policy-violating external paths remain exposed while the tenant-ticket model path becomes controlled. With tenant isolation `not_evaluated`, the affected ticket paths remain visibly exposed.

### Deterministic security evidence

- adversarial data-flow/evidence cases: **61**;
- vulnerable ASR: **61/61**;
- hardened ASR: **0/61**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- architecture SHA-256: `787beed984d6765faee0dc10e29de3b8e9df9ca895c9861406977ef87e664898`;
- data-flow graph SHA-256: `15fdff97e0db42cb47fc7bca46e449976f56e126d6e5ff4ef11b76b7bb4b51b2`;
- P7-A assessment evidence SHA-256: `dc4ff396d00bd80aad09e63a66a59ccbfa53f698901e04dccdf01d2736ba5c4a`;
- P7-B assessment evidence SHA-256: `f5f2aef707c185caa1f9c1c4048e2021a0f5c571e3b16bf8d0da4d7a2b633392`;
- P6-D posture evidence SHA-256: `c9004770d9ef9e75cf25118ec382dc5ddf89f8c41a6a5420bee1d5d4f8964af9`;
- control-catalog SHA-256: `26f7a85e19fe5911d97d3ca880ab087df7d9c52a029a26c97af74e8c50a3ff2a`;
- dataset SHA-256: `a9522bfa2d48ec6a60e010aa5d73df6ea8de4dff291d001382015b9562182c78`;
- fixture SHA-256: `af445184bc0e6057e6f82844176b117bec77a3bdae09833ade1a6abd6ecb8ed6`.

An isolated local harness exercised an API-compatible mirror of the P7-C implementation/evaluation/test logic, passed **33 P7-C security-test outcomes**, and completed the deterministic evaluation with the metrics above. The harness used API-compatible P7-A `VerifiedAttackPathAssessment`, P7-B `VerifiedPrivilegeEscalationAssessment`, and P6-D `VerifiedSecurityPosture` interfaces. This is not a claim that full-repository pytest ran locally or that GitHub-hosted P7-C files executed byte-for-byte in the harness.

### Adversarial coverage

The 61-case evaluation covers request identity/evidence/scope substitution; manifest digest/schema/version/architecture/time substitution; data deletion/duplication/addition/owner/origin/tenant/kind/classification attacks; edge deletion/duplication/addition/owner/reference/self-loop/data/endpoint/flow/control/transform attacks; non-contiguous routes and unknown controls; degraded/substituted P7-A, P7-B, and P6-D evidence; control-catalog and aggregate-status inconsistency; malformed policy pins; path-count/hop truncation; tenant-destination substitution; and forged caller green summaries.

### Claim boundary

P7-C is deterministic synthetic information-flow evidence. It does **not** claim production data discovery/classification, semantic PII/secret detection, real DLP enforcement, packet capture, live egress interception, real tenant data or credential access, production model prompt/output inspection, live exfiltration testing, formal non-interference/information-flow proof, complete lineage, production SIEM/DLP/CASB integration, or privacy/compliance certification.

## Next direction

P7-D should add **secrets, credential, and trust-root exposure analysis** across application configuration, model/tool credentials, signing keys, telemetry, build/release artifacts, and runtime injection boundaries, with exact ownership/rotation/provenance evidence and explicit blast-radius paths.
