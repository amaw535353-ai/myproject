# Phase 7 progress — AI security architecture and attack-path analysis

Phase 7 broadens AegisDesk from continuous assurance into explicit security-architecture analysis. The current sequence covers trust-boundary attack paths, identity/capability escalation, tenant-aware data exfiltration, secrets/credential/trust-root blast radius, third-party dependency/service-egress trust, and security-preserving graceful degradation. Every milestone remains deterministic and synthetic and binds analysis to prior assurance evidence rather than trusting caller summaries.

## P7-A — trust-boundary graph and attack-path assurance

Status: **implemented and deterministically evaluated**.

`TrustBoundaryAttackPathAnalyzer` pins a canonical architecture graph, trust zones, sensitive targets, P6-D control posture, bounded path enumeration, per-path control gaps, and mitigating counterevidence.

Evidence: vulnerable ASR **50/50**, hardened ASR **0/50**, hardened FPR **0/3**, SafeTaskRate **3/3**.

## P7-B — identity, privilege, and capability escalation paths

Status: **implemented and deterministically evaluated**.

`IdentityPrivilegeCapabilityAnalyzer` overlays policy-pinned principals, privilege tiers/scopes, delegated capabilities, exact P7-A routes, and P6-D controls. It derives privilege/scope amplification and sensitive capability-acquisition paths while retaining satisfied controls as counterevidence.

Evidence: vulnerable ASR **54/54**, hardened ASR **0/54**, hardened FPR **0/3**, SafeTaskRate **3/3**.

## P7-C — data flow, tenant isolation, and exfiltration paths

Status: **implemented and deterministically evaluated in an isolated API-compatible harness**.

`TenantIsolationExfiltrationAnalyzer` models classified data objects, authoritative tenant ownership, exact P7-A routes, data transforms, approved sinks, classification ceilings, external egress, P7-B identity evidence, and P6-D control posture.

Evidence: vulnerable ASR **61/61**, hardened ASR **0/61**, hardened FPR **0/3**, SafeTaskRate **3/3**.

P7-C does not claim production data discovery/classification, semantic PII detection, real DLP enforcement, live egress interception, formal information-flow proof, or privacy/compliance certification.

## P7-D — secrets, credential, and trust-root exposure analysis

Status: **implemented with deterministic fixture/evaluation/test coverage; hosted runner execution pending infrastructure**.

`SecretsCredentialTrustRootExposureAnalyzer` models secret material and transfer surfaces across application configuration, synthetic build/release boundaries, tool credentials, model signing/runtime injection, telemetry credentials, key-vault boundaries, and external egress. The repository encodes 67 adversarial cases plus benign scenarios; hosted execution remains blocked by runner-provisioning infrastructure.

P7-D does not claim production secret discovery/scanning, real vault/HSM/KMS integration, real credential use, automatic rotation/revocation, hardware-backed key isolation, live exfiltration testing, formal blast-radius proof, or compliance certification.

## P7-E — external dependency, service-egress, and third-party trust paths

Status: **implemented and deterministically exercised in an isolated API-compatible harness; hosted runner execution pending infrastructure**.

P7-E adds `ExternalDependencyTrustAnalyzer`, which models hosted-model, privileged-tool, identity-provider, telemetry, and registry dependencies as explicit trust objects instead of accepting a caller-owned “all destinations trusted” summary.

The hardened analyzer requires exact dependency/P7-A/P7-B/P7-C/P7-D/P6-D evidence binding, trusted providers/owners, policy-pinned dependency identity/criticality, exact endpoints and transport/authentication/server identity, bounded data/secret exposure, exact controls, fail-closed expectations, contiguous egress routing, and deterministic caller-summary verification.

An isolated API-compatible harness passed **53 P7-E security-test outcomes** with vulnerable ASR **49/49**, hardened ASR **0/49**, hardened FPR **0/3**, and SafeTaskRate **3/3**. This is not a claim that full-repository pytest ran locally or that GitHub-hosted P7-E files executed byte-for-byte in that harness.

P7-E does not claim production dependency discovery, live DNS/TLS/SPIFFE/OAuth/mTLS validation, production egress enforcement, real third-party requests, vendor penetration testing, complete supply-chain provenance, formal reachability proof, or compliance certification.

## P7-F — dependency failure and graceful-degradation security

Status: **implemented and deterministically exercised in an isolated API-compatible harness; hosted runner execution pending infrastructure**.

P7-F adds `DependencyFailureSecurityAnalyzer`, which separates service continuity from security preservation. It evaluates degraded, unavailable, and untrusted P7-E dependencies against exact policy-pinned fallback plans instead of accepting a caller-owned “availability restored safely” declaration.

The hardened boundary requires:

- exact resilience-plan ID/version/SHA-256, freshness, and dependency-graph binding;
- exact P7-E assessment and P6-D posture/control-catalog evidence;
- fully verified P7-E destination identity, transport/authentication, egress-scope, fail-closed, and risk derivation properties;
- exact failure-scenario/fallback coverage and trusted owners;
- policy-pinned dependency and failure state per scenario;
- exact required controls and complete preserved/disabled-control accounting;
- exact fallback mode/target/data/secret/retry/cache semantics;
- fail-closed strategies that perform no external operation;
- bounded retry of the primary only;
- independently represented alternate dependencies;
- local safe mode with no external target or secret consumption;
- concrete cache timestamps and deterministic freshness evaluation;
- explicit exposure for disabled, exceptioned, or not-evaluated controls on continuing fallbacks;
- explicit exposure for retrying an untrusted primary, exposed/weaker alternate providers, or stale cache material; and
- rejection of forged caller exposed-scenario or maximum-risk summaries.

### Deterministic fixture

Seven modeled scenarios cover model-provider unavailable/untrusted/degraded states, privileged-tool outage, identity-provider outage, telemetry degradation, and registry outage. They exercise local safe mode, alternate provider, bounded retry, fail closed, and cache fallback.

With modeled controls satisfied:

- scenarios: **7**;
- security-preserved scenarios: **7**;
- exposed scenarios: **0**;
- service-continuity scenarios: **5**;
- deliberate fail-closed scenarios: **2**;
- maximum security risk: **0**.

Additional valid evidence states demonstrate:

- `CTRL-CACHE-INTEGRITY` exceptioned → telemetry and registry cache scenarios exposed, maximum risk **68**;
- `CTRL-FALLBACK-AUTHZ` not evaluated → all three model-continuity scenarios exposed, maximum risk **73**;
- stale telemetry cache → one exposed scenario, risk **56**; and
- fail-closed tool/identity paths remain security-preserving even when `CTRL-FAIL-CLOSED` is exceptioned, because no operation proceeds; the exception remains visible in per-scenario evidence.

### Deterministic security evidence

An isolated local API-compatible harness compiled and exercised a mirror of the P7-F implementation/evaluator/test contract, passed **70 P7-F security-test outcomes**, and completed the deterministic evaluation:

- adversarial cases: **64**;
- vulnerable ASR: **64/64**;
- hardened ASR: **0/64**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- resilience-plan SHA-256: `ac05d8714cc2b13c8bcfa29675884f5831e2de35e244c9756e23f8165547abe1`;
- dataset SHA-256: `769ea9a325c703ed6a200bd543240f5d333877657a3f8cb85d122d228c5e7b15`;
- fixture SHA-256: `953b61ba33e010b27c837305ea5d29c27216192d054578f6c867063b8a8c9df7`.

The harness used API-compatible P7-E/P6-D interfaces. This is **not** a claim that full-repository pytest ran locally or that the GitHub-hosted P7-F files executed byte-for-byte in that harness.

The 64-case adversarial set covers request/manifest substitution, time drift, scenario/fallback deletion and duplication, owner/dependency/state/control drift, mode/target/data/secret changes, retry/cache abuse, invalid fallback shapes, malformed policy maps/bounds, P7-E/P6-D evidence substitution, explicit control disabling, retry of an untrusted primary, stale cache, exposed/weaker alternate dependencies, and forged caller green summaries.

The intentionally weak `VulnerableAvailabilityRestorationReporter` equates restored availability with preserved security and trusts caller-owned aggregate degradation/risk declarations.

### Claim boundary

P7-F does **not** claim production dependency-health monitoring, real failover orchestration, live chaos/outage testing, actual retry/queue/cache/network behavior, SLA/SLO/RTO/RPO achievement, disaster-recovery certification, production alternate-provider validation, formal liveness/safety proof, or compliance certification. `service_continuity_expected=True` is a modeled plan property, not operational uptime evidence.

## Next direction

P7-G should add **security telemetry integrity, auditability, and detection blind-spot analysis** across model/tool/data/identity/dependency paths: map required security events to trusted collection paths, detect missing/tamperable telemetry and failover-induced observability gaps, bind alerting evidence to existing architecture controls, and prevent a caller-declared “fully monitored” state from masking detection blind spots.
