# Phase 7 progress — AI security architecture and attack-path analysis

Phase 7 broadens AegisDesk from continuous assurance into explicit security-architecture analysis. The current sequence covers trust-boundary attack paths, identity/capability escalation, tenant-aware data exfiltration, secrets/credential/trust-root blast radius, and third-party dependency/service-egress trust. Every milestone remains deterministic and synthetic and binds analysis to prior assurance evidence rather than trusting caller summaries.

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

Status: **implemented with deterministic fixture/evaluation/test coverage; execution evidence pending runnable CI/local repository environment**.

P7-E adds `ExternalDependencyTrustAnalyzer`, which models hosted-model, privileged-tool, identity-provider, telemetry, and registry dependencies as explicit trust objects instead of accepting a caller-owned “all destinations trusted” summary.

The hardened analyzer requires:

- exact dependency-graph ID/version/SHA-256, freshness, and P7-A architecture binding;
- exact P7-A, P7-B, P7-C, P7-D, and P6-D evidence digests;
- exact required dependency and service-egress-route coverage;
- trusted internal owners and trusted external provider IDs;
- policy-pinned dependency type and minimum criticality;
- exact endpoint host/port, transport, authentication, and expected server identity;
- bounded data-class and secret exposure scope per dependency;
- exact dependency/route control sets with P6-D control-state derivation;
- policy-pinned fail-closed behavior;
- exact route source/dependency/P7-A flow/control bindings and contiguous routing;
- policy-owned entry-source and target-dependency scope; and
- rejection of forged caller exposed-path or maximum-risk summaries.

### Deterministic fixture

The fixture models five dependencies and five egress routes. With all modeled controls satisfied, all five paths are controlled. With `CTRL-TOOL-EGRESS` exceptioned, one critical secret-bearing/restricted-data path is exposed at synthetic risk score **134**. With `CTRL-TELEMETRY-EGRESS` not evaluated, one telemetry path is exposed at score **60**.

### Evaluation coverage

The repository evaluator encodes **49 adversarial cases** plus three benign scenarios. It targets graph/request identity substitution, missing/duplicate dependencies or routes, provider/owner substitution, endpoint/port drift, transport/authentication downgrade, destination-identity substitution, criticality downgrade, unauthorized data/secret scope, control removal, fail-open drift, route/flow manipulation, non-contiguous routing, upstream evidence downgrade/substitution, control-catalog drift, and forged green summaries.

The matched `VulnerableDependencyTrustReporter` accepts caller declarations that the graph is complete, all destinations are trusted, and aggregate exposure/risk are zero.

Until a runnable environment executes the repository source, the evaluator expectations are **targets encoded by the test/eval logic, not a claim of green CI or completed full-repository pytest**.

### Claim boundary

P7-E does **not** claim production dependency discovery, live DNS/TLS/SPIFFE/OAuth/mTLS validation, production egress enforcement, real third-party requests, vendor penetration testing, real secret transmission, complete supply-chain provenance, formal reachability proof, or compliance certification.

## Next direction

P7-F should add **availability, dependency-failure, and graceful-degradation security analysis**: model how model/tool/identity/telemetry/registry dependency outages or degraded trust states affect authorization, safety controls, fail-open behavior, retry/fallback paths, and release security posture so resilience mechanisms cannot silently bypass security boundaries.
