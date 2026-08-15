# Phase 7 progress — AI security architecture and attack-path analysis

Phase 7 broadens AegisDesk from continuous assurance into explicit security-architecture analysis. The current sequence covers trust-boundary attack paths, identity/capability escalation, tenant-aware data exfiltration, and secrets/credential/trust-root blast radius. Every milestone remains deterministic and synthetic and binds analysis to prior assurance evidence rather than trusting caller summaries.

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

P7-D adds `SecretsCredentialTrustRootExposureAnalyzer`, which models secret material and transfer surfaces across application configuration, synthetic build/release boundaries, tool credentials, model signing/runtime injection, telemetry credentials, key-vault boundaries, and external egress.

The hardened analyzer requires:

- exact secret-graph ID/version/SHA-256 and exact P7-A architecture SHA-256;
- exact P7-A, P7-B, P7-C, and P6-D evidence digests;
- exact required exposure-surface, secret, and transfer-edge coverage;
- trusted surface/secret/edge owners;
- policy-pinned surface type, scope, trust zone, and optional P7-A asset mapping;
- policy-pinned secret owner, kind, authority scope, home surface, sensitivity floor, and trust-root classification;
- structurally valid rotation/expiry metadata plus per-secret maximum rotation age;
- explicit allowed target surfaces and exposure scopes per secret;
- plaintext and persistence policy per secret;
- exact transfer secret/endpoints/channel/P7-A route/control pins;
- contiguous P7-A routing for mapped transfer edges and route-backed controls;
- exact P6-D control evidence with exceptioned/not-evaluated states preserved;
- bounded fail-closed simple-path enumeration;
- derived unauthorized-surface, scope, plaintext, persistence, rotation, expiry, external-egress, and trust-root exposure reasons; and
- rejection when caller-declared exposed paths or maximum blast radius differ from derived evidence.

### Deterministic fixture

The fixture models six synthetic secrets:

1. privileged-tool API token;
2. build token;
3. model publisher signing key;
4. runtime admission credential;
5. telemetry export credential; and
6. root signing key.

It derives six paths. With all controls satisfied, all six are controlled. With `CTRL-BUILD-SECRET` exceptioned, one build-token path is exposed at synthetic blast-radius score **95**. With `CTRL-TELEMETRY-REDACTION` not evaluated, one telemetry path is exposed at score **94**.

### Deterministic security evidence

- adversarial secret/evidence cases: **67**;
- vulnerable ASR target: **67/67**;
- hardened ASR target: **0/67**;
- hardened FPR target: **0/3**;
- SafeTaskRate target: **3/3**;
- architecture SHA-256: `0b95fb12dac8a89843e925d7fcbd1a87414cf2990247cd9d9ddeadb9b431e40a`;
- secret graph SHA-256: `a11de4cc9c62573cdba94e5d45d11bba83a2d919079481773cae8b2ea937ccc2`;
- dataset SHA-256: `47abd62da9fa453932568c45b207a2a37ee3fca5dae35d8ab0da2b9788001ef5`;
- fixture SHA-256: `83fb6757955a0dd14c5765b7b17b3dddb526d0a9e0c1cc6a25b19e0281ca5854`.

The test suite contains the 67 adversarial cases plus benign all-satisfied, exceptioned-control, missing-evidence, and metric checks. Until a runnable environment executes the repository files, these figures remain deterministic fixture/evaluator targets rather than a claim of hosted green CI.

### Claim boundary

P7-D does **not** claim production secret discovery/scanning, real vault/HSM/KMS integration, real credential use, automatic rotation/revocation, hardware-backed key isolation, production build-secret isolation, live exfiltration testing, formal blast-radius proof, complete secret lineage, or compliance certification.

## Next direction

P7-E should add **external dependency, service-egress, and third-party trust-path analysis**: model outbound API/model/tool dependencies, destination identity, transport/authentication assumptions, data/credential exposure, dependency criticality, and fail-closed egress policy so a release cannot appear architecturally safe while relying on unpinned or weakly governed external services.
