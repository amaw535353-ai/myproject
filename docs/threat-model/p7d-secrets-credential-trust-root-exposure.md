# P7-D — secrets, credential, and trust-root exposure analysis

## Objective

P7-D adds deterministic analysis for secret material that can cross application configuration, build/release, tool, model-registry/runtime, telemetry, and external-egress surfaces. The security property is that a caller cannot declare a secret inventory or blast radius safe while hiding a policy-pinned exposure route, weakening secret identity/ownership/sensitivity, omitting a transfer edge, substituting upstream evidence, or masking exceptioned/not-evaluated controls.

The milestone is an architecture-assurance model. It does not retrieve or test real credentials.

## Assets and trust roots

The synthetic fixture models:

- a scoped privileged-tool API token;
- a build token;
- a model publisher signing key;
- a model-runtime admission credential;
- a telemetry export credential; and
- a root signing key explicitly classified as a trust root.

Exposure surfaces cover application configuration, a synthetic build runner, release artifacts, a key-vault boundary, a tool gateway, model registry, model runtime, telemetry pipeline, and an external egress sink. Surfaces may bind to exact P7-A architecture assets where a corresponding architecture node exists; build/config/artifact surfaces remain explicitly supplemental rather than pretending the P7-A asset taxonomy already models them.

## Evidence boundary

`SecretsCredentialTrustRootExposureAnalyzer` requires:

1. the exact P7-D secret graph ID, version, and SHA-256;
2. the exact P7-A architecture SHA-256;
3. exact P7-A attack-path assessment evidence;
4. exact P7-B identity/privilege assessment evidence;
5. exact P7-C data-exfiltration assessment evidence;
6. exact P6-D posture evidence and control-catalog SHA-256;
7. exact required surface, secret, and transfer-edge coverage; and
8. caller-declared path/blast-radius summaries that exactly match evidence-derived results.

The gate does not treat boolean `safe`, `complete`, or `zero_exposure` caller claims as evidence.

## Secret identity and lifecycle invariants

Each required secret is policy-pinned to:

- an exact owner;
- an exact kind;
- an exact authority scope;
- an exact home surface;
- a minimum sensitivity;
- an exact trust-root classification;
- a maximum rotation age;
- allowed exposure surfaces and exposure scopes;
- plaintext-handling policy; and
- persistence policy.

Rotation and expiry metadata must be structurally valid. Overdue rotation and expiration are not silently normalized away: when the evidence remains structurally valid, they become explicit exposure reasons on the derived path.

## Transfer-edge invariants

Each transfer edge is policy-pinned to:

- exact secret ID;
- exact source and target surfaces;
- transfer channel;
- optional P7-A architecture route;
- required control IDs; and
- trusted ownership.

Mapped P7-A routes must exist and be contiguous. If a transfer edge claims a control for an architecture-backed route, that control must also appear on the bound P7-A flow route. Unknown controls and unknown routes fail closed.

## Exposure derivation

For each policy-owned entry secret, the analyzer enumerates bounded simple transfer paths to policy-owned target surfaces. It derives:

- unauthorized-surface exposure;
- exposure-scope violations;
- forbidden plaintext handling;
- forbidden persistent copies;
- overdue rotation;
- expired credentials;
- exceptioned controls;
- not-evaluated controls;
- trust-root external egress;
- external-egress presence; and
- a deterministic synthetic blast-radius score.

Satisfied controls remain visible as mitigating counterevidence. Exceptioned and missing evidence remain visible; neither is converted into a satisfied control.

## Fail-closed graph behavior

The gate rejects:

- hidden or injected surfaces/secrets/edges;
- duplicate identifiers;
- untrusted owners;
- surface type/scope/trust-zone or architecture mapping drift;
- secret kind/scope/home/trust-root substitution;
- sensitivity downgrade;
- malformed rotation metadata;
- secret/endpoint/channel/route/control drift on transfer edges;
- unknown controls or P7-A flows;
- non-contiguous architecture routes;
- path-count overflow; and
- hop-bound truncation that would hide a reachable frontier.

## Vulnerable baseline

`VulnerableSecretExposureReporter` intentionally trusts three caller values: whether the graph is complete, the declared exposed-path count, and the declared maximum blast-radius score. A caller can therefore claim a complete graph with zero exposure even when the supplied secret topology is unsafe. The deterministic P7-D evaluation uses that behavior as the matched vulnerable baseline.

## Deterministic fixture properties

With all fixture controls satisfied, six secret paths are derived and all six are controlled.

With `CTRL-BUILD-SECRET` exceptioned, exactly one build-token path is exposed with synthetic blast-radius score **95**.

With `CTRL-TELEMETRY-REDACTION` not evaluated, exactly one telemetry-credential path is exposed with synthetic blast-radius score **94**.

The adversarial suite also covers plaintext/persistent key-material handling, overdue/expired credentials, and a repinned root-key route to external egress. Those cases cannot be masked by a caller-declared zero-exposure summary.

## Deterministic evidence

- adversarial cases: **67**;
- target vulnerable ASR: **67/67**;
- target hardened ASR: **0/67**;
- target hardened FPR: **0/3**;
- target SafeTaskRate: **3/3**;
- architecture SHA-256: `0b95fb12dac8a89843e925d7fcbd1a87414cf2990247cd9d9ddeadb9b431e40a`;
- secret graph SHA-256: `a11de4cc9c62573cdba94e5d45d11bba83a2d919079481773cae8b2ea937ccc2`;
- P7-A evidence SHA-256: `bf78ecb8476952ea5a003dffc87aa4bd2fc2e6211d363c719df027ec28805a4e`;
- P7-B evidence SHA-256: `c1885785ba6eafcb0b55c0c545b20b7145604692fd1baee071243a043bca6b4a`;
- P7-C evidence SHA-256: `874232f4b98b2532d9f8127b24a67f1ebfc1b99bda3e8736acbd19841fdf63f1`;
- P6-D posture SHA-256: `67a3940ebf0f8acbae219e09d063c3288b5cd610822d700e8ff834c3d2565461`;
- control-catalog SHA-256: `4b1d310a61f9282599c6375f8ef4b6599be744cbfd43270d7932bf5709857109`;
- dataset SHA-256: `47abd62da9fa453932568c45b207a2a37ee3fca5dae35d8ab0da2b9788001ef5`;
- fixture SHA-256: `83fb6757955a0dd14c5765b7b17b3dddb526d0a9e0c1cc6a25b19e0281ca5854`.

These hashes are deterministic fixture identifiers. Hosted execution evidence must still be reported separately from design-time calculation.

## Claim boundary

P7-D does **not** claim:

- production secret discovery or secret scanning;
- semantic detection of leaked credentials in arbitrary content;
- real vault/HSM/KMS integration;
- real credential validation or use;
- automatic rotation or revocation;
- hardware-backed key isolation;
- production build-system or CI secret isolation;
- packet capture, live egress interception, or exfiltration testing;
- formal blast-radius or non-interference proof;
- complete secret lineage;
- production SIEM/DLP/CSPM/CNAPP integration; or
- compliance/certification evidence.

`trust_root=True` is a policy classification in synthetic evidence, not proof that a key is hardware protected or operationally offline.
