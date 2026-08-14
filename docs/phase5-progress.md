# Phase 5 progress — model and AI supply-chain security

Phase 5 broadens AegisDesk beyond checkpoint and agent-runtime hardening into model artifacts, provenance, dependency trust, registry acquisition, signing-key lifecycle, model runtime/execution boundaries, model-content risk indicators, inference privacy controls, and deployment provenance/attestation.

## P5-A — model artifact provenance and safe loading

Status: **implemented and deterministically evaluated**.

P5-A adds caller-bound artifact/model/revision identity, SHA-256 payload binding, Ed25519 manifests, trusted publishers and source prefixes, data-format allowlisting, and a non-deserializing verified artifact handle.

Evidence: vulnerable ASR 4/4; hardened ASR 0/4; hardened FPR 0/2; SafeTaskRate 2/2.

## P5-B — transitive model-package and adapter provenance

Status: **implemented and deterministically evaluated**.

P5-B extends trust to the exact signed model-package closure and enforces exact component membership, package-pinned publisher/digest/size metadata, role-specific publisher authorization, dependency validation, remote-code rejection, and nested P5-A provenance for every component.

Evidence: vulnerable ASR 9/9; hardened ASR 0/9; hardened FPR 0/3; SafeTaskRate 3/3.

## P5-C — immutable model-registry acquisition and release pinning

Status: **implemented and deterministically evaluated**.

P5-C separates mutable registry discovery aliases from immutable release identity, requires exact deployment release SHA-256 pins, constrains registry sources/redirects, re-hashes fetched and cached releases, binds package identity, and hands accepted content through P5-B.

Evidence: vulnerable ASR 8/8; hardened ASR 0/8; hardened FPR 0/3; SafeTaskRate 3/3.

- dataset SHA-256: `758aff515e6566ca80bffb5e4fae61e2b24c87832da2fcc72e406fd47608af5d`
- fixture SHA-256: `dc553db5d14e11b65c6822b2d31265498a0551b597359e5ca63417d66469b695`

## P5-D — provenance signing-key lifecycle and revocation

Status: **implemented and deterministically evaluated**.

P5-D adds signer key IDs, trusted issuers, exact issuer/publisher/key binding, artifact/package usage separation, signing-time and subject binding, validity windows, active/retired/revoked states, successor rotation metadata, and current-state strict rejection of expired/revoked/retired keys.

Evidence: vulnerable ASR 12/12; hardened ASR 0/12; hardened FPR 0/3; SafeTaskRate 3/3.

- dataset SHA-256: `3cb29e261f27df97b468e2878752d33104dc475d237c7481e8c72e42890772f9`
- fixture SHA-256: `d263c288db5c83789eaa7898f78a819873e0c4fa36f2bc7d638e8526f47b8726`

## P5-E — model parser/runtime isolation and execution-boundary remote-code denial

Status: **implemented and deterministically evaluated**.

P5-E separates provenance validity from execution authority. A verified package must pass exact runtime closure/role checks, role-specific parser allowlists, sandbox-backend policy, remote/dynamic/native/custom-code denial, host-capability denial, required isolation mode, and bounded resource requests.

Evidence: vulnerable ASR 15/15; hardened ASR 0/15; hardened FPR 0/3; SafeTaskRate 3/3.

- dataset SHA-256: `34d4b0e9f7884fcb545217a0d72afc890ec4dd698e5901b5ed4f20cf1d204b44`
- fixture SHA-256: `8b16c23c7f7f864ff1cd24d0b078400dd766e6a26a905ee5a4822397d191c32d`

P5-E is an admission-policy lab, not a production kernel/container/microVM sandbox.

## P5-F — model poisoning and backdoor indicators

Status: **implemented and deterministically evaluated**.

P5-F adds a release-scoped model-content evidence gate after provenance and runtime admission. It requires exact scanner/profile/baseline and subject-digest binding, exact package/probe coverage, bounded synthetic tensor statistics, trigger-like tokenizer/config checks, and deterministic synthetic backdoor-probe thresholds.

Evidence: vulnerable ASR 16/16; hardened ASR 0/16; hardened FPR 0/3; SafeTaskRate 3/3.

- dataset SHA-256: `a69d318ed7a674e272b40bade12a1099aecdffdcce3275e500292715be25b719`
- fixture SHA-256: `117a2473d2df1f5825ba6040aada6b92a363be612520b57b05ebbddc37ada580`

P5-F consumes synthetic statistics/probe outcomes and does not prove a model is backdoor-free or behaviorally safe.

## P5-G — model privacy, extraction, and membership-inference controls

Status: **implemented and deterministically evaluated**.

P5-G treats inference access as a scoped privacy capability even after a model has passed P5-E and P5-F. The hardened `ModelPrivacyGateway` adds intact runtime/scan requirements, exact scan-digest binding, principal/session/query identity, output minimization, sensitive-channel denial, canary and memorization/membership/extraction indicator gates, and deterministic query/repeated-fingerprint budgets.

Evidence:

- vulnerable ASR: 16/16;
- hardened ASR: 0/16;
- hardened FPR: 0/3;
- hardened SafeTaskRate: 3/3;
- dataset SHA-256: `77d70ca43f0098919df126da4b892e1ea530d2adf8fb062362f4acd99c37eca4`;
- fixture SHA-256: `243cefb858ba25324418373d7ec81c2d3c936f1fbdc8c0b7019fceac5a802489`.

P5-G uses deterministic synthetic response evidence. It does **not** claim a differential-privacy guarantee, real resistance to adaptive membership inference/model extraction, production distributed rate limiting, side-channel protection, secure multi-tenant accounting, or real training-corpus memorization measurement.

## P5-H — deployment provenance and attestation

Status: **implemented and deterministically evaluated**.

P5-H binds the approved security chain to a specific deployment environment. The hardened `DeploymentAttestationVerifier` requires:

- an intact P5-C immutable verified release;
- an intact P5-E verified runtime plan bound to the release package;
- an intact clear P5-F scan handle bound to the runtime;
- exact deployment, registry/channel/tag, package/model/revision/runtime identity;
- exact deployment-policy pins for the release SHA-256 and P5-F evidence SHA-256;
- a canonical SHA-256 of the exact P5-G privacy policy;
- exact binding of P5-C/P5-E/P5-F/P5-G policy and mode versions;
- policy-pinned environment image digest and synthetic runtime measurement;
- an allowlisted orchestrator and sandbox backend matching the P5-E runtime;
- least-privilege environment evidence: isolated networking, read-only filesystem, brokered secrets, no debug mode, no privileged mode, no host PID namespace, no host networking, and no writable root filesystem;
- explicit trusted-attestor membership;
- Ed25519 verification over canonical attestation bytes;
- deployment challenge nonce binding;
- deterministic issuance/expiry freshness checks.

The sixteen attacks cover release/scan/privacy-policy substitution, deployment identity substitution, image/runtime-measurement substitution, untrusted orchestrator/backend, privileged/host-network/writable-root environment requests, untrusted attestor, forged signature, stale attestation, nonce mismatch, and a degraded P5-C release handle.

Evidence:

- vulnerable ASR: 16/16;
- hardened ASR: 0/16;
- hardened FPR: 0/3;
- hardened SafeTaskRate: 3/3;
- dataset SHA-256: `77548fcef9d14f19fd9d93b1e98ee44a54d572ea56dd4b8756b0cc0d2dd25d85`;
- fixture SHA-256: `030c244da5e5eb5fbf7a52100a569ad706f9c4e9b41244e45fa4b48ab24e5bde`.

P5-H is a **synthetic signed-attestation evidence gate**. It does not claim TPM/TEE/confidential-VM attestation, measured boot, production Kubernetes admission enforcement, transparency-log verification, secure GPU attestation, or protection against a compromised host fabricating synthetic measurements.

## Remaining Phase 5 direction

The next breadth milestone should move away from another provenance-only layer. A useful P5-I direction is **model-serving abuse telemetry and incident response**: aggregate privacy-budget exhaustion and suspicious-query signals, bind incident evidence to the deployed model identity, support deterministic quarantine/revocation decisions, and preserve explicit non-claims about production SIEM/SOAR and distributed enforcement.

Later work can add real runtime-isolation integrations, production scanning integrations, privacy-budget backends, transparency-log evidence, and hardware-backed deployment attestation.
