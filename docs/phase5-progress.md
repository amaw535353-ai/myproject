# Phase 5 progress — model and AI supply-chain security

Phase 5 broadens AegisDesk beyond checkpoint and agent-runtime hardening into model artifacts, provenance, dependency trust, registry acquisition, signing-key lifecycle, model runtime/execution boundaries, model-content risk indicators, and inference privacy controls.

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

P5-G treats inference access as a scoped privacy capability even after a model has passed P5-E and P5-F. The hardened `ModelPrivacyGateway` adds:

- intact P5-E runtime and clear P5-F scan handle requirements;
- exact package/model/revision/runtime identity binding;
- exact deployment binding to the approved P5-F evidence SHA-256;
- principal/session/query/query-fingerprint identity;
- output-mode allowlisting;
- bounded top-k and confidence precision;
- denial of raw logits, per-token probabilities, embeddings, and hidden states;
- bounded response length and output-mode consistency;
- training-canary fragment rejection;
- synthetic memorization-overlap thresholding;
- synthetic membership-inference advantage thresholding;
- synthetic model-extraction similarity thresholding;
- per-session query budgets;
- repeated-query-fingerprint budgets;
- query-ID replay rejection;
- an in-memory deterministic budget ledger with explicit non-production claims.

The sixteen attacks cover raw logits, token probabilities, embeddings, hidden states, excessive top-k, high-precision confidence, an unapproved full-distribution mode, training-canary leakage, memorization overlap, membership signal, extraction signal, session budget exhaustion, repeated-fingerprint probing, P5-F scan-digest substitution, a degraded scan handle, and a degraded runtime handle.

Evidence:

- vulnerable ASR: 16/16;
- hardened ASR: 0/16;
- hardened FPR: 0/3;
- hardened SafeTaskRate: 3/3;
- dataset SHA-256: `77d70ca43f0098919df126da4b892e1ea530d2adf8fb062362f4acd99c37eca4`;
- fixture SHA-256: `243cefb858ba25324418373d7ec81c2d3c936f1fbdc8c0b7019fceac5a802489`.

P5-G uses deterministic synthetic response evidence. It does **not** claim a differential-privacy guarantee, real resistance to adaptive membership inference/model extraction, production distributed rate limiting, side-channel protection, secure multi-tenant accounting, or real training-corpus memorization measurement.

## Remaining Phase 5 direction

The next breadth milestone is **P5-H — deployment provenance and attestation**: bind the approved release, runtime policy, scan evidence, privacy policy, and deployment environment into deterministic deployment evidence while clearly separating synthetic attestation from production hardware-backed attestation or transparency infrastructure.

Later work can add real runtime-isolation integrations, production scanning integrations, privacy-budget backends, transparency-log evidence, and hardware-backed deployment attestation.
