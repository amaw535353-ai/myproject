# P5-G threat model — model privacy, extraction, and membership-inference controls

## Objective

P5-G adds an inference-privacy policy boundary after the existing P5-E runtime-admission and P5-F model-content scan gates. The security question is different from provenance or poisoning detection: even a correctly sourced, runtime-admissible, scan-clear model can expose too much information through a high-fidelity or effectively unlimited inference oracle.

The hardened boundary therefore treats inference access itself as a scoped capability. It binds each release to an exact approved P5-F scan digest, constrains output fidelity, denies sensitive internal channels, applies deterministic query budgets, and rejects modeled canary, memorization, membership-inference, and model-extraction indicators.

## Security properties

`ModelPrivacyGateway` requires all of the following before releasing the modeled response:

- an intact non-executing P5-E `VerifiedRuntimePlan`;
- an intact clear P5-F `VerifiedModelScan` for the same package/model/revision/runtime identity;
- exact binding to the deployment-approved P5-F evidence SHA-256;
- non-empty principal, session, query, and query-fingerprint identity;
- an allowlisted output mode;
- bounded top-k and confidence precision;
- denial of raw logits, per-token probabilities, embeddings, and hidden states, both when requested and when present in response evidence;
- bounded response length;
- answer-only and top-label mode consistency;
- complete canary scanning and fail-closed rejection of forbidden training-canary fragments;
- bounded synthetic memorization-overlap evidence;
- bounded synthetic membership-inference advantage;
- bounded synthetic model-extraction similarity;
- a per-session inference-query budget;
- a repeated-query-fingerprint budget;
- one-time query IDs within the model/principal/session scope.

The accepted handle records only the modeled minimized output plus privacy-control evidence. No real model inference occurs in P5-G.

## Adversary model

The deterministic evaluation models an attacker who can request or induce privacy-sensitive response modes after a model has otherwise passed earlier Phase 5 gates. The attacker attempts to:

1. request raw logits;
2. induce per-token probability return;
3. request embeddings;
4. induce hidden-state return;
5. request an excessive top-k distribution;
6. request high-precision confidence values;
7. select an unapproved full-distribution output mode;
8. elicit a planted training-canary string;
9. produce excessive training-text overlap;
10. produce a strong synthetic membership-inference signal;
11. produce a strong synthetic model-extraction similarity signal;
12. exhaust the per-session query budget and continue querying;
13. repeatedly probe the same query fingerprint beyond policy;
14. substitute a different P5-F scan evidence digest;
15. use a degraded P5-F scan handle;
16. use a degraded P5-E runtime handle.

The matched vulnerable baseline is an inert unlimited oracle that trusts these declarations and response-evidence fields. It does not execute a model.

## Deterministic evidence

- adversarial cases: **16**
- vulnerable ASR: **16/16**
- hardened ASR: **0/16**
- hardened FPR: **0/3**
- hardened SafeTaskRate: **3/3**
- dataset SHA-256: `77d70ca43f0098919df126da4b892e1ea530d2adf8fb062362f4acd99c37eca4`
- fixture SHA-256: `243cefb858ba25324418373d7ec81c2d3c936f1fbdc8c0b7019fceac5a802489`

The benign cases cover answer-only output, one top label, and one-decimal coarse confidence under separate bounded query fingerprints.

## Evidence hygiene

P5-G uses only deterministic synthetic response evidence. It performs:

- no real model inference;
- no real membership-inference attack;
- no real model-extraction attack;
- no access to a real training corpus;
- no network calls;
- no raw logit, embedding, or hidden-state handling.

## Claim boundary

P5-G demonstrates policy logic for oracle-fidelity minimization, query budgeting, canary leakage rejection, and synthetic privacy-risk indicators. It does **not** establish a differential-privacy guarantee, prove resistance to adaptive membership inference or model extraction, enforce a production distributed rate limit, prevent side channels, provide secure multi-tenant accounting, prove that canary absence means memorization absence, or calibrate real-world privacy thresholds.

The in-memory budget ledger is deterministic lab state. It is not rollback-resistant, distributed, durable, race-hardened, or abuse-resistant across independent gateway processes.

## Next breadth direction

A natural P5-H breadth milestone is **deployment provenance and attestation**: bind the approved model release, runtime policy, scan evidence, privacy policy, and deployment environment into deterministic deployment evidence, while explicitly distinguishing synthetic attestation from production hardware-backed attestation or transparency infrastructure.
