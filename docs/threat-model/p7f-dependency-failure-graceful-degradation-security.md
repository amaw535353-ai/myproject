# P7-F — dependency-failure and graceful-degradation security analysis

## Security objective

Availability mechanisms must not silently weaken security guarantees. P7-F models dependency failure states and fallback behavior as security evidence, distinguishing **service continuity** from **security preservation**.

`DependencyFailureSecurityAnalyzer` binds a versioned resilience plan to exact P7-E third-party trust evidence and P6-D control posture, then deterministically derives whether each modeled degraded/unavailable/untrusted dependency scenario remains controlled or becomes security-exposed.

## Failure and fallback model

Failure states:

- `DEGRADED`
- `UNAVAILABLE`
- `UNTRUSTED`

Fallback modes:

- `FAIL_CLOSED`
- `RETRY_PRIMARY`
- `ALTERNATE_DEPENDENCY`
- `LOCAL_SAFE_MODE`
- `CACHE_FALLBACK`

A fail-closed result can preserve security while intentionally not restoring service continuity. Conversely, a fallback can restore synthetic continuity while remaining explicitly exposed when required controls, alternate-provider trust, retry semantics, or cache freshness are unsafe.

## Hardened properties

The analyzer requires:

- exact resilience-plan ID, version, SHA-256, freshness, and P7-E dependency-graph binding;
- exact P7-E assessment and P6-D posture/control-catalog evidence digests;
- fully verified P7-E destination identity, transport/authentication, egress-scope, and fail-closed properties;
- one unambiguous P7-E trust path per modeled dependency;
- exact required failure-scenario and fallback coverage;
- trusted scenario/fallback owners;
- policy-pinned dependency and failure state per scenario;
- exact required security controls per scenario;
- exact fallback mode, scenario binding, target dependency, preserved/disabled controls, bounded data classes, secret scope, retry bounds, and cache-age policy;
- complete accounting for every required security control as either preserved or explicitly disabled;
- fail-closed fallbacks that cannot transmit data, retry, cache, target another dependency, or disable controls;
- retry-primary fallbacks that target only the primary dependency with bounded attempts;
- alternate-dependency fallbacks that target a distinct P7-E dependency;
- local safe mode that does not consume secrets or silently call an external dependency;
- cache fallback with a concrete cache timestamp and deterministic freshness evaluation;
- semantic exposure when a required control is disabled, exceptioned, or not evaluated on a continuing fallback;
- semantic exposure when an untrusted dependency is retried;
- semantic exposure when an alternate P7-E path is already exposed or has weaker transport/authentication than the primary path;
- semantic exposure when cache material exceeds its policy-owned age bound; and
- rejection when caller-declared exposed scenarios or maximum security risk disagree with derived evidence.

## Deterministic fixture

Seven scenarios exercise different resilience semantics:

1. hosted model unavailable → local constrained safe mode;
2. hosted model untrusted → independently pinned secondary model dependency;
3. hosted model degraded → bounded retry of the primary;
4. privileged tool unavailable → fail closed;
5. identity provider unavailable → fail closed;
6. telemetry processor degraded → bounded local cache/buffer fallback; and
7. registry unavailable → bounded previously verified local cache fallback.

The default fixture contains **seven failure scenarios and seven fallback strategies**. With modeled controls satisfied, all seven scenarios preserve security; five retain synthetic service continuity and two deliberately fail closed.

Additional valid evidence cases demonstrate that:

- an exception on `CTRL-CACHE-INTEGRITY` exposes the telemetry and registry cache scenarios, with maximum synthetic security risk **68**;
- `CTRL-FALLBACK-AUTHZ` as `NOT_EVALUATED` exposes all three model-continuity scenarios, with maximum risk **73**;
- a stale telemetry cache remains visible as one exposed scenario with synthetic risk **56**; and
- a fail-closed tool/identity scenario remains security-preserving even if the modeled `CTRL-FAIL-CLOSED` status is exceptioned, because no operation proceeds; the exception remains visible in per-scenario evidence rather than being treated as restored availability.

## Adversarial evaluation

The repository evaluator encodes **64 adversarial cases**. The set covers request/manifest identity substitution; stale/future plans; missing/duplicate failure scenarios or fallbacks; untrusted owners; dependency/failure-state/control drift; fallback scenario/mode/target/control/data/secret drift; retry and cache-time violations; invalid fail-closed/retry/alternate/local/cache shapes; malformed policy maps/bounds; P7-E and P6-D verification/digest/control-summary substitution; explicit control disabling; retry of an untrusted primary; stale cache continuation; exposed alternate dependencies; weaker alternate transport/authentication; and forged caller green summaries.

An isolated local API-compatible harness compiled and exercised a P7-F mirror, passed **70 P7-F security-test outcomes**, and completed the deterministic evaluation:

- adversarial cases: **64**;
- vulnerable ASR: **64/64**;
- hardened ASR: **0/64**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**;
- resilience-plan SHA-256: `ac05d8714cc2b13c8bcfa29675884f5831e2de35e244c9756e23f8165547abe1`;
- dataset SHA-256: `769ea9a325c703ed6a200bd543240f5d333877657a3f8cb85d122d228c5e7b15`;
- fixture SHA-256: `953b61ba33e010b27c837305ea5d29c27216192d054578f6c867063b8a8c9df7`.

The harness used API-compatible P7-E/P6-D interfaces and a mirror of the P7-F implementation/evaluator/test contract. This is **not** a claim that full-repository pytest ran locally or that the GitHub-hosted P7-F files executed byte-for-byte in that harness.

## Vulnerable baseline

`VulnerableAvailabilityRestorationReporter` accepts caller-owned aggregate declarations that dependencies recovered, fallbacks are safe, security degradation count is zero, and maximum risk is zero. It does not bind exact failure scenarios, fallback semantics, P7-E trust evidence, or individual P6-D control states.

## Claim boundary

P7-F is deterministic synthetic resilience-security evidence. It does **not** claim:

- production dependency health monitoring;
- real failover/fallback orchestration;
- live outage or chaos testing;
- real retry behavior, queues, caches, or network partitions;
- actual availability, latency, SLA, SLO, RTO, or RPO achievement;
- disaster-recovery certification;
- production alternate-provider validation;
- live authorization or credential behavior during outages;
- formal liveness/safety proof; or
- compliance/audit certification.

`service_continuity_expected=True` is a modeled plan property, not evidence that service availability is operationally restored.
