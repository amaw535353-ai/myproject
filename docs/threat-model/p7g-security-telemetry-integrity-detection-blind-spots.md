# P7-G — security telemetry integrity, auditability, and detection blind-spot analysis

## Security objective

A release must not be described as “fully monitored” merely because logs exist or an aggregate coverage percentage is green. P7-G treats security telemetry as an evidence-bound architecture surface: required events must map to exact upstream security objects, traverse policy-owned telemetry routes, retain required fields and integrity properties, remain observable during relevant failover scenarios, and preserve alert/audit paths.

`SecurityTelemetryIntegrityAnalyzer` derives blind spots from exact P7-A/P7-B/P7-C/P7-D/P7-E/P7-F/P6-D evidence instead of trusting caller-owned monitoring summaries.

## Event catalog

The deterministic catalog contains twelve event requirements spanning:

1. authentication;
2. authorization;
3. privilege changes;
4. privileged tool execution;
5. sensitive data access;
6. data egress;
7. secret/credential access;
8. model runtime security events;
9. model release/signing;
10. third-party dependency egress;
11. dependency failure/failover; and
12. security-control status changes.

Every requirement binds a severity, exact upstream source kind/object IDs, required event fields, alert requirement, detection-latency objective, trusted owner, and relevant P7-F failure scenarios that must remain observable.

## Telemetry topology

The synthetic topology separates event producers from a trusted collector, processor, append-only audit sink, and alert sink. Each requirement has exactly one policy-owned route. Route evidence records:

- source-signature validity;
- chain-integrity validity;
- append-only audit acknowledgement;
- alert-path operation;
- observed detection latency;
- required P6-D telemetry controls;
- required fields dropped in transit; and
- P7-F failure scenarios for which the route remains observable.

## Hardened properties

The analyzer requires:

- exact telemetry-plan ID/version/SHA-256 and freshness;
- exact P7-A through P7-F assessment digests and exact P6-D posture/control-catalog binding;
- verified upstream evidence flags rather than caller-owned source IDs;
- exact required event, node, and route coverage;
- trusted requirement/node/route owners and trusted route observers;
- policy-pinned event class, minimum severity, upstream source kind/object IDs, fields, alert requirement, and latency objective;
- upstream source object IDs that actually exist in the exact verified assessment objects;
- policy-pinned telemetry node types/trust zones and minimum integrity, append-only, and alert capabilities;
- one exact route per requirement;
- producer → collector → processor → audit-sink route shape, plus alert sink when required;
- exact P6-D control sets per route and consistent per-control posture summaries;
- fresh route observations;
- fallback-coverage claims limited to exact P7-F scenarios; and
- deterministic rejection when caller-declared blind spots or maximum risk disagree with evidence.

## Derived blind spots

A structurally valid plan can still be security-degraded. P7-G explicitly derives blind spots when current trusted observations show:

- invalid source signatures;
- broken telemetry integrity chains;
- missing append-only audit acknowledgement;
- unavailable required alert path;
- detection latency above the requirement objective;
- exceptioned telemetry controls;
- not-evaluated telemetry controls;
- P7-F failover scenarios missing from required observability coverage; or
- required event fields dropped in transit.

Satisfied controls remain visible as mitigating counterevidence rather than being collapsed into a single coverage percentage.

## Deterministic fixture

The default fixture contains **12 telemetry requirements, 13 telemetry nodes, and 12 routes**. With all modeled controls satisfied and route observations intact:

- monitored requirements: **12/12**;
- blind spots: **0**;
- maximum blind-spot risk: **0**.

Representative valid degraded states include:

- `CTRL-TELEMETRY-FAILOVER` exceptioned → **6** requirements show telemetry-control blind spots, including **3 critical**, maximum synthetic risk **103**;
- `CTRL-ALERT-ROUTING` not evaluated → **9** alert-required requirements become blind spots, including **7 critical**, maximum risk **101**;
- secret-access alert route unavailable → **1 critical** alerting blind spot, risk **109**;
- tool-execution telemetry missing its `scenario-tool-unavailable` failover coverage → **1 critical** fallback-observability blind spot, risk **105**;
- model-release telemetry chain invalid → **1 critical** integrity blind spot, risk **115**; and
- data-egress required field `data_class` dropped → **1 critical** integrity/completeness blind spot, risk **97**.

## Evaluation and local evidence

The repository evaluator encodes **80 adversarial cases** plus three benign evidence states. The adversarial set covers request/manifest substitution; event, node, and route deletion/duplication/drift; untrusted owners/observers; source-object substitution or omission; field/severity/alert/latency drift; telemetry-node capability loss; route/control/time/fallback manipulation; upstream P7-A through P7-F verification/digest substitution; P6-D posture/catalog/control-summary manipulation; and caller attempts to mask current signature, chain, audit, alert, latency, failover, field-loss, exception, or not-evaluated blind spots.

A small isolated core harness independently reconstructed the canonical P7-G fixture and risk derivation and passed **11 focused checks** covering exact canonical hashes, all-monitored behavior, telemetry failover-control exception, not-evaluated alert routing, alert outage, failover coverage loss, chain-integrity failure, append-only acknowledgement failure, required-field loss, latency breach, and source-signature failure.

Exact deterministic hashes:

- telemetry-plan SHA-256: `f14ddafa02e9a5e5b2b1b2e8055a4ab581c2203bc7a8f3b81c68de9d6e1d4166`;
- adversarial-dataset SHA-256: `70244b7d723da4a959fa7b4555b3c8215c0051347dc64a4e4316615ebf6dca1d`;
- fixture SHA-256: `ed9bfd10eb9e8b76b74498fb14dbc6f8cd2863141e41fa17a942f8e38986f9ea`.

The repository evaluator is designed for vulnerable ASR **80/80**, hardened ASR **0/80**, hardened FPR **0/3**, and SafeTaskRate **3/3**. Because the full GitHub-hosted evaluator and full-repository pytest have not executed in a runnable repository environment, these aggregate values are **encoded evaluator targets, not a green-test claim**. The isolated core harness is also not a claim that the GitHub-hosted P7-G files executed byte-for-byte.

## Vulnerable baseline

`VulnerableMonitoringCoverageReporter` trusts caller declarations that monitoring coverage is 100%, blind-spot count is zero, maximum blind-spot risk is zero, and the system is fully monitored. It does not bind event requirements, upstream evidence, telemetry routes, route integrity, failover observability, or P6-D control states.

## Claim boundary

P7-G is deterministic synthetic telemetry-architecture evidence. It does **not** claim:

- production log ingestion;
- production SIEM/SOAR integration;
- real alert delivery or analyst acknowledgement;
- real detection efficacy, recall, precision, MTTD, or MTTR;
- production timestamp synchronization or immutable storage;
- hardware-backed log signing;
- complete audit-event semantics;
- live adversary detection;
- SOC operating effectiveness; or
- compliance/audit certification.

`append_only_acknowledged=True` and `source_signature_valid=True` are synthetic evidence fields in this lab, not proof of operational WORM storage or hardware-backed signing.
