# P11-F live-local detection engineering

P11-F validates a bounded security-analytics pipeline: minimized canonical event,
authenticated producer envelope, HTTP collector, source authorization, temporary
SQLite storage, repository-native rules, temporal correlation, alert deduplication,
incident handoff, and tamper-evident evidence.

## Trust boundaries and threats

Each producer has an ephemeral Ed25519 identity and an allowlist of event domains.
The collector verifies the signature and body binding before trusting source,
category, timestamp, or provenance classification. It rejects source/category
impersonation, unsigned or modified events, replay amplification, malformed or
oversized input, stale/future timestamps, unbounded attributes, control-character
injection, and secret-bearing telemetry. SQLite uniqueness and event/alert hash
chains make local mutation evident; they are not immutable or WORM storage and do
not protect against a privileged operator rebuilding the database and trust root.

Rules are canonical JSON data, never executable expressions. Validation rejects
duplicate IDs, unknown rule fields/operators, disabled protected rules, unbounded
windows, and incomplete domain coverage. Correlation is grouping- and window-bound
and is tested against wrong-tenant/principal, missing-stage, out-of-window,
out-of-order, replay, and benign-flood evasion. Alert deduplication limits storms
without suppressing the first high-severity signal.

The HTTP route consumes the body incrementally and returns 413 when the bounded
collector cap is crossed. Freshness is evaluated against an injected trusted
server clock; caller headers cannot set that clock. Deterministic tests inject a
fixed clock directly into the service, never through HTTP.

## Data minimization

Events contain bounded reason codes and domain-separated HMAC references. They do
not contain prompts, responses, retrieved text, tool arguments, tokens, cookies,
keys, secrets, model bytes, or authorization headers. Sensitive-material scanning
is part of the live pass predicate and is supplemented by an external leak scan.

## Evidence classes

- `NATIVE_LIVE` is reserved for a producer's direct live event.
- `LIVE_CONTROL_OBSERVATION` represents an adapter event derived from an actually
  observed local HTTP or Kubernetes control denial.
- `DETERMINISTIC_FIXTURE` is a bounded attack/benign story routed through the real
  live collector, store, and rules.

Fixture events are never described as native application logs. The Kubernetes
adapter observes an API denial and is not a Kubernetes audit-log pipeline.
Fixture producers and live-control adapters have separate ephemeral keys and
single-class provenance policies. No `NATIVE_LIVE` event is manufactured by this
lab.

## Detection and integrity semantics

Input fixtures specify event sequences and expected rule IDs but no observed
result. Eight covered malicious sequences and thirteen overlapping benign
sequences execute through fresh real source registries, collectors, SQLite stores,
and rule engines; metrics are derived from persisted alerts. Mutation tests prove
that rule removal increases escapes and an overbroad rule increases false alerts.

One canonical digest of the parsed, ordered JSON rule bundle is used by loading,
evaluation, live evidence, and validation. The validator independently recomputes
the alert chain and incident snapshot and exactly checks the rule digest. The
event-chain terminal and SQLite snapshot hashes are computed and verified before
the temporary database is deleted, then cross-bound into retained evidence; raw
event payloads are intentionally not retained, so the event chain cannot be
independently replayed from the sanitized evidence alone.

## Claim boundary

Success is **live-local AI-security telemetry and detection-engineering
validation**. It does not claim a production SIEM, enterprise SOC, Kubernetes or
cloud audit pipeline, EDR/UEBA, threat-intelligence enrichment, production-scale
retention/ingestion, ATT&CK completeness, or detection latency/SLA.
