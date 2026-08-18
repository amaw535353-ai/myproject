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

## Claim boundary

Success is **live-local AI-security telemetry and detection-engineering
validation**. It does not claim a production SIEM, enterprise SOC, Kubernetes or
cloud audit pipeline, EDR/UEBA, threat-intelligence enrichment, production-scale
retention/ingestion, ATT&CK completeness, or detection latency/SLA.
