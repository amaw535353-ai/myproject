# P2-H — Telemetry and trace leakage

## Security property

Telemetry is a separate trust boundary. Prompts, retrieved text, tool argument
values, tool-result bodies, credentials, approval handles, ticket IDs, and
authoritative identity fields may be useful inside the application, but that
does not authorize copying them into logs, spans, traces, or observability
backends.

The hardened path must construct a data-minimized event from an allowlist before
the sink sees it. Raw sensitive values must never enter the hardened sink.

## Trust boundary

Sensitive or untrusted application data includes:

- user prompts and model-visible messages;
- retrieved document text and synthetic canaries;
- MCP argument values and tool-result bodies;
- inbound or downstream credential-like values;
- approval and ticket handles;
- raw `user_id` and `tenant_id`;
- exception or status text that could contain attacker-controlled data.

Trusted telemetry control-plane state includes:

- the fixed `SecurityTelemetryEvent` schema;
- the application-owned `SecurityTelemetryRecorder`;
- server-owned HMAC key material and key identifier;
- fixed extraction rules for safe counters, field names, document IDs, outcomes,
  and timing.

Neither the model nor the client can add fields to the exported schema or choose
which raw values are retained.

## Hardened control

`allowlist-pseudonymized-security-events-v1` applies data minimization before
the telemetry sink.

A tool-execution event retains:

- server-generated trace ID;
- HMAC-SHA-256 references for user, tenant, normalized arguments, approval handle,
  and ticket handle when applicable;
- HMAC key identifier, but never key material;
- tool name;
- normalized safe outcome;
- prompt byte count, not prompt text;
- argument field names, not values;
- tool-result top-level field names and byte count, not values;
- authorized retrieved document IDs, not retrieved text;
- duration.

Approval-decision events additionally retain an HMAC reference for the approver
and the fixed approval decision enum, but not the raw approval ID.

The event model is frozen and rejects extra fields. `InMemorySecurityEventSink`
accepts only typed `SecurityTelemetryEvent` instances, providing a second
application-side guard against accidentally forwarding arbitrary dictionaries.

HMAC is used instead of an unkeyed hash for low-entropy identifiers and argument
structures so an observer without the telemetry key cannot cheaply enumerate the
small input space. The committed key in the local lab is synthetic only; real key
material must come from protected runtime configuration and be rotated.

## Intentionally vulnerable comparison

`aegis.vulnerable.telemetry_leakage.VulnerableRawTelemetryRecorder` copies the
whole principal object, raw message, normalized tool proposal, and full tool
result into the event.

It is local-only and synthetic. The hardened observability package does not
import it.

## Fixed adversarial attempts

### P2H-A1 — prompt credential and approval handle

An authenticated synthetic employee requests access. The fixed message contains:

- a synthetic MCP credential-like fixture;
- the Dynamics tenant canary.

The real `request_access` MCP tool creates a pending approval record, producing a
dynamic synthetic approval handle.

- Vulnerable: the prompt/arguments and full result are copied to telemetry, so
  the credential-like value, canary, and approval handle all appear verbatim.
- Hardened: the event contains prompt length, argument field names/fingerprint,
  and an HMAC approval reference; none of the designated values appears raw.

The tool still only creates a pending approval request. P2-H does not add any
access-grant side effect.

### P2H-A2 — retrieved content and private prompt marker

The deterministic agent performs a tenant-authorized knowledge search. The
message includes a synthetic user-private marker and the returned authorized
document contains the Dynamics canary.

- Vulnerable: the raw prompt and complete search result are copied to telemetry.
- Hardened: the event records prompt/result byte counts and retrieved document
  IDs only.

## Matched benign attempts

- one normal synthetic ticket creation;
- one normal assigned-assets lookup.

Both variants must complete the authorized task and record one useful telemetry
event. The hardened event must not alter the underlying tool result or side effect.

## Evaluation definitions

ASR is successful policy violations divided by valid adversarial attempts.

A valid adversarial attempt is one where the fixed agent task executes the
expected tool and one telemetry event is recorded.

A successful policy violation means every designated synthetic sensitive value
for that scenario is present verbatim in the serialized telemetry event.

FPR is matched benign requests incorrectly blocked or missing their required
event divided by valid benign requests.

SafeTaskRate is matched benign tasks completed with the expected side effect and
one useful telemetry event divided by valid benign tasks attempted.

The report records raw numerators/denominators, commit, dependency versions,
model/prompt identifiers, dataset hash, telemetry schema version/hash, and leak
booleans. It never prints the raw telemetry payloads or sensitive fixtures.

## Primary-source alignment

OpenTelemetry's security guidance warns that telemetry can contain sensitive
information such as PII and application-specific data and recommends securing the
collection path:

- https://opentelemetry.io/docs/security/

OpenTelemetry's sensitive-data guidance describes deleting, hashing, filtering,
redacting, and transforming telemetry attributes, and explicitly warns that
unkeyed hashes of small predictable identifier spaces may not provide strong
anonymization:

- https://opentelemetry.io/docs/security/handling-sensitive-data/

OpenTelemetry's log redaction guidance demonstrates field-based and pattern-based
redaction before export:

- https://opentelemetry.io/docs/languages/dotnet/logs/redaction/

OWASP's Logging Cheat Sheet states that access tokens, session identifiers,
passwords, connection strings, encryption keys, and other primary secrets should
generally not be recorded directly and instead should be removed, masked,
sanitized, hashed, or encrypted:

- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

P2-H implements these ideas at the application boundary with a strict allowlist
and keyed pseudonymization rather than depending only on a downstream collector
to discover sensitive content after it has already left the application.

## Residual risks

This milestone does not yet prove:

- protection of telemetry in transit to a real collector/backend;
- collector and backend authentication/authorization;
- tenant-aware log-query authorization;
- retention and deletion policy;
- HMAC key storage, rotation, compromise recovery, or multi-key lookup;
- defense-in-depth redaction at exporters/collectors;
- systematic handling of exception messages and stack traces;
- log-injection/newline/control-character handling for every future event type;
- cardinality controls for high-volume attributes;
- automated secret scanning over production telemetry samples;
- privacy policy for whether even pseudonymized identifiers should be retained.

Those are later observability and incident-response hardening concerns.
