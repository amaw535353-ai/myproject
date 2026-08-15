# P7-E — external dependency, service-egress, and third-party trust-path analysis

## Security objective

P7-E makes outbound service trust explicit. A release must not appear architecturally safe merely because internal trust-boundary, privilege, data-flow, secret, and control-posture evidence is present while outbound model, tool, identity, telemetry, or registry dependencies are caller-declared as trusted.

`ExternalDependencyTrustAnalyzer` derives third-party trust paths from a policy-pinned dependency manifest and exact upstream P7-A/P7-B/P7-C/P7-D/P6-D evidence.

## Protected properties

The hardened boundary requires:

- exact dependency-graph ID, version, SHA-256, freshness, and architecture binding;
- exact P7-A attack-path, P7-B privilege, P7-C data-flow, P7-D secret-exposure, and P6-D posture evidence digests;
- one exact manifest record for every required dependency and service-egress route;
- trusted internal owners and trusted external provider identities;
- policy-pinned dependency type and minimum criticality;
- exact endpoint host and port;
- exact transport and authentication mode;
- exact expected destination/server identity;
- bounded data-class and secret exposure scope per dependency;
- exact dependency and route control sets with P6-D status derivation;
- policy-pinned fail-closed behavior;
- exact route source asset, target dependency, architecture-flow chain, and controls;
- contiguous P7-A flow routing that terminates at the declared egress source;
- policy-owned entry-source and target-dependency scope; and
- caller-declared exposed paths and maximum risk checked against deterministic derived evidence.

Satisfied controls are retained as mitigating counterevidence. Exceptioned and not-evaluated egress controls remain explicit exposure reasons rather than being collapsed into a green aggregate.

## Threats covered

The synthetic adversarial evaluation targets graph/request identity substitution, missing or duplicate dependencies/routes, untrusted providers/owners, endpoint or port substitution, transport/authentication downgrade, destination-identity substitution, criticality downgrade, unauthorized data or secret scope, control removal, fail-open drift, route/source/dependency/flow/control substitution, non-contiguous architecture routing, upstream evidence downgrade/substitution, control-catalog drift, and forged caller green summaries.

## Deterministic fixture

The fixture models five third-party dependencies:

1. hosted model provider;
2. privileged tool API;
3. external telemetry processor;
4. package/model registry; and
5. identity provider.

Each dependency has an exact provider, endpoint, port, transport/authentication profile, expected server identity, egress data/secret scope, criticality, control set, and fail-closed expectation. Five service-egress routes bind those dependencies to exact P7-A architecture-flow chains.

With all modeled controls satisfied, all five paths are controlled. An exception on `CTRL-TOOL-EGRESS` exposes one critical, secret-bearing, restricted-data path with synthetic risk score 134. A `NOT_EVALUATED` `CTRL-TELEMETRY-EGRESS` state exposes one telemetry path with score 60.

The repository evaluator encodes 49 adversarial cases plus three benign scenarios.

## Vulnerable baseline

`VulnerableDependencyTrustReporter` trusts caller-owned aggregate claims that the graph is complete, all destinations are trusted, exposed-path count is zero, and maximum risk is zero. It does not validate destination identity, route coverage, transport/authentication assumptions, upstream evidence, or individual control states.

## Claim boundary

P7-E is deterministic synthetic architecture evidence. It does **not** claim:

- production dependency discovery or SBOM/service-catalog completeness;
- live DNS, TLS certificate, SPIFFE, OAuth, or mTLS validation;
- production firewall, proxy, service-mesh, or cloud-egress enforcement;
- real outbound API/model/tool calls;
- third-party penetration testing or vendor assurance;
- real secret transmission or credential validation;
- complete software-supply-chain provenance;
- formal reachability/non-interference proof; or
- compliance, audit, or regulatory certification.

Provider IDs and expected server identities are policy assertions in the synthetic fixture, not independently verified operational identities.
