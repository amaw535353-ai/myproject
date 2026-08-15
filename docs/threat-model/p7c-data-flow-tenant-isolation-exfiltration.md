# P7-C threat model — data flow, tenant isolation, and exfiltration paths

## Objective

P7-C extends the Phase 7 architecture model from topology and identity/capability escalation into explicit data-flow analysis. The goal is to make tenant ownership, data classification, route coverage, transforms, sink policy, and evidence-backed controls first-class security facts rather than caller assertions.

The hardened boundary is `TenantIsolationExfiltrationAnalyzer`. It consumes a canonical `DataFlowManifest`, the exact P7-A `ArchitectureManifest`, intact P7-A and P7-B assessment evidence, and P6-D control posture. It deterministically derives paths from policy-owned data origins to policy-owned sinks and surfaces cross-tenant or high-sensitivity egress conditions.

## Assets and protected properties

The synthetic fixture models:

- multi-tenant content originating in `vector-store`;
- retrieval through `retriever` into `agent-orchestrator`;
- model-context transfer into `model-runtime`;
- user response egress to `external-user`;
- synthetic credential material from `secret-store` through `tool-gateway` and the agent;
- minimized runtime security telemetry into `security-telemetry`.

Protected properties:

1. **Exact graph binding.** The data graph is bound to its ID, version, SHA-256, and exact P7-A architecture digest.
2. **Tenant ownership integrity.** Policy pins the authoritative tenant for every required data object. The manifest cannot silently relabel a tenant-owned object.
3. **Classification integrity.** Policy pins a minimum classification floor. A caller cannot lower `secret` or `confidential` data to make an unsafe sink appear acceptable.
4. **Route completeness.** Required data objects and flow edges must match the policy-owned inventory exactly; omission and untracked additions fail closed.
5. **Route integrity.** Every required data edge is bound to exact source/target assets, P7-A flow IDs, controls, and an allowlisted transform.
6. **Upstream evidence integrity.** P7-C binds the exact P7-A attack-path evidence, P7-B privilege evidence, P6-D posture evidence, and control catalog.
7. **Tenant-boundary visibility.** Every edge destination tenant is checked against the data object's policy-allowed tenant set and violations remain explicit path facts.
8. **Sink/classification visibility.** The final sink is checked against the data object's allowed sinks and the sink classification ceiling. Approved redaction/aggregation/tokenization can reduce the exposed payload for classification-ceiling analysis, but does not rewrite the original data classification.
9. **Control-gap visibility.** Exceptioned and not-evaluated P6-D controls make the path exposed; satisfied controls remain visible as mitigating counterevidence.
10. **Caller-summary distrust.** The analyzer rejects caller-declared exposed-path IDs or maximum risk scores that do not match the evidence-derived result.
11. **Bounded enumeration.** Simple data paths are enumerated with path-count and hop bounds. If a bound would truncate a reachable frontier, analysis fails closed.

## Trust boundaries

- **Tenant data → retrieval.** Tenant isolation and RAG filtering constrain retrieved content.
- **Agent → model runtime.** Inference privacy constrains model-context transfer.
- **Secret store → privileged tool.** Credential brokering and least privilege constrain synthetic secret movement.
- **Tool → agent.** Tool authorization constrains the return of privileged results.
- **Agent → external user.** Tenant isolation and output filtering constrain external response egress.
- **Model runtime → security telemetry.** Telemetry minimization constrains security observability data.

## Adversary model

The modeled attacker can submit or substitute synthetic architecture/data evidence and can attempt to make a release appear data-safe by:

- deleting required data objects or routes;
- adding untracked routes;
- relabeling tenant ownership or data kind;
- lowering classification;
- substituting route endpoints, P7-A flows, controls, or transforms;
- substituting P7-A/P7-B/P6-D evidence or control-catalog digests;
- degrading upstream verification flags;
- corrupting control-assessment aggregates;
- narrowing the entry-data or sink scope;
- exploiting path-count/hop truncation; or
- declaring zero exposed paths and zero risk despite contrary evidence.

The attacker does **not** control the trusted P7-C policy object in the security claim. Evaluation includes malformed policy cases to show fail-closed behavior, but a deliberately changed trusted policy is a governance/change-management problem rather than an inference-layer attack.

## Deterministic fixture result

The default fixture contains three data objects and eight required data-flow edges. It derives four paths:

- tenant ticket → model runtime;
- tenant ticket → external user;
- synthetic platform secret → external user;
- runtime telemetry → security telemetry.

With `CTRL-TENANT-ISOLATION` exceptioned and other fixture controls satisfied:

- topology paths: **4**;
- exposed paths: **3**;
- controlled paths: **1**;
- cross-tenant exposed paths: **2**;
- external-egress exposed paths: **2**;
- restricted/secret exposed paths: **1**;
- maximum synthetic risk score: **157**.

The secret-to-user path is exposed because the destination tenant is not authorized, `external-user` is not an allowed secret sink, and the untransformed secret exceeds the sink classification ceiling. The tenant-ticket model path remains visible as exposed while tenant isolation is exceptioned. Runtime telemetry remains controlled because it is redacted, goes to the approved security tenant/sink, and its required control is satisfied.

## Security evaluation

The deterministic P7-C evaluation contains **61 adversarial cases** and three benign analysis inputs.

Expected metrics:

- vulnerable ASR: **61/61**;
- hardened ASR: **0/61**;
- hardened FPR: **0/3**;
- SafeTaskRate: **3/3**.

The matched intentionally weak `VulnerableDataExfiltrationReporter` trusts caller-declared graph completeness, exposed-path count, and maximum risk and therefore accepts a forged green summary without inspecting tenant/classification/route/upstream evidence.

## Claim boundary

P7-C is a deterministic synthetic information-flow analysis lab. It does **not** claim:

- production cloud/SaaS/database data discovery;
- automatic data classification or semantic PII/secret detection;
- production DLP enforcement;
- live packet capture, network reachability, or egress interception;
- real tenant data access;
- credential retrieval;
- model prompt/output inspection in production;
- live exfiltration testing;
- formal non-interference or information-flow proof;
- complete data lineage;
- production SIEM/DLP/CASB integration;
- legal privacy/compliance certification; or
- protection against a compromised trusted policy/runner that fabricates all upstream evidence consistently.

The synthetic risk score is an ordering aid for the fixture, not a calibrated probability, loss estimate, CVSS score, or compliance rating.
