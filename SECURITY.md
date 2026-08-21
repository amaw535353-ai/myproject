# Security Policy

## Supported Versions

Before the first tagged release, only `main` is supported. Once a tagged release
exists, `main` and the latest tagged release are supported.

| Version | Supported |
|---|---|
| `main` | Yes |
| Latest tagged release | Yes, once one exists |
| Older tags or branches | No |

No tag or release currently exists.

## Reporting a Vulnerability

Do not report vulnerabilities, credentials, secrets, tenant data, or exploit
details in public GitHub issues, pull requests, discussions, or other public
channels.

Use GitHub Private Vulnerability Reporting: open the repository's **Security**
tab, open **Advisories**, and select **Report a vulnerability**. That is the only
vulnerability-reporting route for this repository.

Include only the information needed to understand and reproduce the issue safely:

- the affected component and revision;
- the security boundary or invariant that fails;
- prerequisites and realistic impact;
- a minimal, sanitized local reproduction;
- suggested remediation, if known.

Do not include credentials, personal information, real tenant data, unnecessary
exploit detail, or data obtained from third-party systems.

## Disclosure and Response Expectations

Reports will be reviewed on a best-effort basis. There is no promised
acknowledgment, remediation, or disclosure SLA.

Keep vulnerability details private while the report is being reviewed. Any
disclosure timing should be coordinated through the private advisory. Submission
does not guarantee acceptance, a particular severity, remediation, or a release.

## System and Scope

AegisDesk is a synthetic, local AI-security engineering lab for a multi-tenant
help-desk RAG agent, MCP tools, agentic workflows, model supply chain, training,
inference, and platform-security controls. It is a portfolio demonstration, not
a production product or attack platform.

Security review may cover:

- the default FastAPI application and server-owned identity, tenant,
  authorization, approval, budget, and effect boundaries;
- hardened RAG, MCP, memory, agentic, model-supply-chain, training, inference,
  platform, detection, and incident-handling components;
- packaging, dependency, workflow, and evidence-integrity controls;
- isolation of intentionally vulnerable local comparison components;
- documentation or automation that could materially misrepresent deterministic,
  live-local, or production evidence.

The repository contains intentionally vulnerable components for local comparison.
They are expected to remain isolated under explicit vulnerable or lab paths and
must not be exposed publicly.

## Threat Model and Trust Boundaries

Protected assets include tenant-scoped knowledge and memory, authenticated
principal and tenant identity, authorization and approval state, tool and effect
authority, model and container provenance, training and inference state,
credentials and trust material, security telemetry, and evidence integrity.

Attacker-controlled or untrusted inputs include request bodies, prompts,
retrieved documents, model output, MCP tool metadata and arguments, delegated
agent messages, uploaded or fetched artifacts, external service responses,
package and model metadata, deployment manifests, runtime observations, and
caller-supplied evidence summaries.

Important trust boundaries include:

- client input to server-derived identity and tenant scope;
- retrieved or model-generated content to server-owned policy;
- agent or tool proposals to authorization, approval, and effect execution;
- mutable artifacts and tags to digest-, provenance-, and policy-bound admission;
- tenant requests to shared retrieval, memory, training, cache, adapter, batch,
  and output state;
- runtime observations to evidence validation and portfolio claims;
- intentionally vulnerable local labs to hardened and potentially exposed
  application paths.

Tests and committed evidence describe intended controls and regression behavior.
They do not prove that a control works in production.

## Security Invariants

The following properties must hold:

- tenant and principal scope is derived from trusted server context, not
  attacker-controlled request or model data;
- retrieved text, model output, tool metadata, memory, and agent messages cannot
  grant identity, authorization, approval, or effect authority;
- tool and effect execution is authorized at the effect boundary using typed,
  server-owned policy and current security context;
- high-impact approvals are bound to the exact principal, tenant, action,
  arguments, plan, evidence, reviewer authority, freshness, and replay state;
- untrusted parsing, network access, retries, model calls, tool calls, and other
  resource use remain bounded and fail closed;
- model, package, container, training, and deployment decisions bind immutable
  identity, provenance, policy, and relevant security evidence;
- tenant-specific retrieval, memory, training, inference, cache, adapter, batch,
  and output state cannot cross tenant boundaries;
- evidence cannot be upgraded from deterministic to live-local or production by
  a caller declaration, missing observation, template, or fabricated pass;
- intentionally vulnerable components remain local, synthetic, isolated, and
  absent from the default hardened application surface;
- secrets, credentials, private prompts, personal information, and unnecessary
  sensitive output are not committed or emitted as evidence.

## Reportable Findings and Severity Context

Reportable findings include realistic, reachable failures of the invariants
above, including:

- cross-tenant access, state reuse, or information disclosure;
- authentication, authorization, approval, or effect-boundary bypass;
- prompt, model, tool, memory, or agent-controlled expansion of authority;
- unsafe artifact execution, provenance bypass, or supply-chain admission bypass;
- credential, secret, private prompt, or sensitive telemetry exposure;
- unbounded parsing, network access, execution, or resource consumption with a
  meaningful security impact;
- escape or public exposure of an intentionally vulnerable component;
- evidence-integrity failures that can convert missing, synthetic, blocked, or
  failed execution into a live or production pass;
- material workflow or packaging weaknesses that create a realistic repository
  or release compromise path.

Severity depends on demonstrated reachability, attacker prerequisites, affected
assets, tenant or authorization boundary crossed, confidentiality, integrity, or
availability impact, persistence, and whether the affected path is part of the
default application, an opt-in local lab, or an unimplemented production
integration.

Reachable cross-tenant disclosure, unauthorized high-impact effects, credential
compromise, arbitrary code execution, or release or supply-chain compromise may
justify high or critical severity. A local-only issue with substantial
prerequisites, no boundary escape, and no realistic sensitive asset may warrant
lower severity. Labels, test names, or vulnerable-component names alone do not
determine severity.

## Out of Scope and Accepted Risk

The following exclusions and accepted risks apply:

- documented behavior of intentionally vulnerable local comparison components is
  accepted risk only while it remains synthetic, isolated, local, and absent
  from the default application; an isolation failure or undocumented boundary
  escape remains reportable;
- attacks against third-party systems, services, accounts, models, registries,
  clusters, or infrastructure are out of scope;
- denial-of-service testing, social engineering, persistence, data exfiltration,
  and testing with real credentials or tenant data are out of scope;
- model answer quality, hallucination, groundedness, or factual correctness alone
  is out of scope unless it causes a concrete security-boundary failure;
- absence of an unclaimed production integration is not itself a vulnerability;
  a false evidence or documentation claim that upgrades unverified behavior may
  be reportable;
- synthetic markers, canaries, fixture credentials, and intentionally reviewed
  secret-scan fixtures are not real secrets merely because they resemble one;
  exposure of an actual secret or an unsafe fixture escape remains reportable;
- unsupported older tags and branches are out of scope.

These exclusions do not suppress a finding merely because a test passes or a
component is described as a lab. Reachability and boundary impact must still be
assessed.

## Known Limitations and Compensating Controls

Repository evidence is primarily deterministic and local. Synthetic and local
evidence is not production evidence. Intentionally vulnerable components are
local lab comparisons, and their isolation is an intended control rather than a
production guarantee.

Real-model correctness is not claimed. Production Kubernetes, GPU/MIG/CUDA,
cloud IAM/KMS/HSM, registry, SIEM/SOC, multi-node behavior, scale, reliability,
and production deployment remain unverified.

Compensating measures include synthetic-only fixtures, local binding, explicit
vulnerable/hardened separation, server-owned policy boundaries, bounded
execution, pinned dependencies and actions, reviewed secret scanning, focused
security tests, and explicit `VERIFIED`, `BLOCKED`, and `FAILED` evidence states.
These measures reduce risk and document intended behavior; they do not prove
production effectiveness.

## Safe Harbor

Good-faith security research within this policy is welcome. To remain within this
safe-harbor intent, researchers must:

- test only repository code and systems they own or are explicitly authorized to
  test;
- use synthetic local data and minimize privacy impact and service disruption;
- stop if sensitive or third-party data is encountered;
- not exfiltrate data, establish persistence, use social engineering, perform
  denial-of-service testing, or test third-party systems;
- use the minimum testing needed to demonstrate the issue;
- promptly report the issue through GitHub Private Vulnerability Reporting and
  keep the details private while they are reviewed.

For research conducted in good faith and consistently with these requirements,
the project maintainers intend not to pursue or support legal action solely
because of that research. This statement expresses project intent only. It is
not legal advice, a legal guarantee, immunity, authorization for third-party
systems, or a promise that another person or organization will take the same
view.
