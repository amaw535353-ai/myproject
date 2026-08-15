# P9-D threat model — training execution provenance and least-privilege launch boundary

## Security objective

P9-D consumes one exact P9-C fine-tuning admission assessment and decides whether a **synthetic training launch manifest** is bound to the same authorized plan. The boundary independently derives job identity, code/config provenance, runtime environment policy, secret leases, and capabilities. Caller-declared safety summaries are never authoritative.

## Trusted policy inputs

The policy pins the P9-C assessment digest, P9-C manifest/principal/task/output identities, synthetic scheduler/job/executor identity, immutable code and configuration evidence, container/runtime evidence, exact secret leases, exact capabilities, and freshness bounds. Policy mutation is outside the attacker-controlled request surface for this milestone.

## Attacker-controlled or untrusted evidence

The execution manifest, launch request, scheduler/job fields, source revision/tree/entrypoint/config/lock digests, runtime image and environment settings, secret-lease evidence, capability evidence, and caller-declared summaries are treated as untrusted until verified against policy-owned pins.

## Fail-closed controls

`TrainingExecutionProvenanceAnalyzer` rejects malformed policy/manifests, manifest-digest mismatches, request/replay/freshness mismatches, and caller summaries that disagree with derived evidence. It denies execution when any of these evidence families diverge:

- P9-C decision, flags, schema/mode, assessment digest, admission identity, principal/task, or planned output identity;
- synthetic job ID, scheduler, namespace, queue, service account, executor principal, token audience, attempt, or launch nonce;
- repository, commit, tree, entrypoint, entrypoint digest, config digest, dependency-lock digest, or read-only source policy;
- remote fetches, dynamic dependency installation, or custom startup code;
- container image identity/digest, Python/framework/accelerator pins, privileged/host-network/privilege-escalation/docker-socket settings;
- exact environment-variable allowlist, network egress, writable paths, host-mount policy, or device profile;
- exact ordered secret IDs/provider versions/purposes/mount paths, narrow scopes, executor binding, lease validity, non-exportability, and denial of environment-variable injection; or
- exact ordered capabilities/resources/actions with no wildcard expansion.

The intentionally vulnerable baseline `VulnerableCallerDeclaredTrainingExecutionSafety` accepts caller-declared safety booleans instead of deriving these facts.

## Canonical synthetic execution

The fixture binds one training job to the exact P9-C clean assessment, one immutable source commit/tree/entrypoint/config/lock set, one pinned trainer image/runtime/device profile, three short-lived non-exportable secret leases, four explicit capabilities, restricted network egress, a read-only root filesystem, two writable workspace paths, and the exact P9-C planned adapter output identity.

## Evidence and claim boundary

P9-D SHA-256 and Git-object pins are deterministic synthetic integrity/provenance evidence. The fixture uses modeled scheduler, identity, secret-broker, network, filesystem, container, and GPU facts.

P9-D does **not** prove that a production scheduler launched the workload, that the synthetic identity came from a production identity provider, that secrets were delivered by a real secret manager, that a container/GPU runtime enforced the declared restrictions, that code/config/image evidence was cryptographically attested, that hardware isolation held, that the training loop executed, or that the resulting model/adapter is safe. Those remain future integration/assurance work.

## Focused validation

The focused P9-D harness executes the exact P9-D implementation/evaluator/test files against an API-compatible copy of the repository P9-C assessment dataclass contract. It is not a full-repository pytest or production-runtime claim.
