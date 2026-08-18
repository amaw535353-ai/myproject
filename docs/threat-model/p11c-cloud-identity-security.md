# P11-C provider-neutral cloud identity security

The live-local trust chain is a real K3s ServiceAccount token → Kubernetes TokenReview → verified workload principal with API-derived cluster identity and actual token expiry → short-lived local broker credential → explicit-allow IAM → local KMS, encrypted secrets, and metadata capability. The exact broker credential issued from the reviewed token drives each control-plane service. Caller-supplied tenant, namespace, ServiceAccount, role, permissions, and principal never override verified identity.

The deterministic lab separately uses cryptographically signed synthetic tokens to attack token binding, tenant isolation, privilege escalation, ciphertext/context integrity, key lifecycle, secret rotation, metadata capability binding, and audit integrity. Synthetic identities cannot satisfy the live gate.

The live integrated scenario detects compromise of the Kubernetes-derived broker credential, fences its identity generation, rotates secret and KEK versions, and rejects the old credential. Recovery requests a new Kubernetes ServiceAccount token, submits it to TokenReview, issues a newer-generation broker credential for the same intended principal, and restores only the scoped safe operation.

Audit events contain identifiers, decisions, reason codes, and generations/versions; they exclude JWTs, credentials, keys, DEKs, KEKs, and plaintext secrets. Evidence is canonical SHA-256 bound and metrics derive from raw observations.

This is provider-neutral live-local validation. It does not validate AWS, GCP, Azure, real cloud federation, production IAM/KMS/secrets/metadata, HSM custody, multi-account/project behavior, or production cloud incident response.
