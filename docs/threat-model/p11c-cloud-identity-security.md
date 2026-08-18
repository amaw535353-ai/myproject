# P11-C provider-neutral cloud identity security

The trust chain is Kubernetes ServiceAccount token → TokenReview → derived workload principal → short-lived local credential → explicit-allow IAM → local KMS, encrypted secrets, and metadata capability. Caller-supplied tenant, namespace, ServiceAccount, role, permissions, and principal never override verified identity.

The deterministic lab attacks token binding, tenant isolation, privilege escalation, ciphertext/context integrity, key lifecycle, secret rotation, metadata capability binding, and audit integrity. The integrated scenario detects a compromised credential, fences its identity generation, rotates secret and KEK versions, rejects the old credential, establishes a replacement identity, and restores only the scoped safe operation.

Audit events contain identifiers, decisions, reason codes, and generations/versions; they exclude JWTs, credentials, keys, DEKs, KEKs, and plaintext secrets. Evidence is canonical SHA-256 bound and metrics derive from raw observations.

This is provider-neutral live-local validation. It does not validate AWS, GCP, Azure, real cloud federation, production IAM/KMS/secrets/metadata, HSM custody, multi-account/project behavior, or production cloud incident response.
