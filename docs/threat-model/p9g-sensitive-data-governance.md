# P9-G threat model — sensitive-data, PII, secret, and canary governance

## Security boundary

P9-G consumes the exact P9-F assessment identity and adds deterministic evidence for sensitive-data handling across modeled training inputs, evaluation inputs, and model outputs. The policy, scanner-profile digest, canary-registry digest, expected record set, finding digests, dispositions, and inclusion decisions are trusted inputs outside the modeled attacker compromise.

## Adversary capabilities

The attacker may substitute upstream assessment evidence, alter record content or sanitized-content digests, change data-surface labels, remove or forge findings, downgrade classifications, alter redaction/quarantine dispositions, force quarantined training records into the included set, reproduce modeled PII/secrets/canaries in outputs, replace the output batch, add modeled network operations, replay stale requests, or lie in caller-declared safety summaries.

## Enforced invariants

The hardened analyzer binds exact P9-F/evaluation/checkpoint identity, scanner and canary-registry profiles, record order and digests, finding IDs and evidence digests, sensitivity classification, policy-owned disposition, training inclusion, exact output identity/batch digest, and zero modeled network operations. PII in modeled input records must be deterministically redacted before inclusion; modeled secrets and canaries must be quarantined; any modeled sensitive finding in outputs fails closed.

## Claim boundary

This is deterministic synthetic governance evidence, not a production DLP/privacy proof. Exact rule/fingerprint evidence does not establish comprehensive PII or secret detection, legal/consent/license compliance, cryptographic scanner authenticity, differential privacy, membership-inference resistance, memorization absence, production redaction enforcement, or proof that a real model generated the modeled outputs.
