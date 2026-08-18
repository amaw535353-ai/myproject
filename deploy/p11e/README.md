# P11-E live-local supply-chain lab

The runner creates this namespace and its admission resources dynamically because
the webhook PKI, receipt verification key, image digest, and local-registry name
are ephemeral. No signing or TLS private key is stored in this directory.

The protected namespace is fail-closed by a narrowly scoped validating admission
webhook. It accepts only immutable image references carrying a fresh signed
receipt bound to SBOM, scanner report, provenance, signer, and policy metadata.
