# P11-C provider-neutral live-local identity lab

The runner creates one pinned local K3s server, obtains short-lived ServiceAccount tokens with `kubectl create token`, and submits them to the Kubernetes TokenReview API with the broker audience. Tokens remain in memory and are never written to evidence or logs. IAM, envelope encryption, secrets, metadata capabilities, auditing, containment, rotation, and recovery execute locally with synthetic data.
