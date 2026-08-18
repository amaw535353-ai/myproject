# P11-D live-local deployed model-serving hardening

The public trust boundary is a real Kubernetes Ingress serving HTTPS with an ephemeral SAN-bound certificate. Only the gateway is routed. The gateway rejects caller-supplied internal identity and unsafe hop headers, binds requests to a synthetic authenticated principal and tenant, limits body size, rate, and concurrency, and sanitizes responses. It verifies the backend certificate and forwards through mTLS. The backend TLS boundary requires a locally trusted client certificate and the `gateway.p11d.internal` service identity.

The lifecycle boundary distinguishes process health from readiness. Draining removes eligibility for new work while an accepted request completes, reaches zero in-flight work, and permits a replacement pod to become ready. NetworkPolicy permits Traefik to gateway and gateway to backend while denying an unrelated attacker. Pods retain non-root, no-escalation, dropped-capability, read-only-root, seccomp, and resource-bound settings.

Runtime-generated CA and leaf private keys exist only in a temporary directory and Kubernetes Secrets inside the disposable cluster. Evidence contains certificate fingerprints, SANs, validity metadata, raw case outcomes, raw rate counts, and canonical hashes—not keys, credentials, payload secrets, or internal error details.

The lab uses one local K3s node, one gateway, one synthetic backend, and a local CA. It does not validate production ingress/load balancers, public PKI, certificate rotation operations, a production service mesh, multi-node or multi-zone availability, autoscaling, GPU/model servers, WAF/DDoS controls, or production SLOs.
