# P11-D live-local serving lab

The runner builds a local pinned-tag Python image, creates one K3s server with bundled Traefik, generates ephemeral PKI, and dynamically creates Kubernetes Secrets. The external path is trusted HTTPS through a real Ingress to the gateway; the internal path uses authenticated TLS from gateway to backend. NetworkPolicy and Restricted-compatible security contexts bound the workloads. No key, token, or synthetic secret is committed or recorded in evidence.
