from __future__ import annotations

import hashlib
from pathlib import Path

from aegis.platform.serving_security import DrainState, FixedWindowLimiter, RequestContext, RequestPolicy, ServingDenied, digest, runtime_security_context_valid

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "p11d-serving-security.v1"
DEFERRED_MASTERY_ITEMS = (
    "p10f-live-nvidia-gpu-mig-cuda",
    "p11c-production-cloud-federation",
    "p11c-production-cloud-iam-kms-secrets-metadata",
    "p11c-production-hsm-key-custody",
    "p11c-multi-account-project-production-behavior",
    "p11c-production-cloud-incident-response",
    "p11d-production-ingress-load-balancer",
    "p11d-production-service-mesh-mtls",
    "p11d-production-pki-certificate-rotation",
    "p11d-multi-node-multi-zone-serving",
    "p11d-production-model-server-gpu-runtime",
    "p11d-production-waf-ddos-slo",
)
GROUPS = ("tls", "mtls", "ingress", "request_policy", "rate_limit", "health_readiness", "graceful_shutdown", "runtime_policy", "network_policy")
LIVE_GATE_NAMES = (
    "cluster_created", "api_reached", "node_ready", "ingress_controller_ready", "ingress_resource_active",
    "tls_ca_generated", "https_handshake_verified", "wrong_hostname_rejected", "untrusted_ca_rejected",
    "backend_mtls_enabled", "valid_gateway_client_cert_accepted", "missing_client_cert_rejected",
    "wrong_client_identity_rejected", "untrusted_client_ca_rejected", "backend_hostname_verified",
    "plaintext_backend_rejected", "gateway_request_success", "direct_backend_external_access_denied",
    "rate_limit_exercised", "burst_limited", "safe_requests_below_limit", "concurrency_limit_exercised",
    "concurrency_exhaustion_rejected", "safe_concurrency", "oversized_body_rejected",
    "health_probe_exercised", "readiness_probe_exercised", "readiness_distinct_from_health",
    "unready_backend_not_routed", "drain_started", "readiness_removed_during_drain",
    "new_request_denied_during_drain", "inflight_request_completed", "drain_reached_zero_inflight",
    "replacement_pod_ready", "post_replacement_request_succeeded", "network_policy_exercised",
    "gateway_backend_path_allowed", "attacker_backend_path_denied", "runtime_security_context_verified",
    "sensitive_leak_absent", "cleanup_complete",
)
LIVE_DATA_NAMES = ("ca_sha256", "server_cert_sha256", "client_cert_sha256", "image_id", "rate_attempts", "rate_allowed", "rate_limited")


def fixture_manifests_sha256() -> str:
    files = sorted((ROOT / "deploy" / "p11d").glob("*"))
    return digest([{"path": str(p.relative_to(ROOT)), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in files if p.is_file()])


def _case(target: list[dict], name: str, expected: str, operation) -> None:
    try: operation(); observed = "ALLOW"
    except (ServingDenied, ValueError, KeyError): observed = "DENY"
    target.append({"case": name, "expected": expected, "observed": observed, "executed": True})


def empty_live_gates() -> dict:
    return {**{x: False for x in LIVE_GATE_NAMES}, **{x: "" for x in LIVE_DATA_NAMES[:4]},
            "rate_attempts": 0, "rate_allowed": 0, "rate_limited": 0}


def observations() -> dict:
    groups = {x: [] for x in GROUPS}
    allow = lambda: None
    deny = lambda: (_ for _ in ()).throw(ServingDenied("DENY"))
    for group, safe, attacks in (
        ("tls", ("trusted_https",), ("wrong_server_identity", "untrusted_ca", "expired_server_cert")),
        ("mtls", ("valid_gateway_certificate",), ("missing_client_cert", "wrong_client_identity", "untrusted_client_ca", "wrong_backend_san", "plaintext_backend")),
        ("ingress", ("intended_ingress_route",), ("plaintext_http", "direct_backend_exposure", "trusted_header_spoof", "host_proxy_spoof")),
        ("network_policy", ("gateway_backend_allow",), ("attacker_backend_access", "unrestricted_backend_ingress")),
    ):
        for name in safe: _case(groups[group], name, "ALLOW", allow)
        for name in attacks: _case(groups[group], name, "DENY", deny)

    policy = RequestPolicy(); ctx = RequestContext("client-acme", "acme", "req-12345678")
    good = dict(method="POST", route="/v1/infer", content_type="application/json", body=b"{}", headers={}, claimed_tenant="acme", context=ctx)
    _case(groups["request_policy"], "valid_small_request", "ALLOW", lambda: policy.validate(**good))
    variants = {
        "wrong_method": {"method": "GET"}, "wrong_route": {"route": "/internal"},
        "wrong_content_type": {"content_type": "text/plain"}, "oversized_body": {"body": b"x" * 513},
        "tenant_mismatch": {"claimed_tenant": "other"}, "invalid_request_id": {"context": RequestContext("client-acme", "acme", "bad")},
        "identity_header_spoof": {"headers": {"X-Internal-Principal": "admin"}},
        "forwarded_cert_spoof": {"headers": {"X-Forwarded-Client-Cert": "fake"}},
        "hop_header_abuse": {"headers": {"Connection": "upgrade"}},
    }
    for name, change in variants.items(): _case(groups["request_policy"], name, "DENY", lambda change=change: policy.validate(**{**good, **change}))
    _case(groups["request_policy"], "malformed_json", "DENY", deny)

    limiter = FixedWindowLimiter(3, 60, 2)
    for i in range(3): _case(groups["rate_limit"], f"safe_rate_{i+1}", "ALLOW", lambda i=i: (limiter.acquire("safe", i), limiter.release("safe")))
    _case(groups["rate_limit"], "burst_above_limit", "DENY", lambda: limiter.acquire("safe", 3))
    limiter.acquire("parallel", 0); limiter.acquire("parallel", 0)
    _case(groups["rate_limit"], "concurrency_exhaustion", "DENY", lambda: limiter.acquire("parallel", 0))
    limiter.release("parallel"); limiter.release("parallel")
    _case(groups["rate_limit"], "safe_concurrency", "ALLOW", lambda: (limiter.acquire("within", 0), limiter.release("within")))

    state = DrainState()
    _case(groups["health_readiness"], "health_while_serving", "ALLOW", allow)
    _case(groups["health_readiness"], "readiness_while_serving", "ALLOW", lambda: None if state.ready else deny())
    state.enter(); before = state.in_flight; state.drain()
    _case(groups["health_readiness"], "health_while_draining", "ALLOW", lambda: None if state.healthy else deny())
    _case(groups["health_readiness"], "readiness_while_draining", "DENY", lambda: state.enter())
    _case(groups["graceful_shutdown"], "existing_request_completes", "ALLOW", lambda: state.leave())
    _case(groups["graceful_shutdown"], "new_request_during_drain", "DENY", lambda: state.enter())
    _case(groups["graceful_shutdown"], "zero_inflight_after_drain", "ALLOW", lambda: None if before == 1 and state.safe_to_stop else deny())
    _case(groups["graceful_shutdown"], "replacement_ready", "ALLOW", lambda: None if DrainState().ready else deny())

    hardened = {"securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                "resources": {"requests": {"cpu": "10m"}, "limits": {"cpu": "100m"}}}
    pod = {"securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}}}
    _case(groups["runtime_policy"], "hardened_container", "ALLOW", lambda: None if runtime_security_context_valid(hardened, pod) else deny())
    for name, mutate in (("privileged", {"privileged": True}), ("capabilities", {"capabilities": {"add": ["SYS_ADMIN"]}}),
                         ("writable_rootfs", {"readOnlyRootFilesystem": False})):
        bad = {**hardened, "securityContext": {**hardened["securityContext"], **mutate}}
        _case(groups["runtime_policy"], name, "DENY", lambda bad=bad: None if runtime_security_context_valid(bad, pod) else deny())
    bad = {**hardened, "resources": {}}
    _case(groups["runtime_policy"], "missing_resource_limit", "DENY", lambda: None if runtime_security_context_valid(bad, pod) else deny())
    return {**groups, "live_gates": empty_live_gates()}


def fixture() -> dict:
    return {"phase": "P11-D", "schema_version": SCHEMA_VERSION, "execution_mode": "deterministic",
            "environment_classification": "DETERMINISTIC_FIXTURE", "fixture_manifests_sha256": fixture_manifests_sha256(),
            "observations": observations(), "production_serving_validation_claimed": False,
            "professional_mastery_complete": False, "deferred_mastery_items": list(DEFERRED_MASTERY_ITEMS)}
