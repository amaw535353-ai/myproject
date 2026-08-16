from __future__ import annotations

from dataclasses import replace
import hashlib

from aegis.inference.incident_response_types import *
from aegis.platform.workload_security_types import *

NOW = 1_800_032_400
MANIFEST_ID = "p11a-platform-workload-001"
P10I_CLEAN_ASSESSMENT_SHA256 = "a34f4aa714000482cee8a1145878c3e4ee2878717392830fba999df6d07f328f"
P10I_MANIFEST_SHA256 = "70d6b823f0bb6fc5df1e81f15185af6fa05d86c3e243a7edc631061167496f11"
REQUEST_ID = "request-acme-0001"
TENANT_ID = "acme"
SESSION_ID = "tenant/acme/session/s-001"
TARGET_MODEL_ID = "aegisdesk-helpdesk-security"
TARGET_MODEL_REVISION = "rev-2026-08-p9h"
ADAPTER_IDS = ("adapter-security-policy", "adapter-acme-helpdesk")
ADAPTER_GENERATION = 12
ROUTER_ID = "router-inference-01"
ROUTER_GENERATION = 42
WORKLOAD_ID = "inference-workload-acme-001"
NAMESPACE = "tenant-acme-inference"
SERVICE_ACCOUNT = "aegisdesk-inference"
POD_UID = "pod-acme-inference-001"
NODE_ID = "worker-secure-01"
RUNTIME_CLASS = "default"
RUN_AS_USER = 20001
RUN_AS_GROUP = 20001
WORKLOAD_IDENTITY_SUBJECT = f"system:serviceaccount:{NAMESPACE}:{SERVICE_ACCOUNT}"
WORKLOAD_IDENTITY_AUDIENCE = "aegisdesk-inference-runtime"
CONTAINER_IDS = ("ctr-inference-001", "ctr-policy-sidecar-001")
IMAGE_DIGESTS = (
    hashlib.sha256(b"image:aegisdesk-inference:0.100.0").hexdigest(),
    hashlib.sha256(b"image:aegisdesk-policy-sidecar:0.100.0").hexdigest(),
)
IMAGE_REFS = (
    f"registry.example/aegisdesk/inference@sha256:{IMAGE_DIGESTS[0]}",
    f"registry.example/aegisdesk/policy-sidecar@sha256:{IMAGE_DIGESTS[1]}",
)
SECRET_IDS = ("secret-model-registry-token", "secret-workload-identity-token")
NETWORK_POLICY_IDS = ("netpol-inference-acme",)
INGRESS_PEERS = ("service:router-inference",)
EGRESS_PEERS = ("dns:kube-system", "service:policy-enforcer", "service:qdrant-acme")
EGRESS_PORTS = (53, 443, 6333)
RBAC_BINDING_IDS = ("rbac-runtime-config-reader",)
DEFERRED_MASTERY = (
    "p10f-live-nvidia-gpu-mig-cuda",
    "p11a-live-kubernetes-cluster",
)


def h(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def p10i_assessment() -> VerifiedInferenceIncidentResponseAssessment:
    return VerifiedInferenceIncidentResponseAssessment(
        "p10i-incident-response-001",
        P10I_MANIFEST_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        IncidentDecision.ALLOW,
        (),
        "05b72ff88bb41fa60bdea581b5ddd7fa49deb722f030e508b8d349344197d703",
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        ("partition-acme-mig-0", "partition-acme-exclusive-1"),
        "stream-acme-0001",
        ROUTER_ID,
        ROUTER_GENERATION,
        ("replica-inference-a", "replica-inference-b", "replica-inference-c"),
        ("route-acme-0001",),
        "incident-p10i-acme-0001",
        "replica-inference-a",
        ("signal-integrity-001", "signal-replay-002", "signal-tenant-003"),
        ("contain-fence-001", "contain-router-002", "contain-stream-003"),
        ("recover-replace-001", "recover-health-002", "recover-resume-003"),
        ("forensic-router-log-001", "forensic-health-002", "forensic-report-003"),
        ExitGateStatus.PASS_WITH_DEFERRED,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        False,
        P10I_ASSESSMENT_SCHEMA_VERSION,
        P10I_ASSESSMENT_MODE,
        P10I_CLEAN_ASSESSMENT_SHA256,
    )


def _identity() -> WorkloadIdentityEvidence:
    return WorkloadIdentityEvidence(
        WORKLOAD_ID,
        NAMESPACE,
        TENANT_ID,
        SERVICE_ACCOUNT,
        POD_UID,
        NODE_ID,
        RUNTIME_CLASS,
        RUN_AS_USER,
        RUN_AS_GROUP,
        (RUN_AS_GROUP,),
        WORKLOAD_IDENTITY_SUBJECT,
        WORKLOAD_IDENTITY_AUDIENCE,
        NOW + 300,
        h("projected-workload-identity-token:acme:v1"),
        False,
    )


def _containers() -> tuple[ContainerBoundaryEvidence, ...]:
    common = dict(
        run_as_non_root=True,
        run_as_user=RUN_AS_USER,
        run_as_group=RUN_AS_GROUP,
        privileged=False,
        allow_privilege_escalation=False,
        read_only_root_filesystem=True,
        host_network=False,
        host_pid=False,
        host_ipc=False,
        host_path_mounts=(),
        added_capabilities=(),
        dropped_capabilities=("ALL",),
        seccomp_profile="RuntimeDefault",
        apparmor_profile="runtime/default",
        proc_mount="Default",
    )
    return (
        ContainerBoundaryEvidence(
            CONTAINER_IDS[0],
            "inference",
            IMAGE_REFS[0],
            IMAGE_DIGESTS[0],
            writable_paths=("/tmp", "/var/run/aegisdesk"),
            **common,
        ),
        ContainerBoundaryEvidence(
            CONTAINER_IDS[1],
            "policy-sidecar",
            IMAGE_REFS[1],
            IMAGE_DIGESTS[1],
            writable_paths=("/tmp",),
            **common,
        ),
    )


def _secrets() -> tuple[SecretProjectionEvidence, ...]:
    return (
        SecretProjectionEvidence(
            SECRET_IDS[0],
            WORKLOAD_ID,
            NAMESPACE,
            TENANT_ID,
            "/var/run/secrets/model-registry/token",
            "kubernetes_secret_volume",
            "aegisdesk-model-registry-token",
            True,
            0o440,
            0,
            RUN_AS_GROUP,
            h("secret:model-registry-token:acme:v3"),
            NOW - 60,
            NOW + 3600,
        ),
        SecretProjectionEvidence(
            SECRET_IDS[1],
            WORKLOAD_ID,
            NAMESPACE,
            TENANT_ID,
            "/var/run/secrets/workload-identity/token",
            "projected_service_account_token",
            WORKLOAD_IDENTITY_AUDIENCE,
            True,
            0o440,
            0,
            RUN_AS_GROUP,
            h("projected-workload-identity-token:acme:v1"),
            NOW,
            NOW + 300,
        ),
    )


def _network() -> tuple[NetworkPolicyEvidence, ...]:
    return (
        NetworkPolicyEvidence(
            NETWORK_POLICY_IDS[0],
            NAMESPACE,
            WORKLOAD_ID,
            True,
            True,
            INGRESS_PEERS,
            EGRESS_PEERS,
            EGRESS_PORTS,
            True,
            False,
        ),
    )


def _rbac() -> tuple[RbacBindingEvidence, ...]:
    return (
        RbacBindingEvidence(
            RBAC_BINDING_IDS[0],
            NAMESPACE,
            SERVICE_ACCOUNT,
            "aegisdesk-runtime-config-reader",
            ("get",),
            ("configmaps",),
            ("aegisdesk-runtime-config",),
            False,
        ),
    )


def _images() -> tuple[ImageTrustEvidence, ...]:
    return tuple(
        ImageTrustEvidence(
            ref,
            digest,
            "registry.example",
            False,
            h(f"signature-bundle:{digest}"),
            h(f"sbom:{digest}"),
            h(f"provenance:{digest}"),
            0,
            True,
        )
        for ref, digest in zip(IMAGE_REFS, IMAGE_DIGESTS)
    )


def _runtime() -> RuntimeBoundaryEvidence:
    return RuntimeBoundaryEvidence(
        RUNTIME_CLASS,
        "cgroup-v2",
        "userns-remap",
        True,
        "apparmor",
        True,
        "none",
        (),
        True,
        0,
    )


def _manifest() -> PlatformWorkloadSecurityManifest:
    return PlatformWorkloadSecurityManifest(
        P11A_SCHEMA_VERSION,
        MANIFEST_ID,
        NOW,
        P10I_CLEAN_ASSESSMENT_SHA256,
        P10I_MANIFEST_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        ROUTER_ID,
        ROUTER_GENERATION,
        _identity(),
        _containers(),
        _secrets(),
        _network(),
        _rbac(),
        _images(),
        _runtime(),
        DEFERRED_MASTERY,
        0,
    )


def policy_for(m: PlatformWorkloadSecurityManifest) -> PlatformWorkloadSecurityPolicy:
    containers = {item.container_id: item for item in m.containers}
    secrets = {item.secret_id: item for item in m.secrets}
    return PlatformWorkloadSecurityPolicy(
        P11A_POLICY_VERSION,
        m.manifest_id,
        platform_workload_security_manifest_digest(m),
        P10I_CLEAN_ASSESSMENT_SHA256,
        P10I_MANIFEST_SHA256,
        REQUEST_ID,
        TENANT_ID,
        SESSION_ID,
        TARGET_MODEL_ID,
        TARGET_MODEL_REVISION,
        ADAPTER_IDS,
        ADAPTER_GENERATION,
        ROUTER_ID,
        ROUTER_GENERATION,
        WORKLOAD_ID,
        NAMESPACE,
        SERVICE_ACCOUNT,
        POD_UID,
        NODE_ID,
        RUNTIME_CLASS,
        RUN_AS_USER,
        RUN_AS_GROUP,
        (RUN_AS_GROUP,),
        WORKLOAD_IDENTITY_SUBJECT,
        WORKLOAD_IDENTITY_AUDIENCE,
        m.identity.token_sha256,
        600,
        CONTAINER_IDS,
        {key: value.image_ref for key, value in containers.items()},
        {key: value.image_digest for key, value in containers.items()},
        ("/tmp", "/var/run/aegisdesk"),
        SECRET_IDS,
        {key: value.source_kind for key, value in secrets.items()},
        {key: value.source_ref for key, value in secrets.items()},
        {key: value.mount_path for key, value in secrets.items()},
        {key: value.content_sha256 for key, value in secrets.items()},
        0o440,
        NETWORK_POLICY_IDS,
        INGRESS_PEERS,
        EGRESS_PEERS,
        EGRESS_PORTS,
        RBAC_BINDING_IDS,
        {item.binding_id: item.role_name for item in m.rbac_bindings},
        ("get",),
        ("configmaps",),
        IMAGE_REFS,
        ("registry.example",),
        0,
        "cgroup-v2",
        "userns-remap",
        "apparmor",
        "none",
        DEFERRED_MASTERY,
        300,
        5,
    )


def request_for(m: PlatformWorkloadSecurityManifest, *, safe: bool = True) -> PlatformWorkloadSecurityRequest:
    identity = m.identity
    return PlatformWorkloadSecurityRequest(
        m.manifest_id,
        platform_workload_security_manifest_digest(m),
        m.created_at_epoch + 30,
        m.tenant_id,
        identity.namespace,
        identity.workload_id,
        identity.service_account,
        True,
        safe,
        safe,
        safe,
        safe,
        safe,
        safe,
        safe,
        safe,
        True,
        safe,
    )


def build_fixture():
    m = _manifest()
    return {
        "manifest": m,
        "policy": policy_for(m),
        "request": request_for(m),
        "p10i": p10i_assessment(),
    }


def rebind(f, m, *, safe: bool | None = None, refresh_policy: bool = True):
    p = f["policy"]
    if refresh_policy:
        p = replace(p, expected_manifest_sha256=platform_workload_security_manifest_digest(m))
    if safe is None:
        safe = True
    return {"manifest": m, "policy": p, "request": request_for(m, safe=safe), "p10i": f["p10i"]}


def safe_delayed_evaluation_fixture():
    f = build_fixture()
    q = replace(f["request"], evaluated_at_epoch=f["manifest"].created_at_epoch + 120)
    return {**f, "request": q}


def safe_shorter_token_fixture():
    f = build_fixture()
    identity = replace(f["manifest"].identity, token_expiry_epoch=NOW + 180)
    m = replace(f["manifest"], identity=identity)
    return rebind(f, m)


def safe_reduced_writable_path_fixture():
    f = build_fixture()
    containers = list(f["manifest"].containers)
    containers[0] = replace(containers[0], writable_paths=("/tmp",))
    m = replace(f["manifest"], containers=tuple(containers))
    return rebind(f, m)
