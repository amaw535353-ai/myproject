from __future__ import annotations

import re

from aegis.inference.incident_response_types import (
    ExitGateStatus,
    IncidentDecision,
    P10I_ASSESSMENT_MODE,
    P10I_ASSESSMENT_SCHEMA_VERSION,
    VerifiedInferenceIncidentResponseAssessment,
)
from aegis.platform.workload_security_types import *

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def _sha(value: str) -> bool:
    return bool(_HEX64.fullmatch(value or ""))


def _id(value: str) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 200 and value.strip() == value and "\x00" not in value


def _unique(values) -> bool:
    values = tuple(values)
    return len(values) == len(set(values))


def _same_sha(left: str, right: str) -> bool:
    return bool(left and right and left.casefold() == right.casefold())


def _upstream_ok(
    assessment: VerifiedInferenceIncidentResponseAssessment,
    expected_sha256: str,
) -> bool:
    positives = (
        assessment.upstream_p10h_bound,
        assessment.detection_verified,
        assessment.containment_verified,
        assessment.recovery_verified,
        assessment.forensic_chain_verified,
        assessment.phase10_exit_gate_verified,
        assessment.deferred_mastery_debt_carried,
    )
    nonclaims = (
        assessment.caller_declared_safety_trusted,
        assessment.production_soc_integrated,
        assessment.production_siem_integrated,
        assessment.production_orchestrator_remediation_validated,
        assessment.cross_zone_recovery_validated,
        assessment.hosted_ci_execution_verified,
        assessment.production_validation_claimed,
        assessment.professional_mastery_complete,
    )
    return (
        assessment.decision == IncidentDecision.ALLOW
        and not assessment.risks
        and assessment.exit_gate_status == ExitGateStatus.PASS_WITH_DEFERRED
        and all(positives)
        and not any(nonclaims)
        and assessment.assessment_schema_version == P10I_ASSESSMENT_SCHEMA_VERSION
        and assessment.assessment_mode == P10I_ASSESSMENT_MODE
        and _same_sha(assessment.assessment_evidence_sha256, expected_sha256)
    )


def validate_policy(p: PlatformWorkloadSecurityPolicy) -> None:
    if p.policy_version != P11A_POLICY_VERSION:
        reject(WorkloadRejectReason.POLICY_INVALID, "unexpected policy version")
    ids = (
        p.expected_manifest_id,
        p.expected_request_id,
        p.expected_tenant_id,
        p.expected_session_id,
        p.expected_target_model_id,
        p.expected_target_model_revision,
        p.expected_router_id,
        p.expected_workload_id,
        p.expected_namespace,
        p.expected_service_account,
        p.expected_pod_uid,
        p.expected_node_id,
        p.expected_runtime_class,
        p.expected_workload_identity_subject,
        p.expected_workload_identity_audience,
        p.expected_cgroup_mode,
        p.expected_user_namespace_mode,
        p.expected_lsm_mode,
        p.expected_device_access_mode,
    )
    if not all(_id(value) for value in ids):
        reject(WorkloadRejectReason.POLICY_INVALID, "invalid policy identifier")
    if not all(
        _sha(value)
        for value in (
            p.expected_manifest_sha256,
            p.expected_p10i_assessment_sha256,
            p.expected_p10i_manifest_sha256,
            p.expected_workload_token_sha256,
        )
    ):
        reject(WorkloadRejectReason.POLICY_INVALID, "invalid policy digest")
    seqs = (
        p.expected_adapter_ids,
        p.expected_container_ids,
        p.allowed_writable_paths,
        p.expected_secret_ids,
        p.expected_network_policy_ids,
        p.expected_ingress_peers,
        p.expected_egress_peers,
        p.expected_egress_ports,
        p.expected_rbac_binding_ids,
        p.allowed_rbac_verbs,
        p.allowed_rbac_resources,
        p.expected_image_refs,
        p.allowed_registries,
        p.required_deferred_mastery_items,
    )
    for values in seqs:
        if not values or not _unique(values):
            reject(WorkloadRejectReason.POLICY_INVALID, "invalid policy coverage")
    if not all(_id(value) for values in seqs if values and isinstance(values[0], str) for value in values):
        reject(WorkloadRejectReason.POLICY_INVALID, "invalid policy string coverage")
    if set(p.expected_image_ref_by_container) != set(p.expected_container_ids):
        reject(WorkloadRejectReason.POLICY_INVALID, "image-ref map coverage mismatch")
    if set(p.expected_image_digest_by_container) != set(p.expected_container_ids):
        reject(WorkloadRejectReason.POLICY_INVALID, "image-digest map coverage mismatch")
    if set(p.expected_secret_source_by_id) != set(p.expected_secret_ids):
        reject(WorkloadRejectReason.POLICY_INVALID, "secret source map coverage mismatch")
    if set(p.expected_secret_ref_by_id) != set(p.expected_secret_ids):
        reject(WorkloadRejectReason.POLICY_INVALID, "secret ref map coverage mismatch")
    if set(p.expected_secret_mount_path_by_id) != set(p.expected_secret_ids):
        reject(WorkloadRejectReason.POLICY_INVALID, "secret mount map coverage mismatch")
    if set(p.expected_secret_digest_by_id) != set(p.expected_secret_ids):
        reject(WorkloadRejectReason.POLICY_INVALID, "secret digest map coverage mismatch")
    if set(p.expected_rbac_role_by_id) != set(p.expected_rbac_binding_ids):
        reject(WorkloadRejectReason.POLICY_INVALID, "RBAC role map coverage mismatch")
    if not all(_sha(value) for value in p.expected_image_digest_by_container.values()):
        reject(WorkloadRejectReason.POLICY_INVALID, "invalid image digest pin")
    if not all(_sha(value) for value in p.expected_secret_digest_by_id.values()):
        reject(WorkloadRejectReason.POLICY_INVALID, "invalid secret digest pin")
    bounds = (
        p.expected_adapter_generation,
        p.minimum_router_generation,
        p.expected_run_as_user,
        p.expected_run_as_group,
        p.max_workload_token_ttl_seconds,
        p.max_secret_file_mode,
        p.max_critical_vulnerabilities,
        p.max_manifest_age_seconds,
        p.max_future_skew_seconds,
    )
    if any(value < 0 for value in bounds) or p.expected_run_as_user == 0 or p.expected_run_as_group == 0:
        reject(WorkloadRejectReason.POLICY_INVALID, "invalid policy bound")


def validate_manifest(m: PlatformWorkloadSecurityManifest) -> None:
    if m.schema_version != P11A_SCHEMA_VERSION:
        reject(WorkloadRejectReason.MANIFEST_INVALID, "unexpected schema")
    ids = (
        m.manifest_id,
        m.request_id,
        m.tenant_id,
        m.session_id,
        m.target_model_id,
        m.target_model_revision,
        m.router_id,
        m.identity.workload_id,
        m.identity.namespace,
        m.identity.tenant_id,
        m.identity.service_account,
        m.identity.pod_uid,
        m.identity.node_id,
        m.identity.runtime_class,
        m.identity.workload_identity_subject,
        m.identity.workload_identity_audience,
    )
    if not all(_id(value) for value in ids):
        reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid manifest identifier")
    if not all(_sha(value) for value in (m.p10i_assessment_sha256, m.p10i_manifest_sha256, m.identity.token_sha256)):
        reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid manifest digest")
    if min(
        m.created_at_epoch,
        m.adapter_generation,
        m.router_generation,
        m.identity.run_as_user,
        m.identity.run_as_group,
        m.identity.token_expiry_epoch,
        m.network_operations,
    ) < 0:
        reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid manifest numeric field")
    if not m.adapter_ids or not _unique(m.adapter_ids) or not all(_id(value) for value in m.adapter_ids):
        reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid adapter coverage")
    if not all((m.containers, m.secrets, m.network_policies, m.rbac_bindings, m.image_trust, m.deferred_mastery_items)):
        reject(WorkloadRejectReason.MANIFEST_INVALID, "empty workload evidence")
    if not _unique(item.container_id for item in m.containers):
        reject(WorkloadRejectReason.MANIFEST_INVALID, "duplicate container")
    if not _unique(item.secret_id for item in m.secrets):
        reject(WorkloadRejectReason.MANIFEST_INVALID, "duplicate secret")
    if not _unique(item.policy_id for item in m.network_policies):
        reject(WorkloadRejectReason.MANIFEST_INVALID, "duplicate network policy")
    if not _unique(item.binding_id for item in m.rbac_bindings):
        reject(WorkloadRejectReason.MANIFEST_INVALID, "duplicate RBAC binding")
    if not _unique(item.image_ref for item in m.image_trust):
        reject(WorkloadRejectReason.MANIFEST_INVALID, "duplicate image trust record")
    if not _unique(m.deferred_mastery_items) or not all(_id(value) for value in m.deferred_mastery_items):
        reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid deferred mastery coverage")
    for c in m.containers:
        strings = (
            c.container_id,
            c.container_name,
            c.image_ref,
            c.seccomp_profile,
            c.apparmor_profile,
            c.proc_mount,
        )
        if not all(_id(value) for value in strings) or not _sha(c.image_digest):
            reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid container evidence")
        if min(c.run_as_user, c.run_as_group) < 0:
            reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid container identity")
        for values in (c.host_path_mounts, c.added_capabilities, c.dropped_capabilities, c.writable_paths):
            if not _unique(values) or not all(_id(value) for value in values):
                reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid container coverage")
    for s in m.secrets:
        strings = (s.secret_id, s.workload_id, s.namespace, s.tenant_id, s.mount_path, s.source_kind, s.source_ref)
        if not all(_id(value) for value in strings) or not _sha(s.content_sha256):
            reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid secret evidence")
        if min(s.file_mode, s.owner_uid, s.owner_gid, s.rotation_epoch, s.expires_at_epoch) < 0:
            reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid secret numeric field")
    for n in m.network_policies:
        if not all(_id(value) for value in (n.policy_id, n.namespace, n.selector_workload_id)):
            reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid network policy")
        for values in (n.allowed_ingress_peers, n.allowed_egress_peers, n.allowed_egress_ports):
            if not _unique(values):
                reject(WorkloadRejectReason.MANIFEST_INVALID, "duplicate network policy entry")
        if not all(_id(value) for value in n.allowed_ingress_peers + n.allowed_egress_peers):
            reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid network peer")
        if any(port <= 0 or port > 65535 for port in n.allowed_egress_ports):
            reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid network port")
    for r in m.rbac_bindings:
        if not all(_id(value) for value in (r.binding_id, r.namespace, r.subject_service_account, r.role_name)):
            reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid RBAC evidence")
        for values in (r.verbs, r.resources, r.resource_names):
            if not values or not _unique(values) or not all(_id(value) for value in values):
                reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid RBAC rule")
    for image in m.image_trust:
        if not all(_id(value) for value in (image.image_ref, image.registry)):
            reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid image trust identifier")
        if not all(_sha(value) for value in (image.image_digest, image.signature_bundle_sha256, image.sbom_sha256, image.provenance_sha256)):
            reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid image trust digest")
        if image.critical_vulnerability_count < 0:
            reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid vulnerability count")
    runtime = m.runtime_boundary
    if not all(_id(value) for value in (runtime.runtime_class, runtime.cgroup_mode, runtime.user_namespace_mode, runtime.lsm_mode, runtime.device_access_mode)):
        reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid runtime boundary")
    if not _unique(runtime.host_socket_mounts) or not all(_id(value) for value in runtime.host_socket_mounts):
        reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid host socket coverage")
    if runtime.privileged_workloads_on_node < 0:
        reject(WorkloadRejectReason.MANIFEST_INVALID, "invalid privileged workload count")
