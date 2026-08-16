from __future__ import annotations

from aegis.platform.workload_security_types import *
from aegis.platform.workload_security_validation import _same_sha, _sha, _upstream_ok, validate_manifest, validate_policy


class PlatformWorkloadSecurityAnalyzer:
    def __init__(self, policy: PlatformWorkloadSecurityPolicy):
        self.policy = policy
        validate_policy(policy)

    def evaluate(
        self,
        m: PlatformWorkloadSecurityManifest,
        q: PlatformWorkloadSecurityRequest,
        upstream: VerifiedInferenceIncidentResponseAssessment,
    ) -> VerifiedPlatformWorkloadSecurityAssessment:
        validate_manifest(m)
        p = self.policy
        manifest_sha = platform_workload_security_manifest_digest(m)
        if not _same_sha(manifest_sha, p.expected_manifest_sha256):
            reject(WorkloadRejectReason.MANIFEST_DIGEST_MISMATCH, "manifest digest mismatch")
        if q.manifest_id != m.manifest_id or not _same_sha(q.manifest_sha256, manifest_sha):
            reject(WorkloadRejectReason.REQUEST_INVALID, "request outer binding mismatch")
        if q.evaluated_at_epoch + p.max_future_skew_seconds < m.created_at_epoch:
            reject(WorkloadRejectReason.REQUEST_INVALID, "manifest is from the future")
        if q.evaluated_at_epoch - m.created_at_epoch > p.max_manifest_age_seconds:
            reject(WorkloadRejectReason.REQUEST_INVALID, "manifest too old")

        risks: list[WorkloadRisk] = []

        def add(risk: WorkloadRisk, bad: bool) -> None:
            if bad and risk not in risks:
                risks.append(risk)

        up = _upstream_ok(upstream, p.expected_p10i_assessment_sha256)
        add(WorkloadRisk.UPSTREAM_P10I_INVALID, not up)
        add(
            WorkloadRisk.UPSTREAM_BINDING_MISMATCH,
            not _same_sha(m.p10i_assessment_sha256, p.expected_p10i_assessment_sha256)
            or not _same_sha(m.p10i_manifest_sha256, p.expected_p10i_manifest_sha256)
            or not _same_sha(upstream.manifest_sha256, p.expected_p10i_manifest_sha256),
        )
        route = (
            m.request_id == p.expected_request_id == upstream.request_id
            and m.tenant_id == p.expected_tenant_id == upstream.tenant_id
            and m.session_id == p.expected_session_id == upstream.session_id
            and m.target_model_id == p.expected_target_model_id == upstream.target_model_id
            and m.target_model_revision == p.expected_target_model_revision == upstream.target_model_revision
            and m.adapter_ids == p.expected_adapter_ids == upstream.adapter_ids
            and m.adapter_generation == p.expected_adapter_generation == upstream.adapter_generation
            and m.router_id == p.expected_router_id == upstream.router_id
            and m.router_generation >= p.minimum_router_generation
            and m.router_generation == upstream.router_generation
        )
        add(WorkloadRisk.REQUEST_ROUTE_MISMATCH, not route)

        identity = m.identity
        identity_bound = (
            identity.workload_id == p.expected_workload_id
            and identity.namespace == p.expected_namespace
            and identity.service_account == p.expected_service_account
            and identity.pod_uid == p.expected_pod_uid
            and identity.node_id == p.expected_node_id
            and identity.runtime_class == p.expected_runtime_class
        )
        add(WorkloadRisk.WORKLOAD_IDENTITY_MISMATCH, not identity_bound)
        add(WorkloadRisk.WORKLOAD_TENANT_MISMATCH, identity.tenant_id != m.tenant_id or identity.tenant_id != p.expected_tenant_id)
        add(WorkloadRisk.SERVICE_ACCOUNT_MISMATCH, identity.service_account != p.expected_service_account)
        token_ok = (
            identity.run_as_user == p.expected_run_as_user
            and identity.run_as_group == p.expected_run_as_group
            and identity.run_as_user != 0
            and identity.run_as_group != 0
            and identity.supplemental_groups == p.expected_supplemental_groups
            and identity.workload_identity_subject == p.expected_workload_identity_subject
            and identity.workload_identity_audience == p.expected_workload_identity_audience
            and not identity.automount_service_account_token
            and _same_sha(identity.token_sha256, p.expected_workload_token_sha256)
            and identity.token_expiry_epoch > m.created_at_epoch
            and identity.token_expiry_epoch - m.created_at_epoch <= p.max_workload_token_ttl_seconds
        )
        add(WorkloadRisk.WORKLOAD_TOKEN_POLICY_MISMATCH, not token_ok)
        workload_identity = identity_bound and identity.tenant_id == m.tenant_id and token_ok

        container_ids = tuple(item.container_id for item in m.containers)
        add(WorkloadRisk.CONTAINER_COVERAGE_MISMATCH, container_ids != p.expected_container_ids)
        privilege_bad = False
        filesystem_bad = False
        for c in m.containers:
            add(
                WorkloadRisk.IMAGE_DIGEST_MISMATCH,
                p.expected_image_ref_by_container.get(c.container_id) != c.image_ref
                or not _same_sha(p.expected_image_digest_by_container.get(c.container_id, ""), c.image_digest),
            )
            root_bad = not c.run_as_non_root or c.run_as_user == 0 or c.run_as_group == 0 or c.run_as_user != p.expected_run_as_user or c.run_as_group != p.expected_run_as_group
            add(WorkloadRisk.ROOT_USER_UNSAFE, root_bad)
            add(WorkloadRisk.PRIVILEGED_CONTAINER, c.privileged)
            add(WorkloadRisk.PRIVILEGE_ESCALATION_ENABLED, c.allow_privilege_escalation)
            add(WorkloadRisk.ROOT_FILESYSTEM_WRITABLE, not c.read_only_root_filesystem)
            host_ns_bad = c.host_network or c.host_pid or c.host_ipc
            add(WorkloadRisk.HOST_NAMESPACE_EXPOSED, host_ns_bad)
            add(WorkloadRisk.HOST_PATH_MOUNTED, bool(c.host_path_mounts))
            caps_bad = bool(c.added_capabilities) or tuple(value.casefold() for value in c.dropped_capabilities) != ("all",)
            add(WorkloadRisk.CAPABILITY_POLICY_MISMATCH, caps_bad)
            add(WorkloadRisk.SECCOMP_POLICY_MISMATCH, c.seccomp_profile.casefold() != "runtimedefault".casefold())
            add(WorkloadRisk.LSM_POLICY_MISMATCH, c.apparmor_profile.casefold() != "runtime/default")
            add(WorkloadRisk.PROC_MOUNT_UNSAFE, c.proc_mount.casefold() != "default")
            writable_bad = not set(c.writable_paths).issubset(set(p.allowed_writable_paths))
            add(WorkloadRisk.WRITABLE_PATH_POLICY_MISMATCH, writable_bad)
            privilege_bad = privilege_bad or root_bad or c.privileged or c.allow_privilege_escalation or host_ns_bad or bool(c.host_path_mounts) or caps_bad
            filesystem_bad = filesystem_bad or (not c.read_only_root_filesystem) or writable_bad
        privilege_boundary = not any(
            risk in risks
            for risk in (
                WorkloadRisk.CONTAINER_COVERAGE_MISMATCH,
                WorkloadRisk.ROOT_USER_UNSAFE,
                WorkloadRisk.PRIVILEGED_CONTAINER,
                WorkloadRisk.PRIVILEGE_ESCALATION_ENABLED,
                WorkloadRisk.HOST_NAMESPACE_EXPOSED,
                WorkloadRisk.HOST_PATH_MOUNTED,
                WorkloadRisk.CAPABILITY_POLICY_MISMATCH,
                WorkloadRisk.SECCOMP_POLICY_MISMATCH,
                WorkloadRisk.LSM_POLICY_MISMATCH,
                WorkloadRisk.PROC_MOUNT_UNSAFE,
            )
        ) and not privilege_bad
        filesystem_boundary = not filesystem_bad and WorkloadRisk.CONTAINER_COVERAGE_MISMATCH not in risks

        secret_ids = tuple(item.secret_id for item in m.secrets)
        add(WorkloadRisk.SECRET_COVERAGE_MISMATCH, secret_ids != p.expected_secret_ids)
        for s in m.secrets:
            add(
                WorkloadRisk.SECRET_TENANT_MISMATCH,
                s.workload_id != identity.workload_id or s.namespace != identity.namespace or s.tenant_id != identity.tenant_id,
            )
            permission_bad = (
                not s.read_only
                or s.file_mode > p.max_secret_file_mode
                or bool(s.file_mode & 0o007)
                or bool(s.file_mode & 0o020)
                or s.owner_uid not in (0, p.expected_run_as_user)
                or s.owner_gid != p.expected_run_as_group
            )
            add(WorkloadRisk.SECRET_PERMISSION_UNSAFE, permission_bad)
            add(WorkloadRisk.SECRET_SOURCE_MISMATCH, p.expected_secret_source_by_id.get(s.secret_id) != s.source_kind or p.expected_secret_ref_by_id.get(s.secret_id) != s.source_ref or p.expected_secret_mount_path_by_id.get(s.secret_id) != s.mount_path)
            add(WorkloadRisk.SECRET_DIGEST_MISMATCH, not _same_sha(p.expected_secret_digest_by_id.get(s.secret_id, ""), s.content_sha256))
            rotation_bad = s.rotation_epoch > m.created_at_epoch or s.expires_at_epoch <= m.created_at_epoch or s.rotation_epoch > s.expires_at_epoch
            add(WorkloadRisk.SECRET_ROTATION_INVALID, rotation_bad)
        secret_projection = not any(
            risk in risks
            for risk in (
                WorkloadRisk.SECRET_COVERAGE_MISMATCH,
                WorkloadRisk.SECRET_TENANT_MISMATCH,
                WorkloadRisk.SECRET_PERMISSION_UNSAFE,
                WorkloadRisk.SECRET_SOURCE_MISMATCH,
                WorkloadRisk.SECRET_DIGEST_MISMATCH,
                WorkloadRisk.SECRET_ROTATION_INVALID,
            )
        )

        network_ids = tuple(item.policy_id for item in m.network_policies)
        add(WorkloadRisk.NETWORK_POLICY_COVERAGE_MISMATCH, network_ids != p.expected_network_policy_ids)
        for n in m.network_policies:
            add(WorkloadRisk.WORKLOAD_TENANT_MISMATCH, n.namespace != identity.namespace or n.selector_workload_id != identity.workload_id)
            add(WorkloadRisk.DEFAULT_DENY_MISSING, not n.default_deny_ingress or not n.default_deny_egress)
            add(WorkloadRisk.NETWORK_PEER_POLICY_MISMATCH, n.allowed_ingress_peers != p.expected_ingress_peers or n.allowed_egress_peers != p.expected_egress_peers)
            add(WorkloadRisk.NETWORK_PORT_POLICY_MISMATCH, n.allowed_egress_ports != p.expected_egress_ports)
            add(WorkloadRisk.CLOUD_METADATA_EXPOSED, not n.cloud_metadata_blocked)
            add(WorkloadRisk.KUBE_API_ACCESS_UNEXPECTED, n.kube_api_access_allowed)
        network_policy = not any(
            risk in risks
            for risk in (
                WorkloadRisk.NETWORK_POLICY_COVERAGE_MISMATCH,
                WorkloadRisk.DEFAULT_DENY_MISSING,
                WorkloadRisk.NETWORK_PEER_POLICY_MISMATCH,
                WorkloadRisk.NETWORK_PORT_POLICY_MISMATCH,
                WorkloadRisk.CLOUD_METADATA_EXPOSED,
                WorkloadRisk.KUBE_API_ACCESS_UNEXPECTED,
            )
        )

        rbac_ids = tuple(item.binding_id for item in m.rbac_bindings)
        add(WorkloadRisk.RBAC_COVERAGE_MISMATCH, rbac_ids != p.expected_rbac_binding_ids)
        for r in m.rbac_bindings:
            add(WorkloadRisk.RBAC_SUBJECT_MISMATCH, r.namespace != identity.namespace or r.subject_service_account != identity.service_account)
            add(WorkloadRisk.RBAC_CLUSTER_SCOPE, r.cluster_scope)
            add(WorkloadRisk.RBAC_ROLE_MISMATCH, p.expected_rbac_role_by_id.get(r.binding_id) != r.role_name)
            wildcard = "*" in r.verbs or "*" in r.resources or "*" in r.resource_names
            add(WorkloadRisk.RBAC_WILDCARD, wildcard)
            add(WorkloadRisk.RBAC_VERB_EXCESS, not set(r.verbs).issubset(set(p.allowed_rbac_verbs)))
            add(WorkloadRisk.RBAC_RESOURCE_EXCESS, not set(r.resources).issubset(set(p.allowed_rbac_resources)))
        rbac = not any(
            risk in risks
            for risk in (
                WorkloadRisk.RBAC_COVERAGE_MISMATCH,
                WorkloadRisk.RBAC_SUBJECT_MISMATCH,
                WorkloadRisk.RBAC_CLUSTER_SCOPE,
                WorkloadRisk.RBAC_ROLE_MISMATCH,
                WorkloadRisk.RBAC_WILDCARD,
                WorkloadRisk.RBAC_VERB_EXCESS,
                WorkloadRisk.RBAC_RESOURCE_EXCESS,
            )
        )

        image_refs = tuple(item.image_ref for item in m.image_trust)
        add(WorkloadRisk.IMAGE_TRUST_COVERAGE_MISMATCH, image_refs != p.expected_image_refs)
        image_by_ref = {item.image_ref: item for item in m.image_trust}
        for c in m.containers:
            trust = image_by_ref.get(c.image_ref)
            add(WorkloadRisk.IMAGE_TRUST_COVERAGE_MISMATCH, trust is None)
            if trust is None:
                continue
            add(WorkloadRisk.IMAGE_DIGEST_MISMATCH, not _same_sha(c.image_digest, trust.image_digest))
            add(WorkloadRisk.MUTABLE_IMAGE_TAG, trust.mutable_tag_used or "@sha256:" not in trust.image_ref)
            add(WorkloadRisk.IMAGE_SIGNATURE_EVIDENCE_MISMATCH, not _sha(trust.signature_bundle_sha256))
            add(WorkloadRisk.IMAGE_SBOM_MISMATCH, not _sha(trust.sbom_sha256))
            add(WorkloadRisk.IMAGE_PROVENANCE_MISMATCH, not _sha(trust.provenance_sha256))
            add(WorkloadRisk.CRITICAL_VULNERABILITY_PRESENT, trust.critical_vulnerability_count > p.max_critical_vulnerabilities)
            add(WorkloadRisk.ADMISSION_EVIDENCE_MISSING, not trust.admission_verified or trust.registry not in p.allowed_registries)
        image_supply_chain = not any(
            risk in risks
            for risk in (
                WorkloadRisk.IMAGE_TRUST_COVERAGE_MISMATCH,
                WorkloadRisk.IMAGE_DIGEST_MISMATCH,
                WorkloadRisk.MUTABLE_IMAGE_TAG,
                WorkloadRisk.IMAGE_SIGNATURE_EVIDENCE_MISMATCH,
                WorkloadRisk.IMAGE_SBOM_MISMATCH,
                WorkloadRisk.IMAGE_PROVENANCE_MISMATCH,
                WorkloadRisk.CRITICAL_VULNERABILITY_PRESENT,
                WorkloadRisk.ADMISSION_EVIDENCE_MISSING,
            )
        )

        runtime = m.runtime_boundary
        add(WorkloadRisk.RUNTIME_CLASS_MISMATCH, runtime.runtime_class != p.expected_runtime_class)
        add(WorkloadRisk.CGROUP_POLICY_MISMATCH, runtime.cgroup_mode != p.expected_cgroup_mode)
        add(WorkloadRisk.USER_NAMESPACE_POLICY_MISMATCH, runtime.user_namespace_mode != p.expected_user_namespace_mode or not runtime.rootless_or_userns_remap)
        add(WorkloadRisk.RUNTIME_SECCOMP_DEFAULT_MISSING, not runtime.seccomp_default)
        add(WorkloadRisk.RUNTIME_LSM_MISSING, runtime.lsm_mode != p.expected_lsm_mode)
        add(WorkloadRisk.DEVICE_ACCESS_UNSAFE, runtime.device_access_mode != p.expected_device_access_mode)
        add(WorkloadRisk.HOST_SOCKET_EXPOSED, bool(runtime.host_socket_mounts))
        add(WorkloadRisk.PTRACE_POLICY_UNSAFE, not runtime.ptrace_restricted)
        add(WorkloadRisk.NODE_PRIVILEGED_COLOCATION, runtime.privileged_workloads_on_node != 0)
        runtime_boundary = not any(
            risk in risks
            for risk in (
                WorkloadRisk.RUNTIME_CLASS_MISMATCH,
                WorkloadRisk.CGROUP_POLICY_MISMATCH,
                WorkloadRisk.USER_NAMESPACE_POLICY_MISMATCH,
                WorkloadRisk.RUNTIME_SECCOMP_DEFAULT_MISSING,
                WorkloadRisk.RUNTIME_LSM_MISSING,
                WorkloadRisk.DEVICE_ACCESS_UNSAFE,
                WorkloadRisk.HOST_SOCKET_EXPOSED,
                WorkloadRisk.PTRACE_POLICY_UNSAFE,
                WorkloadRisk.NODE_PRIVILEGED_COLOCATION,
            )
        )

        debt_carried = m.deferred_mastery_items == p.required_deferred_mastery_items and upstream.deferred_mastery_debt_carried
        add(WorkloadRisk.DEFERRED_MASTERY_DEBT_DROPPED, not debt_carried)
        add(WorkloadRisk.NETWORK_OPERATION_UNEXPECTED, m.network_operations != 0)

        declared = (
            q.declared_tenant_id == m.tenant_id,
            q.declared_namespace == identity.namespace,
            q.declared_workload_id == identity.workload_id,
            q.declared_service_account == identity.service_account,
            q.declared_upstream_p10i_bound == up,
            q.declared_workload_identity_verified == workload_identity,
            q.declared_privilege_boundary_verified == privilege_boundary,
            q.declared_filesystem_boundary_verified == filesystem_boundary,
            q.declared_secret_projection_verified == secret_projection,
            q.declared_network_policy_verified == network_policy,
            q.declared_rbac_verified == rbac,
            q.declared_image_supply_chain_verified == image_supply_chain,
            q.declared_runtime_boundary_verified == runtime_boundary,
            q.declared_gpu_debt_carried == debt_carried,
        )
        safe = not risks
        if not all(declared) or q.declared_workload_security_safe != safe:
            reject(WorkloadRejectReason.DECLARED_SUMMARY_MISMATCH, "caller summary disagrees with evidence")

        decision = PlatformDecision.ALLOW if safe else PlatformDecision.DENY
        evidence_sha = digest_json(
            {
                "manifest_sha256": manifest_sha,
                "request_id": m.request_id,
                "tenant_id": m.tenant_id,
                "namespace": identity.namespace,
                "workload_id": identity.workload_id,
                "container_ids": container_ids,
                "risks": tuple(item.value for item in risks),
                "decision": decision.value,
                "assessment_schema_version": P11A_ASSESSMENT_SCHEMA_VERSION,
                "assessment_mode": P11A_ASSESSMENT_MODE,
            }
        )
        return VerifiedPlatformWorkloadSecurityAssessment(
            m.manifest_id,
            manifest_sha,
            m.request_id,
            m.tenant_id,
            m.session_id,
            decision,
            tuple(risks),
            m.p10i_assessment_sha256,
            m.p10i_manifest_sha256,
            m.target_model_id,
            m.target_model_revision,
            m.adapter_ids,
            m.adapter_generation,
            m.router_id,
            m.router_generation,
            identity.workload_id,
            identity.namespace,
            identity.service_account,
            container_ids,
            tuple(c.image_ref for c in m.containers),
            up,
            workload_identity,
            privilege_boundary,
            filesystem_boundary,
            secret_projection,
            network_policy,
            rbac,
            image_supply_chain,
            runtime_boundary,
            debt_carried,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            P11A_ASSESSMENT_SCHEMA_VERSION,
            P11A_ASSESSMENT_MODE,
            evidence_sha,
        )
