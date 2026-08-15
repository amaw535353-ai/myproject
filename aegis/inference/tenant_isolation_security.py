from __future__ import annotations
import re
from .tenant_isolation_types import *

_SHA=re.compile(r'^[0-9a-fA-F]{64}$'); _ID=re.compile(r'^[a-z0-9][a-z0-9._:/@-]{2,127}$')
_MUTABLE={'latest','stable','current','prod','production','default','main'}

class InferenceTenantIsolationAnalyzer:
    def __init__(self,policy:InferenceTenantIsolationPolicy): self.policy=policy; self._validate_policy()
    @staticmethod
    def _sha(v): return bool(_SHA.fullmatch(str(v)))
    @staticmethod
    def _id(v): return bool(_ID.fullmatch(str(v)))
    def _validate_policy(self):
        p=self.policy
        if p.policy_version!=P10A_POLICY_VERSION: reject(InferenceRejectReason.POLICY_INVALID,'unexpected policy version')
        ids=(p.expected_manifest_id,p.expected_deployment_attestation_id,p.expected_deployment_id,p.expected_endpoint_id,p.expected_model_id,p.expected_revision,p.expected_adapter_id,p.expected_draft_model_id,p.expected_draft_revision)
        if not all(map(self._id,ids)): reject(InferenceRejectReason.POLICY_INVALID,'policy identity pins are invalid')
        digs=(p.expected_manifest_sha256,p.expected_deployment_attestation_sha256,p.expected_p9h_promotion_assessment_sha256,p.expected_model_artifact_sha256,p.expected_tokenizer_sha256,p.expected_adapter_sha256,p.expected_draft_model_artifact_sha256,p.expected_prior_request_ledger_sha256,*p.expected_authorization_context_sha256_by_tenant.values())
        if not all(map(self._sha,digs)): reject(InferenceRejectReason.POLICY_INVALID,'policy digest pins must be SHA-256')
        if not p.allowed_tenant_ids or len(p.allowed_tenant_ids)!=len(set(p.allowed_tenant_ids)): reject(InferenceRejectReason.POLICY_INVALID,'tenant allowlist invalid')
        if set(p.allowed_principal_ids_by_tenant)!=set(p.allowed_tenant_ids) or set(p.expected_authorization_context_sha256_by_tenant)!=set(p.allowed_tenant_ids): reject(InferenceRejectReason.POLICY_INVALID,'tenant policy maps incomplete')
        for t in p.allowed_tenant_ids:
            principals=p.allowed_principal_ids_by_tenant[t]
            if not self._id(t) or not principals or len(principals)!=len(set(principals)) or not all(map(self._id,principals)): reject(InferenceRejectReason.POLICY_INVALID,'tenant/principal allowlist invalid')
        if not p.allowed_scheduler_ids or len(p.allowed_scheduler_ids)!=len(set(p.allowed_scheduler_ids)): reject(InferenceRejectReason.POLICY_INVALID,'scheduler allowlist invalid')
        if p.expected_revision.casefold() in _MUTABLE or p.expected_draft_revision.casefold() in _MUTABLE: reject(InferenceRejectReason.POLICY_INVALID,'model revisions must be immutable')
        if min(p.max_sequence_no,p.max_manifest_age_seconds,p.max_future_skew_seconds)<0: reject(InferenceRejectReason.POLICY_INVALID,'policy bounds invalid')
    def _validate_manifest(self,m:InferenceTenantIsolationManifest):
        if m.schema_version!=P10A_SCHEMA_VERSION: reject(InferenceRejectReason.MANIFEST_INVALID,'unexpected inference manifest schema')
        if not self._id(m.manifest_id) or not self._id(m.deployment_attestation_id) or m.manifest_id!=self.policy.expected_manifest_id or m.created_at_epoch<=0: reject(InferenceRejectReason.MANIFEST_INVALID,'manifest identity/time invalid')
        if not self._sha(m.deployment_attestation_sha256) or not self._sha(m.p9h_promotion_assessment_sha256): reject(InferenceRejectReason.MANIFEST_INVALID,'upstream digest malformed')
        r=m.route
        if not all(map(self._id,(r.deployment_id,r.endpoint_id,r.model_id,r.revision,r.adapter_id,r.draft_model_id,r.draft_revision))) or not all(map(self._sha,(r.model_artifact_sha256,r.tokenizer_sha256,r.adapter_sha256,r.draft_model_artifact_sha256))): reject(InferenceRejectReason.MANIFEST_INVALID,'route evidence malformed')
        q=m.request_identity
        if not all(map(self._id,(q.request_id,q.tenant_id,q.principal_id,q.session_id,q.conversation_id))) or min(q.sequence_no,q.session_epoch)<0 or not all(map(self._sha,(q.nonce_sha256,q.authorization_context_sha256))): reject(InferenceRejectReason.MANIFEST_INVALID,'request evidence malformed')
        b=m.batch
        if not all(map(self._id,(b.batch_id,b.scheduler_id,b.partition_key))) or not b.request_ids or not b.tenant_ids: reject(InferenceRejectReason.MANIFEST_INVALID,'batch evidence malformed')
        c=m.cache
        if not all(map(self._id,(c.kv_cache_namespace,c.kv_cache_owner_tenant_id,c.kv_cache_session_id,c.prefix_cache_namespace,c.prefix_cache_owner_tenant_id))) or c.kv_cache_epoch<0 or not self._sha(c.prefix_cache_key_sha256): reject(InferenceRejectReason.MANIFEST_INVALID,'cache evidence malformed')
        o=m.output
        if not all(map(self._id,(o.output_channel_id,o.recipient_tenant_id,o.recipient_session_id,o.response_object_id))): reject(InferenceRejectReason.MANIFEST_INVALID,'output evidence malformed')
        if len(m.prior_request_ids)!=len(set(m.prior_request_ids)) or not all(map(self._id,m.prior_request_ids)) or not self._sha(m.prior_request_ledger_sha256) or m.network_operations<0: reject(InferenceRejectReason.MANIFEST_INVALID,'ledger/network evidence malformed')
    def derive(self,m:InferenceTenantIsolationManifest):
        self._validate_manifest(m); p=self.policy; R=set(); r=m.route; q=m.request_identity; b=m.batch; c=m.cache; o=m.output
        if m.deployment_attestation_id!=p.expected_deployment_attestation_id or m.deployment_attestation_sha256.casefold()!=p.expected_deployment_attestation_sha256.casefold(): R.add(InferenceRisk.UPSTREAM_DEPLOYMENT_BINDING_MISMATCH)
        if m.p9h_promotion_assessment_sha256.casefold()!=p.expected_p9h_promotion_assessment_sha256.casefold(): R.add(InferenceRisk.UPSTREAM_PROMOTION_BINDING_MISMATCH)
        if (r.deployment_id,r.endpoint_id,r.model_id,r.revision)!=(p.expected_deployment_id,p.expected_endpoint_id,p.expected_model_id,p.expected_revision) or r.model_artifact_sha256.casefold()!=p.expected_model_artifact_sha256.casefold() or r.tokenizer_sha256.casefold()!=p.expected_tokenizer_sha256.casefold(): R.add(InferenceRisk.ROUTE_IDENTITY_MISMATCH)
        if r.revision.casefold() in _MUTABLE or r.draft_revision.casefold() in _MUTABLE: R.add(InferenceRisk.MUTABLE_ROUTE_UNSAFE)
        if q.tenant_id not in p.allowed_tenant_ids or q.principal_id not in p.allowed_principal_ids_by_tenant.get(q.tenant_id,()): R.add(InferenceRisk.REQUEST_IDENTITY_MISMATCH)
        elif q.authorization_context_sha256.casefold()!=p.expected_authorization_context_sha256_by_tenant[q.tenant_id].casefold(): R.add(InferenceRisk.AUTHORIZATION_CONTEXT_MISMATCH)
        tp=f'tenant/{q.tenant_id}/'; sp=f'{tp}session/'
        if not q.session_id.startswith(sp) or not q.conversation_id.startswith(tp): R.add(InferenceRisk.TENANT_SESSION_BINDING_MISMATCH)
        if q.sequence_no>p.max_sequence_no: R.add(InferenceRisk.REQUEST_IDENTITY_MISMATCH)
        if b.scheduler_id not in p.allowed_scheduler_ids or b.partition_key!=q.tenant_id or q.request_id not in b.request_ids or len(b.request_ids)!=len(set(b.request_ids)): R.add(InferenceRisk.BATCH_ISOLATION_MISMATCH)
        if b.mixed_tenant_batch or set(b.tenant_ids)!={q.tenant_id} or len(b.tenant_ids)!=len(b.request_ids): R.add(InferenceRisk.CROSS_TENANT_BATCH)
        if c.kv_cache_namespace!=f'{q.session_id}/epoch/{q.session_epoch}' or c.kv_cache_owner_tenant_id!=q.tenant_id or c.kv_cache_session_id!=q.session_id or c.kv_cache_epoch!=q.session_epoch: R.add(InferenceRisk.KV_CACHE_BINDING_MISMATCH)
        if c.prefix_cache_enabled and (c.prefix_cache_namespace!=f'tenant/{q.tenant_id}/prefix-cache' or c.prefix_cache_owner_tenant_id!=q.tenant_id): R.add(InferenceRisk.PREFIX_CACHE_BINDING_MISMATCH)
        if c.allow_cross_tenant_reuse: R.add(InferenceRisk.CROSS_TENANT_CACHE_REUSE)
        if r.adapter_id!=p.expected_adapter_id or r.adapter_sha256.casefold()!=p.expected_adapter_sha256.casefold(): R.add(InferenceRisk.ADAPTER_ROUTE_MISMATCH)
        if (r.draft_model_id,r.draft_revision)!=(p.expected_draft_model_id,p.expected_draft_revision) or r.draft_model_artifact_sha256.casefold()!=p.expected_draft_model_artifact_sha256.casefold(): R.add(InferenceRisk.DRAFT_MODEL_ROUTE_MISMATCH)
        if o.recipient_tenant_id!=q.tenant_id or o.recipient_session_id!=q.session_id or not o.output_channel_id.startswith(f'{q.session_id}/') or not o.response_object_id.startswith(tp): R.add(InferenceRisk.OUTPUT_BINDING_MISMATCH)
        ledger=prior_request_ledger_digest(m.prior_request_ids)
        if ledger.casefold()!=m.prior_request_ledger_sha256.casefold() or ledger.casefold()!=p.expected_prior_request_ledger_sha256.casefold() or q.request_id in m.prior_request_ids: R.add(InferenceRisk.REQUEST_REPLAY)
        if m.network_operations: R.add(InferenceRisk.NETWORK_OPERATION_UNEXPECTED)
        return tuple(sorted(R,key=lambda x:x.value))
    def evaluate(self,request:InferenceTenantIsolationRequest,m:InferenceTenantIsolationManifest):
        self._validate_manifest(m); actual=inference_tenant_isolation_manifest_digest(m)
        if actual.casefold()!=self.policy.expected_manifest_sha256.casefold(): reject(InferenceRejectReason.MANIFEST_DIGEST_MISMATCH,'inference manifest differs from policy-pinned evidence')
        if request.manifest_id!=m.manifest_id or request.manifest_sha256.casefold()!=actual.casefold(): reject(InferenceRejectReason.REQUEST_INVALID,'request manifest binding mismatch')
        if request.evaluated_at_epoch<m.created_at_epoch-self.policy.max_future_skew_seconds or request.evaluated_at_epoch>m.created_at_epoch+self.policy.max_manifest_age_seconds: reject(InferenceRejectReason.REQUEST_INVALID,'inference manifest freshness invalid')
        q=m.request_identity; r=m.route; b=m.batch; c=m.cache; o=m.output
        declared=(request.declared_request_id,request.declared_tenant_id,request.declared_principal_id,request.declared_session_id,request.declared_model_id,request.declared_revision,request.declared_batch_id,request.declared_kv_cache_namespace,request.declared_output_channel_id)
        actual_ids=(q.request_id,q.tenant_id,q.principal_id,q.session_id,r.model_id,r.revision,b.batch_id,c.kv_cache_namespace,o.output_channel_id)
        if declared!=actual_ids: reject(InferenceRejectReason.DECLARED_SUMMARY_MISMATCH,'caller identity summary disagrees with evidence')
        risks=self.derive(m); decision=InferenceDecision.ALLOW if not risks else InferenceDecision.DENY; safe=not risks
        flags=(request.declared_upstream_bound,request.declared_route_bound,request.declared_request_identity_bound,request.declared_batch_isolated,request.declared_cache_isolated,request.declared_output_isolated,request.declared_request_fresh,request.declared_isolation_safe)
        if flags!=(safe,)*8: reject(InferenceRejectReason.DECLARED_SUMMARY_MISMATCH,'caller safety summary disagrees with derived evidence')
        sha=digest_json({'manifest_id':m.manifest_id,'request_id':q.request_id,'tenant_id':q.tenant_id,'principal_id':q.principal_id,'session_id':q.session_id,'deployment_id':r.deployment_id,'endpoint_id':r.endpoint_id,'model_id':r.model_id,'revision':r.revision,'adapter_id':r.adapter_id,'batch_id':b.batch_id,'risks':risks,'decision':decision,'schema':P10A_ASSESSMENT_SCHEMA_VERSION,'mode':P10A_ASSESSMENT_MODE})
        route_bad={InferenceRisk.ROUTE_IDENTITY_MISMATCH,InferenceRisk.MUTABLE_ROUTE_UNSAFE,InferenceRisk.ADAPTER_ROUTE_MISMATCH,InferenceRisk.DRAFT_MODEL_ROUTE_MISMATCH}; id_bad={InferenceRisk.REQUEST_IDENTITY_MISMATCH,InferenceRisk.TENANT_SESSION_BINDING_MISMATCH,InferenceRisk.AUTHORIZATION_CONTEXT_MISMATCH}; batch_bad={InferenceRisk.BATCH_ISOLATION_MISMATCH,InferenceRisk.CROSS_TENANT_BATCH}; cache_bad={InferenceRisk.KV_CACHE_BINDING_MISMATCH,InferenceRisk.PREFIX_CACHE_BINDING_MISMATCH,InferenceRisk.CROSS_TENANT_CACHE_REUSE}
        return VerifiedInferenceTenantIsolationAssessment(m.manifest_id,q.request_id,q.tenant_id,q.principal_id,q.session_id,r.deployment_id,r.endpoint_id,r.model_id,r.revision,r.adapter_id,b.batch_id,decision,risks,m.deployment_attestation_sha256,m.p9h_promotion_assessment_sha256,InferenceRisk.UPSTREAM_DEPLOYMENT_BINDING_MISMATCH not in risks,InferenceRisk.UPSTREAM_PROMOTION_BINDING_MISMATCH not in risks,not bool(set(risks)&route_bad),not bool(set(risks)&id_bad),not bool(set(risks)&batch_bad),not bool(set(risks)&cache_bad),InferenceRisk.OUTPUT_BINDING_MISMATCH not in risks,InferenceRisk.REQUEST_REPLAY not in risks,False,False,False,False,False,False,P10A_ASSESSMENT_SCHEMA_VERSION,P10A_ASSESSMENT_MODE,sha)
