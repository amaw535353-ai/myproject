from __future__ import annotations
import re
from .speculative_serving_types import P10D_ASSESSMENT_MODE,P10D_ASSESSMENT_SCHEMA_VERSION,ServingDecision,VerifiedInferenceSpeculativeServingAssessment
from .adapter_routing_types import *

_SHA=re.compile(r'^[0-9a-fA-F]{64}$'); _ID=re.compile(r'^[a-z0-9][a-z0-9._:/@-]{2,127}$')
class InferenceAdapterRoutingAnalyzer:
    def __init__(self,policy:InferenceAdapterRoutingPolicy): self.policy=policy; self._validate_policy()
    @staticmethod
    def _sha(v): return bool(_SHA.fullmatch(str(v)))
    @staticmethod
    def _id(v): return bool(_ID.fullmatch(str(v)))
    def _validate_policy(self):
        p=self.policy
        if p.policy_version!=P10E_POLICY_VERSION: reject(AdapterRejectReason.POLICY_INVALID,'unexpected policy version')
        ids=(p.expected_manifest_id,p.expected_request_id,p.expected_tenant_id,p.expected_session_id,p.expected_principal_id,p.expected_target_model_id,p.expected_target_model_revision,p.expected_authorization_id,p.expected_grant_id,p.expected_authorization_action)
        if not all(map(self._id,ids)) or not p.expected_session_id.startswith(f'tenant/{p.expected_tenant_id}/session/'): reject(AdapterRejectReason.POLICY_INVALID,'policy identity pins invalid')
        shas=(p.expected_manifest_sha256,p.expected_p10d_assessment_sha256,p.expected_target_model_sha256,p.expected_tokenizer_sha256,p.expected_prior_swap_ledger_sha256,*p.expected_adapter_artifact_sha256_by_id.values(),*p.expected_adapter_provenance_sha256_by_id.values())
        if not all(map(self._sha,shas)): reject(AdapterRejectReason.POLICY_INVALID,'policy digest pins invalid')
        adapters=set(p.expected_adapter_ids)
        if not adapters or len(adapters)!=len(p.expected_adapter_ids) or set(p.expected_adapter_revision_by_id)!=adapters or set(p.expected_adapter_kind_by_id)!=adapters or set(p.expected_adapter_generation_by_id)!=adapters or set(p.expected_adapter_parent_ids_by_id)!=adapters or set(p.expected_adapter_artifact_sha256_by_id)!=adapters or set(p.expected_adapter_provenance_sha256_by_id)!=adapters: reject(AdapterRejectReason.POLICY_INVALID,'adapter policy coverage invalid')
        if not p.allowed_adapter_kinds or not p.allowed_serialization_formats or not p.allowed_target_modules: reject(AdapterRejectReason.POLICY_INVALID,'adapter allowlists empty')
        if p.max_adapter_rank<=0 or p.max_adapter_alpha_bps<=0 or p.max_stack_depth<=0 or min(p.max_manifest_age_seconds,p.max_future_skew_seconds)<0: reject(AdapterRejectReason.POLICY_INVALID,'policy bounds invalid')
        if len(p.expected_before_adapter_ids)>p.max_stack_depth or len(p.expected_after_adapter_ids)>p.max_stack_depth: reject(AdapterRejectReason.POLICY_INVALID,'expected stack exceeds depth')
        if any(a not in adapters for a in (*p.expected_before_adapter_ids,*p.expected_after_adapter_ids)): reject(AdapterRejectReason.POLICY_INVALID,'expected stack references unknown adapter')
        if p.expected_before_adapter_ids not in p.allowed_compositions or p.expected_after_adapter_ids not in p.allowed_compositions: reject(AdapterRejectReason.POLICY_INVALID,'expected stack composition unauthorized')
        if p.expected_after_generation<=p.expected_before_generation: reject(AdapterRejectReason.POLICY_INVALID,'generation must advance')
        swaps=set(p.expected_swap_ids)
        if not swaps or len(swaps)!=len(p.expected_swap_ids) or not all(map(self._id,p.expected_swap_ids)): reject(AdapterRejectReason.POLICY_INVALID,'swap policy coverage invalid')
    def _validate_manifest(self,m:InferenceAdapterRoutingManifest):
        if m.schema_version!=P10E_SCHEMA_VERSION or m.manifest_id!=self.policy.expected_manifest_id or not self._id(m.manifest_id) or m.created_at_epoch<=0: reject(AdapterRejectReason.MANIFEST_INVALID,'manifest identity/schema/time invalid')
        ids=(m.request_id,m.tenant_id,m.session_id,m.principal_id,m.target_model_id,m.target_model_revision,m.authorization.authorization_id,m.authorization.grant_id,m.authorization.principal_id,m.authorization.tenant_id,m.authorization.action,m.route_before.snapshot_id,m.route_after.snapshot_id)
        if not all(map(self._id,ids)) or not m.session_id.startswith(f'tenant/{m.tenant_id}/session/'): reject(AdapterRejectReason.MANIFEST_INVALID,'route/auth identities malformed')
        if not all(map(self._sha,(m.p10d_assessment_sha256,m.target_model_sha256,m.tokenizer_sha256,m.authorization.base_model_sha256,m.prior_swap_ledger_sha256))): reject(AdapterRejectReason.MANIFEST_INVALID,'manifest digests malformed')
        if len({a.adapter_id for a in m.adapters})!=len(m.adapters) or not m.adapters: reject(AdapterRejectReason.MANIFEST_INVALID,'adapter evidence empty or duplicated')
        for a in m.adapters:
            if not all(map(self._id,(a.adapter_id,a.revision,a.tenant_id,a.base_model_id,a.base_model_revision))) or not all(map(self._sha,(a.artifact_sha256,a.base_model_sha256,a.tokenizer_sha256,a.provenance_sha256))) or a.generation<0 or a.rank<=0 or a.alpha_bps<=0 or not a.serialization_format or not a.target_modules or len(a.target_modules)!=len(set(a.target_modules)) or len(a.parent_adapter_ids)!=len(set(a.parent_adapter_ids)): reject(AdapterRejectReason.MANIFEST_INVALID,'adapter evidence malformed')
            if any(not self._id(x) for x in (*a.target_modules,*a.parent_adapter_ids)): reject(AdapterRejectReason.MANIFEST_INVALID,'adapter modules/parents malformed')
        auth=m.authorization
        if auth.issued_at_epoch<=0 or auth.expires_at_epoch<=auth.issued_at_epoch or len(auth.target_adapter_ids)!=len(set(auth.target_adapter_ids)) or any(not self._id(x) for x in auth.target_adapter_ids): reject(AdapterRejectReason.MANIFEST_INVALID,'authorization malformed')
        for s in (m.route_before,m.route_after):
            if not all(map(self._id,(s.snapshot_id,s.request_id,s.tenant_id,s.session_id,s.base_model_id,s.base_model_revision))) or not all(map(self._sha,(s.base_model_sha256,s.tokenizer_sha256,s.composition_sha256))) or s.generation<0 or len(s.active_adapter_ids)!=len(set(s.active_adapter_ids)) or any(not self._id(x) for x in s.active_adapter_ids): reject(AdapterRejectReason.MANIFEST_INVALID,'route snapshot malformed')
        if not m.swaps or len({s.swap_id for s in m.swaps})!=len(m.swaps): reject(AdapterRejectReason.MANIFEST_INVALID,'swap evidence empty or duplicated')
        for s in m.swaps:
            if not all(map(self._id,(s.swap_id,s.request_id,s.tenant_id,s.session_id))) or min(s.sequence_no,s.from_generation,s.to_generation)<0 or not all(map(self._sha,(s.authorization_sha256,s.before_snapshot_sha256,s.after_snapshot_sha256,s.previous_swap_sha256))) or len(s.prior_adapter_ids)!=len(set(s.prior_adapter_ids)) or len(s.next_adapter_ids)!=len(set(s.next_adapter_ids)): reject(AdapterRejectReason.MANIFEST_INVALID,'swap evidence malformed')
        if len(m.prior_swap_ids)!=len(set(m.prior_swap_ids)) or any(not self._id(x) for x in m.prior_swap_ids) or len(m.retired_adapter_ids)!=len(set(m.retired_adapter_ids)) or any(not self._id(x) for x in m.retired_adapter_ids) or m.network_operations<0: reject(AdapterRejectReason.MANIFEST_INVALID,'ledger/network malformed')
    def _upstream_ok(self,a:VerifiedInferenceSpeculativeServingAssessment)->bool:
        flags=(a.upstream_p10c_bound,a.route_identity_verified,a.draft_model_trust_verified,a.service_topology_verified,a.state_transfer_verified,a.speculative_verification_verified,a.final_state_verified)
        nonclaims=(a.caller_declared_safety_trusted,a.production_inference_engine_integrated,a.production_rpc_transport_verified,a.cryptographic_service_attestation_verified,a.production_speculative_decoder_validated,a.semantic_token_equivalence_verified,a.side_channel_resistance_validated)
        return a.decision==ServingDecision.ALLOW and not a.risks and all(flags) and not any(nonclaims) and a.assessment_schema_version==P10D_ASSESSMENT_SCHEMA_VERSION and a.assessment_mode==P10D_ASSESSMENT_MODE
    def derive(self,m:InferenceAdapterRoutingManifest,a:VerifiedInferenceSpeculativeServingAssessment):
        self._validate_manifest(m); p=self.policy; R=set(); adapters={x.adapter_id:x for x in m.adapters}
        if not self._upstream_ok(a): R.add(AdapterRisk.UPSTREAM_P10D_INVALID)
        if m.p10d_assessment_sha256.casefold()!=p.expected_p10d_assessment_sha256.casefold() or a.assessment_evidence_sha256.casefold()!=p.expected_p10d_assessment_sha256.casefold(): R.add(AdapterRisk.UPSTREAM_BINDING_MISMATCH)
        if (m.request_id,m.tenant_id,m.session_id)!=(p.expected_request_id,p.expected_tenant_id,p.expected_session_id) or (a.request_id,a.tenant_id,a.session_id)!=(m.request_id,m.tenant_id,m.session_id): R.add(AdapterRisk.REQUEST_ROUTE_MISMATCH)
        if m.principal_id!=p.expected_principal_id: R.add(AdapterRisk.REQUEST_ROUTE_MISMATCH)
        if (m.target_model_id,m.target_model_revision)!=(p.expected_target_model_id,p.expected_target_model_revision) or (a.target_model_id,a.target_model_revision)!=(m.target_model_id,m.target_model_revision) or m.target_model_sha256.casefold()!=p.expected_target_model_sha256.casefold(): R.add(AdapterRisk.BASE_MODEL_MISMATCH)
        if m.tokenizer_sha256.casefold()!=p.expected_tokenizer_sha256.casefold(): R.add(AdapterRisk.TOKENIZER_MISMATCH)
        if tuple(x.adapter_id for x in m.adapters)!=p.expected_adapter_ids or set(adapters)!=set(p.expected_adapter_ids): R.add(AdapterRisk.ADAPTER_COVERAGE_MISMATCH)
        for x in m.adapters:
            if x.revision!=p.expected_adapter_revision_by_id.get(x.adapter_id) or x.kind!=p.expected_adapter_kind_by_id.get(x.adapter_id) or x.generation!=p.expected_adapter_generation_by_id.get(x.adapter_id): R.add(AdapterRisk.ADAPTER_IDENTITY_MISMATCH)
            expected_sha=p.expected_adapter_artifact_sha256_by_id.get(x.adapter_id,'')
            if x.artifact_sha256.casefold()!=expected_sha.casefold(): R.add(AdapterRisk.ADAPTER_DIGEST_MISMATCH)
            if x.provenance_sha256.casefold()!=p.expected_adapter_provenance_sha256_by_id.get(x.adapter_id,'').casefold(): R.add(AdapterRisk.ADAPTER_PROVENANCE_MISMATCH)
            if x.kind not in p.allowed_adapter_kinds or x.serialization_format not in p.allowed_serialization_formats: R.add(AdapterRisk.ADAPTER_FORMAT_UNSAFE)
            if (x.base_model_id,x.base_model_revision,x.base_model_sha256.casefold())!=(m.target_model_id,m.target_model_revision,m.target_model_sha256.casefold()): R.add(AdapterRisk.ADAPTER_BASE_BINDING_MISMATCH)
            if x.tokenizer_sha256.casefold()!=m.tokenizer_sha256.casefold(): R.add(AdapterRisk.TOKENIZER_MISMATCH)
            if x.tenant_id!=m.tenant_id: R.add(AdapterRisk.ADAPTER_TENANT_MISMATCH)
            if x.rank>p.max_adapter_rank or x.alpha_bps>p.max_adapter_alpha_bps or any(t not in p.allowed_target_modules for t in x.target_modules): R.add(AdapterRisk.ADAPTER_PARAMETER_POLICY_MISMATCH)
            if x.parent_adapter_ids!=p.expected_adapter_parent_ids_by_id.get(x.adapter_id,()) or any(parent not in adapters or parent==x.adapter_id for parent in x.parent_adapter_ids): R.add(AdapterRisk.ADAPTER_STACK_ORDER_MISMATCH)
        auth=m.authorization
        if (auth.authorization_id,auth.grant_id,auth.principal_id,auth.tenant_id,auth.action)!=(p.expected_authorization_id,p.expected_grant_id,p.expected_principal_id,p.expected_tenant_id,p.expected_authorization_action) or auth.target_adapter_ids!=p.expected_after_adapter_ids or auth.base_model_sha256.casefold()!=m.target_model_sha256.casefold(): R.add(AdapterRisk.AUTHORIZATION_INVALID)
        if not (auth.issued_at_epoch<=m.created_at_epoch<=auth.expires_at_epoch): R.add(AdapterRisk.AUTHORIZATION_EXPIRED)
        artifact_map={k:v.artifact_sha256 for k,v in adapters.items()}
        for snap,expected_gen,expected_ids in ((m.route_before,p.expected_before_generation,p.expected_before_adapter_ids),(m.route_after,p.expected_after_generation,p.expected_after_adapter_ids)):
            if (snap.request_id,snap.tenant_id,snap.session_id)!=(m.request_id,m.tenant_id,m.session_id) or (snap.base_model_id,snap.base_model_revision,snap.base_model_sha256.casefold())!=(m.target_model_id,m.target_model_revision,m.target_model_sha256.casefold()) or snap.tokenizer_sha256.casefold()!=m.tokenizer_sha256.casefold(): R.add(AdapterRisk.ROUTE_SNAPSHOT_MISMATCH)
            if snap.generation!=expected_gen: R.add(AdapterRisk.HOT_SWAP_GENERATION_MISMATCH)
            if snap.active_adapter_ids!=expected_ids: R.add(AdapterRisk.ADAPTER_STACK_ORDER_MISMATCH)
            if len(snap.active_adapter_ids)>p.max_stack_depth: R.add(AdapterRisk.ADAPTER_STACK_DEPTH_EXCEEDED)
            if snap.active_adapter_ids not in p.allowed_compositions: R.add(AdapterRisk.ADAPTER_COMPOSITION_UNAUTHORIZED)
            if any(x not in adapters for x in snap.active_adapter_ids): R.add(AdapterRisk.ADAPTER_COVERAGE_MISMATCH)
            else:
                expected_comp=adapter_composition_digest(m.target_model_sha256,m.tokenizer_sha256,snap.active_adapter_ids,artifact_map)
                if snap.composition_sha256.casefold()!=expected_comp.casefold(): R.add(AdapterRisk.ROUTE_SNAPSHOT_MISMATCH)
            if any(x in m.retired_adapter_ids for x in snap.active_adapter_ids): R.add(AdapterRisk.RETIRED_ADAPTER_RESURRECTED)
        if tuple(s.swap_id for s in m.swaps)!=p.expected_swap_ids: R.add(AdapterRisk.HOT_SWAP_COVERAGE_MISMATCH)
        previous=m.prior_swap_ledger_sha256; before=m.route_before
        for i,s in enumerate(m.swaps,1):
            if s.sequence_no!=i: R.add(AdapterRisk.HOT_SWAP_SEQUENCE_MISMATCH)
            if s.swap_id in m.prior_swap_ids: R.add(AdapterRisk.HOT_SWAP_REPLAY)
            if (s.request_id,s.tenant_id,s.session_id)!=(m.request_id,m.tenant_id,m.session_id): R.add(AdapterRisk.REQUEST_ROUTE_MISMATCH)
            if s.previous_swap_sha256.casefold()!=previous.casefold(): R.add(AdapterRisk.HOT_SWAP_SEQUENCE_MISMATCH)
            if s.authorization_sha256.casefold()!=adapter_authorization_digest(auth).casefold(): R.add(AdapterRisk.AUTHORIZATION_INVALID)
            if s.from_generation!=before.generation or s.to_generation!=s.from_generation+1: R.add(AdapterRisk.HOT_SWAP_GENERATION_MISMATCH)
            if s.prior_adapter_ids!=before.active_adapter_ids or s.next_adapter_ids!=m.route_after.active_adapter_ids: R.add(AdapterRisk.HOT_SWAP_TRANSITION_INVALID)
            if s.before_snapshot_sha256.casefold()!=route_snapshot_digest(before).casefold() or s.after_snapshot_sha256.casefold()!=route_snapshot_digest(m.route_after).casefold(): R.add(AdapterRisk.ROUTE_SNAPSHOT_MISMATCH)
            if s.next_adapter_ids not in p.allowed_compositions or len(s.next_adapter_ids)>p.max_stack_depth: R.add(AdapterRisk.ADAPTER_COMPOSITION_UNAUTHORIZED)
            if any(x in m.retired_adapter_ids for x in s.next_adapter_ids): R.add(AdapterRisk.RETIRED_ADAPTER_RESURRECTED)
            previous=adapter_hot_swap_digest(s); before=m.route_after
        ledger=prior_swap_ledger_digest(m.prior_swap_ids)
        if ledger.casefold()!=m.prior_swap_ledger_sha256.casefold() or ledger.casefold()!=p.expected_prior_swap_ledger_sha256.casefold(): R.add(AdapterRisk.PRIOR_SWAP_LEDGER_MISMATCH)
        if m.network_operations: R.add(AdapterRisk.NETWORK_OPERATION_UNEXPECTED)
        return tuple(sorted(R,key=lambda x:x.value))
    def evaluate(self,request:InferenceAdapterRoutingRequest,m:InferenceAdapterRoutingManifest,a:VerifiedInferenceSpeculativeServingAssessment):
        self._validate_manifest(m); actual=inference_adapter_routing_manifest_digest(m)
        if actual.casefold()!=self.policy.expected_manifest_sha256.casefold(): reject(AdapterRejectReason.MANIFEST_DIGEST_MISMATCH,'adapter routing manifest differs from policy-pinned evidence')
        if request.manifest_id!=m.manifest_id or request.manifest_sha256.casefold()!=actual.casefold(): reject(AdapterRejectReason.REQUEST_INVALID,'request manifest binding mismatch')
        if request.evaluated_at_epoch<m.created_at_epoch-self.policy.max_future_skew_seconds or request.evaluated_at_epoch>m.created_at_epoch+self.policy.max_manifest_age_seconds: reject(AdapterRejectReason.REQUEST_INVALID,'adapter routing manifest freshness invalid')
        identity=(request.declared_request_id,request.declared_tenant_id,request.declared_session_id,request.declared_principal_id,request.declared_target_model_revision,request.declared_before_adapter_ids,request.declared_after_adapter_ids,request.declared_after_generation,request.declared_swap_ids)
        evidence=(m.request_id,m.tenant_id,m.session_id,m.principal_id,m.target_model_revision,m.route_before.active_adapter_ids,m.route_after.active_adapter_ids,m.route_after.generation,tuple(s.swap_id for s in m.swaps))
        if identity!=evidence: reject(AdapterRejectReason.DECLARED_SUMMARY_MISMATCH,'caller adapter routing identity summary disagrees with evidence')
        risks=self.derive(m,a); decision=AdapterDecision.ALLOW if not risks else AdapterDecision.DENY; safe=not risks
        declared=(request.declared_upstream_p10d_bound,request.declared_base_route_bound,request.declared_adapter_artifacts_safe,request.declared_tenant_composition_safe,request.declared_authorization_safe,request.declared_hot_swap_safe,request.declared_route_snapshot_safe,request.declared_adapter_routing_safe)
        if declared!=(safe,)*8: reject(AdapterRejectReason.DECLARED_SUMMARY_MISMATCH,'caller adapter safety summary disagrees with derived evidence')
        artifact_bad={AdapterRisk.ADAPTER_COVERAGE_MISMATCH,AdapterRisk.ADAPTER_IDENTITY_MISMATCH,AdapterRisk.ADAPTER_DIGEST_MISMATCH,AdapterRisk.ADAPTER_FORMAT_UNSAFE,AdapterRisk.ADAPTER_BASE_BINDING_MISMATCH,AdapterRisk.ADAPTER_PROVENANCE_MISMATCH,AdapterRisk.ADAPTER_PARAMETER_POLICY_MISMATCH,AdapterRisk.TOKENIZER_MISMATCH}
        tenant_bad={AdapterRisk.ADAPTER_TENANT_MISMATCH,AdapterRisk.ADAPTER_STACK_ORDER_MISMATCH,AdapterRisk.ADAPTER_STACK_DEPTH_EXCEEDED,AdapterRisk.ADAPTER_COMPOSITION_UNAUTHORIZED,AdapterRisk.RETIRED_ADAPTER_RESURRECTED}
        swap_bad={AdapterRisk.HOT_SWAP_COVERAGE_MISMATCH,AdapterRisk.HOT_SWAP_SEQUENCE_MISMATCH,AdapterRisk.HOT_SWAP_GENERATION_MISMATCH,AdapterRisk.HOT_SWAP_REPLAY,AdapterRisk.HOT_SWAP_TRANSITION_INVALID,AdapterRisk.PRIOR_SWAP_LEDGER_MISMATCH}
        route_bad={AdapterRisk.REQUEST_ROUTE_MISMATCH,AdapterRisk.BASE_MODEL_MISMATCH,AdapterRisk.ROUTE_SNAPSHOT_MISMATCH}
        sha=digest_json({'manifest_id':m.manifest_id,'request_id':m.request_id,'tenant_id':m.tenant_id,'target_model_revision':m.target_model_revision,'after_generation':m.route_after.generation,'after_adapter_ids':m.route_after.active_adapter_ids,'risks':risks,'decision':decision,'schema':P10E_ASSESSMENT_SCHEMA_VERSION,'mode':P10E_ASSESSMENT_MODE})
        return VerifiedInferenceAdapterRoutingAssessment(m.manifest_id,actual,m.request_id,m.tenant_id,m.session_id,m.principal_id,decision,risks,m.p10d_assessment_sha256,m.target_model_id,m.target_model_revision,tuple(x.adapter_id for x in m.adapters),m.route_before.active_adapter_ids,m.route_after.active_adapter_ids,m.route_after.generation,tuple(x.swap_id for x in m.swaps),AdapterRisk.UPSTREAM_P10D_INVALID not in risks and AdapterRisk.UPSTREAM_BINDING_MISMATCH not in risks,not bool(set(risks)&route_bad),not bool(set(risks)&artifact_bad),not bool(set(risks)&tenant_bad),AdapterRisk.AUTHORIZATION_INVALID not in risks and AdapterRisk.AUTHORIZATION_EXPIRED not in risks,not bool(set(risks)&swap_bad),AdapterRisk.ROUTE_SNAPSHOT_MISMATCH not in risks,False,False,False,False,False,False,False,P10E_ASSESSMENT_SCHEMA_VERSION,P10E_ASSESSMENT_MODE,sha)
