from __future__ import annotations
import re
from .cache_lifecycle_types import P10C_ASSESSMENT_MODE,P10C_ASSESSMENT_SCHEMA_VERSION,CacheDecision,VerifiedInferenceCacheLifecycleAssessment
from .speculative_serving_types import *

_SHA=re.compile(r'^[0-9a-fA-F]{64}$'); _ID=re.compile(r'^[a-z0-9][a-z0-9._:/@-]{2,127}$')
class InferenceSpeculativeServingAnalyzer:
    def __init__(self,policy:InferenceSpeculativeServingPolicy): self.policy=policy; self._validate_policy()
    @staticmethod
    def _sha(v): return bool(_SHA.fullmatch(str(v)))
    @staticmethod
    def _id(v): return bool(_ID.fullmatch(str(v)))
    def _validate_policy(self):
        p=self.policy
        if p.policy_version!=P10D_POLICY_VERSION: reject(ServingRejectReason.POLICY_INVALID,'unexpected policy version')
        ids=(p.expected_manifest_id,p.expected_upstream_scheduler_id,p.expected_upstream_batch_id,p.expected_request_id,p.expected_tenant_id,p.expected_session_id,p.expected_target_model_id,p.expected_target_model_revision,p.expected_draft_model_id,p.expected_draft_model_revision)
        if not all(map(self._id,ids)): reject(ServingRejectReason.POLICY_INVALID,'policy identity pins invalid')
        shas=(p.expected_manifest_sha256,p.expected_p10c_assessment_sha256,p.expected_request_input_sha256,p.expected_target_model_sha256,p.expected_draft_model_sha256,p.expected_tokenizer_sha256,p.expected_draft_trust_profile_sha256,p.expected_handoff_state_sha256,p.expected_prior_transfer_ledger_sha256,*p.expected_service_identity_sha256_by_id.values())
        if not all(map(self._sha,shas)): reject(ServingRejectReason.POLICY_INVALID,'policy digest pins invalid')
        if p.expected_cache_epoch<0 or p.max_draft_tokens_per_round<=0 or p.max_speculative_rounds<=0 or min(p.max_manifest_age_seconds,p.max_future_skew_seconds)<0: reject(ServingRejectReason.POLICY_INVALID,'policy bounds invalid')
        services=set(p.expected_service_ids); transfers=set(p.expected_transfer_ids); rounds=set(p.expected_round_ids)
        if len(services)!=3 or len(services)!=len(p.expected_service_ids) or set(p.expected_service_role_by_id)!=services or set(p.expected_service_identity_sha256_by_id)!=services: reject(ServingRejectReason.POLICY_INVALID,'service policy coverage invalid')
        if set(p.expected_service_role_by_id.values())!={ServiceRole.PREFILL,ServiceRole.DRAFT,ServiceRole.DECODE}: reject(ServingRejectReason.POLICY_INVALID,'service roles must contain one prefill, draft, and decode service')
        if not transfers or len(transfers)!=len(p.expected_transfer_ids) or set(p.expected_transfer_edges)!=transfers: reject(ServingRejectReason.POLICY_INVALID,'transfer policy coverage invalid')
        if not rounds or len(rounds)!=len(p.expected_round_ids) or len(rounds)>p.max_speculative_rounds: reject(ServingRejectReason.POLICY_INVALID,'round policy coverage invalid')
        if not all(map(self._id,(*p.expected_service_ids,*p.expected_transfer_ids,*p.expected_round_ids))): reject(ServingRejectReason.POLICY_INVALID,'policy topology identifiers invalid')
        for tid,(src,dst) in p.expected_transfer_edges.items():
            if src not in services or dst not in services: reject(ServingRejectReason.POLICY_INVALID,'transfer edge references unknown service')
            if p.expected_service_role_by_id[src]!=ServiceRole.PREFILL or p.expected_service_role_by_id[dst] not in (ServiceRole.DRAFT,ServiceRole.DECODE): reject(ServingRejectReason.POLICY_INVALID,'transfer edges must originate at prefill and terminate at draft/decode')
        if not p.expected_session_id.startswith(f'tenant/{p.expected_tenant_id}/session/'): reject(ServingRejectReason.POLICY_INVALID,'expected session does not belong to tenant')
    def _validate_manifest(self,m:InferenceSpeculativeServingManifest):
        if m.schema_version!=P10D_SCHEMA_VERSION or m.manifest_id!=self.policy.expected_manifest_id or not self._id(m.manifest_id) or m.created_at_epoch<=0 or m.cache_epoch<0: reject(ServingRejectReason.MANIFEST_INVALID,'manifest identity/schema/time invalid')
        ids=(m.upstream_scheduler_id,m.upstream_batch_id,m.request_id,m.tenant_id,m.session_id,m.target_model_id,m.target_model_revision,m.draft_model_id,m.draft_model_revision)
        if not all(map(self._id,ids)) or not m.session_id.startswith(f'tenant/{m.tenant_id}/session/'): reject(ServingRejectReason.MANIFEST_INVALID,'route/model identifiers malformed')
        shas=(m.p10c_assessment_sha256,m.request_input_sha256,m.target_model_sha256,m.draft_model_sha256,m.tokenizer_sha256,m.draft_trust_profile_sha256,m.handoff_state_sha256,m.final_state_sha256,m.prior_transfer_ledger_sha256)
        if not all(map(self._sha,shas)): reject(ServingRejectReason.MANIFEST_INVALID,'manifest digests malformed')
        if not m.services or len({s.service_id for s in m.services})!=len(m.services): reject(ServingRejectReason.MANIFEST_INVALID,'service evidence empty or duplicated')
        for s in m.services:
            if not all(map(self._id,(s.service_id,s.request_id,s.tenant_id,s.session_id,s.model_id,s.model_revision))) or not all(map(self._sha,(s.model_sha256,s.tokenizer_sha256,s.input_evidence_sha256,s.output_evidence_sha256,s.service_identity_sha256))): reject(ServingRejectReason.MANIFEST_INVALID,'service evidence malformed')
        if not m.transfers or len({t.transfer_id for t in m.transfers})!=len(m.transfers): reject(ServingRejectReason.MANIFEST_INVALID,'transfer evidence empty or duplicated')
        for t in m.transfers:
            if not all(map(self._id,(t.transfer_id,t.source_service_id,t.destination_service_id,t.request_id,t.tenant_id,t.session_id))) or min(t.sequence_no,t.cache_epoch)<0 or not all(map(self._sha,(t.state_sha256,t.source_output_sha256,t.destination_input_sha256,t.previous_transfer_sha256))): reject(ServingRejectReason.MANIFEST_INVALID,'transfer evidence malformed')
        if not m.speculative_rounds or len({r.round_id for r in m.speculative_rounds})!=len(m.speculative_rounds): reject(ServingRejectReason.MANIFEST_INVALID,'speculative round evidence empty or duplicated')
        for r in m.speculative_rounds:
            if not all(map(self._id,(r.round_id,r.draft_service_id,r.decode_service_id,r.request_id,r.tenant_id,r.session_id))) or min(r.sequence_no,r.proposed_token_count,r.target_verified_token_count,r.accepted_token_count,r.rejected_token_count)<0 or not all(map(self._sha,(r.input_state_sha256,r.proposal_sha256,r.target_verification_sha256,r.result_state_sha256))): reject(ServingRejectReason.MANIFEST_INVALID,'speculative round evidence malformed')
        if len(m.prior_transfer_ids)!=len(set(m.prior_transfer_ids)) or not all(map(self._id,m.prior_transfer_ids)) or m.network_operations<0: reject(ServingRejectReason.MANIFEST_INVALID,'prior transfer ledger/network malformed')
    def _upstream_ok(self,a:VerifiedInferenceCacheLifecycleAssessment)->bool:
        flags=(a.upstream_p10b_bound,a.ownership_verified,a.reuse_isolation_verified,a.eviction_verified,a.zeroization_verified,a.rollback_safety_verified)
        nonclaims=(a.caller_declared_safety_trusted,a.production_cache_manager_integrated,a.physical_memory_zeroization_verified,a.distributed_cache_coherence_validated,a.gpu_allocator_integrated,a.side_channel_resistance_validated)
        return a.decision==CacheDecision.ALLOW and not a.risks and all(flags) and not any(nonclaims) and a.assessment_schema_version==P10C_ASSESSMENT_SCHEMA_VERSION and a.assessment_mode==P10C_ASSESSMENT_MODE
    def derive(self,m:InferenceSpeculativeServingManifest,a:VerifiedInferenceCacheLifecycleAssessment):
        self._validate_manifest(m); p=self.policy; R=set(); services={s.service_id:s for s in m.services}; transfers={t.transfer_id:t for t in m.transfers}; rounds={r.round_id:r for r in m.speculative_rounds}
        if not self._upstream_ok(a): R.add(ServingRisk.UPSTREAM_P10C_INVALID)
        if m.p10c_assessment_sha256.casefold()!=p.expected_p10c_assessment_sha256.casefold() or a.assessment_evidence_sha256.casefold()!=p.expected_p10c_assessment_sha256.casefold() or (m.upstream_scheduler_id,m.upstream_batch_id,m.cache_epoch)!=(p.expected_upstream_scheduler_id,p.expected_upstream_batch_id,p.expected_cache_epoch) or (a.scheduler_id,a.batch_id,a.cache_epoch)!=(m.upstream_scheduler_id,m.upstream_batch_id,m.cache_epoch): R.add(ServingRisk.UPSTREAM_BINDING_MISMATCH)
        if (m.request_id,m.tenant_id,m.session_id)!=(p.expected_request_id,p.expected_tenant_id,p.expected_session_id) or m.request_input_sha256.casefold()!=p.expected_request_input_sha256.casefold(): R.add(ServingRisk.REQUEST_ROUTE_MISMATCH)
        if (m.target_model_id,m.target_model_revision,m.target_model_sha256.casefold())!=(p.expected_target_model_id,p.expected_target_model_revision,p.expected_target_model_sha256.casefold()): R.add(ServingRisk.TARGET_MODEL_MISMATCH)
        if (m.draft_model_id,m.draft_model_revision,m.draft_model_sha256.casefold())!=(p.expected_draft_model_id,p.expected_draft_model_revision,p.expected_draft_model_sha256.casefold()): R.add(ServingRisk.DRAFT_MODEL_MISMATCH)
        if m.draft_trust_profile_sha256.casefold()!=p.expected_draft_trust_profile_sha256.casefold(): R.add(ServingRisk.DRAFT_TRUST_MISMATCH)
        if m.tokenizer_sha256.casefold()!=p.expected_tokenizer_sha256.casefold(): R.add(ServingRisk.TOKENIZER_MISMATCH)
        if m.handoff_state_sha256.casefold()!=p.expected_handoff_state_sha256.casefold(): R.add(ServingRisk.PREFILL_DECODE_STATE_MISMATCH)
        if tuple(s.service_id for s in m.services)!=p.expected_service_ids or set(services)!=set(p.expected_service_ids): R.add(ServingRisk.SERVICE_COVERAGE_MISMATCH)
        for s in m.services:
            expected_role=p.expected_service_role_by_id.get(s.service_id)
            if expected_role is None: R.add(ServingRisk.SERVICE_COVERAGE_MISMATCH); continue
            if s.role!=expected_role: R.add(ServingRisk.SERVICE_ROLE_MISMATCH)
            expected_identity=p.expected_service_identity_sha256_by_id.get(s.service_id,'')
            if s.service_identity_sha256.casefold()!=service_identity_digest(s).casefold() or s.service_identity_sha256.casefold()!=expected_identity.casefold(): R.add(ServingRisk.SERVICE_IDENTITY_MISMATCH)
            if (s.request_id,s.tenant_id,s.session_id)!=(m.request_id,m.tenant_id,m.session_id): R.add(ServingRisk.REQUEST_ROUTE_MISMATCH)
            if s.tokenizer_sha256.casefold()!=m.tokenizer_sha256.casefold(): R.add(ServingRisk.TOKENIZER_MISMATCH)
            if expected_role==ServiceRole.PREFILL and s.input_evidence_sha256.casefold()!=m.request_input_sha256.casefold(): R.add(ServingRisk.REQUEST_ROUTE_MISMATCH)
            if expected_role==ServiceRole.PREFILL and s.output_evidence_sha256.casefold()!=m.handoff_state_sha256.casefold(): R.add(ServingRisk.PREFILL_DECODE_STATE_MISMATCH)
            if expected_role in (ServiceRole.DRAFT,ServiceRole.DECODE) and s.input_evidence_sha256.casefold()!=m.handoff_state_sha256.casefold(): R.add(ServingRisk.PREFILL_DECODE_STATE_MISMATCH)
            if expected_role in (ServiceRole.PREFILL,ServiceRole.DECODE):
                if (s.model_id,s.model_revision,s.model_sha256.casefold())!=(m.target_model_id,m.target_model_revision,m.target_model_sha256.casefold()): R.add(ServingRisk.TARGET_MODEL_MISMATCH)
            elif expected_role==ServiceRole.DRAFT:
                if (s.model_id,s.model_revision,s.model_sha256.casefold())!=(m.draft_model_id,m.draft_model_revision,m.draft_model_sha256.casefold()): R.add(ServingRisk.DRAFT_MODEL_MISMATCH)
        if tuple(t.transfer_id for t in m.transfers)!=p.expected_transfer_ids or set(transfers)!=set(p.expected_transfer_ids): R.add(ServingRisk.STATE_TRANSFER_COVERAGE_MISMATCH)
        previous=m.prior_transfer_ledger_sha256
        expected_state=m.handoff_state_sha256
        for index,t in enumerate(m.transfers,1):
            if t.sequence_no!=index: R.add(ServingRisk.STATE_TRANSFER_SEQUENCE_MISMATCH)
            edge=p.expected_transfer_edges.get(t.transfer_id)
            if edge is None or (t.source_service_id,t.destination_service_id)!=edge: R.add(ServingRisk.STATE_TRANSFER_COVERAGE_MISMATCH)
            src=services.get(t.source_service_id); dst=services.get(t.destination_service_id)
            if (t.request_id,t.tenant_id)!=(m.request_id,m.tenant_id) or (src and src.tenant_id!=t.tenant_id) or (dst and dst.tenant_id!=t.tenant_id): R.add(ServingRisk.CROSS_TENANT_STATE_TRANSFER)
            if t.session_id!=m.session_id or (src and src.session_id!=t.session_id) or (dst and dst.session_id!=t.session_id): R.add(ServingRisk.CROSS_SESSION_STATE_TRANSFER)
            if t.cache_epoch!=m.cache_epoch: R.add(ServingRisk.UPSTREAM_BINDING_MISMATCH)
            if t.transfer_id in m.prior_transfer_ids: R.add(ServingRisk.STATE_TRANSFER_REPLAY)
            if t.previous_transfer_sha256.casefold()!=previous.casefold(): R.add(ServingRisk.STATE_TRANSFER_SEQUENCE_MISMATCH)
            if src is None or dst is None or t.state_sha256.casefold()!=t.source_output_sha256.casefold() or t.state_sha256.casefold()!=t.destination_input_sha256.casefold() or (src and t.source_output_sha256.casefold()!=src.output_evidence_sha256.casefold()) or (dst and t.destination_input_sha256.casefold()!=dst.input_evidence_sha256.casefold()): R.add(ServingRisk.STATE_TRANSFER_DIGEST_MISMATCH)
            if src and src.role!=ServiceRole.PREFILL: R.add(ServingRisk.SERVICE_ROLE_MISMATCH)
            if dst and dst.role not in (ServiceRole.DRAFT,ServiceRole.DECODE): R.add(ServingRisk.SERVICE_ROLE_MISMATCH)
            if t.state_sha256.casefold()!=expected_state.casefold(): R.add(ServingRisk.PREFILL_DECODE_STATE_MISMATCH)
            previous=state_transfer_digest(t)
        ledger=prior_transfer_ledger_digest(m.prior_transfer_ids)
        if ledger.casefold()!=m.prior_transfer_ledger_sha256.casefold() or ledger.casefold()!=p.expected_prior_transfer_ledger_sha256.casefold(): R.add(ServingRisk.PRIOR_TRANSFER_LEDGER_MISMATCH)
        if any(t.transfer_id in m.prior_transfer_ids for t in m.transfers): R.add(ServingRisk.STATE_TRANSFER_REPLAY)
        if tuple(r.round_id for r in m.speculative_rounds)!=p.expected_round_ids or set(rounds)!=set(p.expected_round_ids): R.add(ServingRisk.SPECULATIVE_ROUND_COVERAGE_MISMATCH)
        if len(m.speculative_rounds)>p.max_speculative_rounds: R.add(ServingRisk.SPECULATIVE_ROUND_MISMATCH)
        for index,r in enumerate(m.speculative_rounds,1):
            if r.sequence_no!=index: R.add(ServingRisk.SPECULATIVE_ROUND_MISMATCH)
            draft=services.get(r.draft_service_id); decode=services.get(r.decode_service_id)
            if draft is None or decode is None or draft.role!=ServiceRole.DRAFT or decode.role!=ServiceRole.DECODE: R.add(ServingRisk.SERVICE_ROLE_MISMATCH)
            if (r.request_id,r.tenant_id,r.session_id)!=(m.request_id,m.tenant_id,m.session_id): R.add(ServingRisk.SPECULATIVE_ROUND_MISMATCH)
            if draft and (draft.request_id,draft.tenant_id,draft.session_id)!=(r.request_id,r.tenant_id,r.session_id): R.add(ServingRisk.SPECULATIVE_ROUND_MISMATCH)
            if decode and (decode.request_id,decode.tenant_id,decode.session_id)!=(r.request_id,r.tenant_id,r.session_id): R.add(ServingRisk.SPECULATIVE_ROUND_MISMATCH)
            if r.input_state_sha256.casefold()!=m.handoff_state_sha256.casefold(): R.add(ServingRisk.PREFILL_DECODE_STATE_MISMATCH)
            if draft and r.input_state_sha256.casefold()!=draft.input_evidence_sha256.casefold(): R.add(ServingRisk.PREFILL_DECODE_STATE_MISMATCH)
            if decode and r.input_state_sha256.casefold()!=decode.input_evidence_sha256.casefold(): R.add(ServingRisk.PREFILL_DECODE_STATE_MISMATCH)
            if draft and r.proposal_sha256.casefold()!=draft.output_evidence_sha256.casefold(): R.add(ServingRisk.SPECULATIVE_ROUND_MISMATCH)
            if decode and r.result_state_sha256.casefold()!=decode.output_evidence_sha256.casefold(): R.add(ServingRisk.FINAL_STATE_MISMATCH)
            if r.proposed_token_count>p.max_draft_tokens_per_round: R.add(ServingRisk.DRAFT_TOKEN_BUDGET_EXCEEDED)
            if r.accepted_token_count+r.rejected_token_count!=r.proposed_token_count or r.target_verified_token_count!=r.proposed_token_count: R.add(ServingRisk.TARGET_VERIFICATION_MISMATCH)
            if r.accepted_token_count>r.target_verified_token_count: R.add(ServingRisk.UNVERIFIED_DRAFT_ACCEPTANCE)
            expected=target_verification_digest(r,m.target_model_sha256,m.tokenizer_sha256)
            if r.target_verification_sha256.casefold()!=expected.casefold(): R.add(ServingRisk.TARGET_VERIFICATION_MISMATCH)
        decode_services=[s for s in m.services if s.role==ServiceRole.DECODE]
        if len(decode_services)!=1: R.add(ServingRisk.SERVICE_ROLE_MISMATCH)
        else:
            decode=decode_services[0]
            if m.final_state_sha256.casefold()!=decode.output_evidence_sha256.casefold(): R.add(ServingRisk.FINAL_STATE_MISMATCH)
        if m.speculative_rounds and m.final_state_sha256.casefold()!=m.speculative_rounds[-1].result_state_sha256.casefold(): R.add(ServingRisk.FINAL_STATE_MISMATCH)
        if m.network_operations: R.add(ServingRisk.NETWORK_OPERATION_UNEXPECTED)
        return tuple(sorted(R,key=lambda x:x.value))
    def evaluate(self,request:InferenceSpeculativeServingRequest,m:InferenceSpeculativeServingManifest,a:VerifiedInferenceCacheLifecycleAssessment):
        self._validate_manifest(m); actual=inference_speculative_serving_manifest_digest(m)
        if actual.casefold()!=self.policy.expected_manifest_sha256.casefold(): reject(ServingRejectReason.MANIFEST_DIGEST_MISMATCH,'serving manifest differs from policy-pinned evidence')
        if request.manifest_id!=m.manifest_id or request.manifest_sha256.casefold()!=actual.casefold(): reject(ServingRejectReason.REQUEST_INVALID,'request manifest binding mismatch')
        if request.evaluated_at_epoch<m.created_at_epoch-self.policy.max_future_skew_seconds or request.evaluated_at_epoch>m.created_at_epoch+self.policy.max_manifest_age_seconds: reject(ServingRejectReason.REQUEST_INVALID,'serving manifest freshness invalid')
        service_ids=tuple(s.service_id for s in m.services); transfer_ids=tuple(t.transfer_id for t in m.transfers); round_ids=tuple(r.round_id for r in m.speculative_rounds)
        identity=(request.declared_request_id,request.declared_tenant_id,request.declared_session_id,request.declared_target_model_revision,request.declared_draft_model_revision,request.declared_service_ids,request.declared_transfer_ids,request.declared_round_ids,request.declared_final_state_sha256)
        expected=(m.request_id,m.tenant_id,m.session_id,m.target_model_revision,m.draft_model_revision,service_ids,transfer_ids,round_ids,m.final_state_sha256)
        if identity!=expected: reject(ServingRejectReason.DECLARED_SUMMARY_MISMATCH,'caller serving identity summary disagrees with evidence')
        risks=self.derive(m,a); decision=ServingDecision.ALLOW if not risks else ServingDecision.DENY; safe=not risks
        flags=(request.declared_upstream_p10c_bound,request.declared_route_safe,request.declared_draft_trust_safe,request.declared_service_binding_safe,request.declared_state_transfer_safe,request.declared_speculative_verification_safe,request.declared_final_state_safe,request.declared_serving_safe)
        if flags!=(safe,)*8: reject(ServingRejectReason.DECLARED_SUMMARY_MISMATCH,'caller serving safety summary disagrees with derived evidence')
        route_bad={ServingRisk.REQUEST_ROUTE_MISMATCH,ServingRisk.TARGET_MODEL_MISMATCH,ServingRisk.TOKENIZER_MISMATCH}; draft_bad={ServingRisk.DRAFT_MODEL_MISMATCH,ServingRisk.DRAFT_TRUST_MISMATCH,ServingRisk.TOKENIZER_MISMATCH}; service_bad={ServingRisk.SERVICE_COVERAGE_MISMATCH,ServingRisk.SERVICE_IDENTITY_MISMATCH,ServingRisk.SERVICE_ROLE_MISMATCH}; transfer_bad={ServingRisk.CROSS_TENANT_STATE_TRANSFER,ServingRisk.CROSS_SESSION_STATE_TRANSFER,ServingRisk.STATE_TRANSFER_COVERAGE_MISMATCH,ServingRisk.STATE_TRANSFER_SEQUENCE_MISMATCH,ServingRisk.STATE_TRANSFER_DIGEST_MISMATCH,ServingRisk.STATE_TRANSFER_REPLAY,ServingRisk.PREFILL_DECODE_STATE_MISMATCH,ServingRisk.PRIOR_TRANSFER_LEDGER_MISMATCH}; speculative_bad={ServingRisk.SPECULATIVE_ROUND_COVERAGE_MISMATCH,ServingRisk.SPECULATIVE_ROUND_MISMATCH,ServingRisk.DRAFT_TOKEN_BUDGET_EXCEEDED,ServingRisk.TARGET_VERIFICATION_MISMATCH,ServingRisk.UNVERIFIED_DRAFT_ACCEPTANCE}
        sha=digest_json({'manifest_id':m.manifest_id,'manifest_sha256':actual,'p10c_assessment_sha256':m.p10c_assessment_sha256,'request_id':m.request_id,'tenant_id':m.tenant_id,'session_id':m.session_id,'target_model_id':m.target_model_id,'target_model_revision':m.target_model_revision,'target_model_sha256':m.target_model_sha256,'draft_model_id':m.draft_model_id,'draft_model_revision':m.draft_model_revision,'draft_model_sha256':m.draft_model_sha256,'tokenizer_sha256':m.tokenizer_sha256,'handoff_state_sha256':m.handoff_state_sha256,'service_ids':service_ids,'transfer_ids':transfer_ids,'round_ids':round_ids,'final_state_sha256':m.final_state_sha256,'risks':risks,'decision':decision,'schema':P10D_ASSESSMENT_SCHEMA_VERSION,'mode':P10D_ASSESSMENT_MODE})
        return VerifiedInferenceSpeculativeServingAssessment(m.manifest_id,actual,m.request_id,m.tenant_id,m.session_id,decision,risks,m.p10c_assessment_sha256,m.upstream_scheduler_id,m.upstream_batch_id,m.cache_epoch,m.target_model_id,m.target_model_revision,m.draft_model_id,m.draft_model_revision,service_ids,transfer_ids,round_ids,m.final_state_sha256,ServingRisk.UPSTREAM_P10C_INVALID not in risks and ServingRisk.UPSTREAM_BINDING_MISMATCH not in risks,not bool(set(risks)&route_bad),not bool(set(risks)&draft_bad),not bool(set(risks)&service_bad),not bool(set(risks)&transfer_bad),not bool(set(risks)&speculative_bad),ServingRisk.FINAL_STATE_MISMATCH not in risks,False,False,False,False,False,False,False,P10D_ASSESSMENT_SCHEMA_VERSION,P10D_ASSESSMENT_MODE,sha)
