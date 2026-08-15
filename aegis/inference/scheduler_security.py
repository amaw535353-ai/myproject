from __future__ import annotations
import re
from .tenant_isolation_types import P10A_ASSESSMENT_MODE,P10A_ASSESSMENT_SCHEMA_VERSION,InferenceDecision,VerifiedInferenceTenantIsolationAssessment
from .scheduler_security_types import *

_SHA=re.compile(r'^[0-9a-fA-F]{64}$'); _ID=re.compile(r'^[a-z0-9][a-z0-9._:/@-]{2,127}$')
class InferenceSchedulerSecurityAnalyzer:
    def __init__(self,policy:InferenceSchedulerPolicy): self.policy=policy; self._validate_policy()
    @staticmethod
    def _sha(v): return bool(_SHA.fullmatch(str(v)))
    @staticmethod
    def _id(v): return bool(_ID.fullmatch(str(v)))
    def _validate_policy(self):
        p=self.policy
        if p.policy_version!=P10B_POLICY_VERSION: reject(SchedulerRejectReason.POLICY_INVALID,'unexpected policy version')
        if not all(map(self._id,(p.expected_manifest_id,p.expected_upstream_request_id,p.expected_upstream_tenant_id,p.expected_upstream_session_id))): reject(SchedulerRejectReason.POLICY_INVALID,'policy identity pins invalid')
        if not all(map(self._sha,(p.expected_manifest_sha256,p.expected_p10a_assessment_sha256,p.expected_prior_admitted_ledger_sha256))): reject(SchedulerRejectReason.POLICY_INVALID,'policy digests must be SHA-256')
        if not p.allowed_scheduler_ids or not p.allowed_worker_pool_ids or not p.allowed_tenant_ids: reject(SchedulerRejectReason.POLICY_INVALID,'policy allowlists cannot be empty')
        if len(set(p.allowed_scheduler_ids))!=len(p.allowed_scheduler_ids) or len(set(p.allowed_worker_pool_ids))!=len(p.allowed_worker_pool_ids) or len(set(p.allowed_tenant_ids))!=len(p.allowed_tenant_ids): reject(SchedulerRejectReason.POLICY_INVALID,'policy allowlists contain duplicates')
        tenants=set(p.allowed_tenant_ids); priorities=set(p.allowed_priority_classes)
        maps=(p.tenant_weights,p.max_concurrent_by_tenant,p.max_queue_depth_by_tenant,p.max_reserved_tokens_by_tenant,p.max_reserved_memory_by_tenant)
        if any(set(x)!=tenants for x in maps): reject(SchedulerRejectReason.POLICY_INVALID,'tenant policy maps incomplete')
        if set(p.priority_rank)!=priorities or set(p.max_wait_seconds_by_priority)!=priorities or not priorities: reject(SchedulerRejectReason.POLICY_INVALID,'priority policy maps incomplete')
        if any(v<=0 for v in p.tenant_weights.values()) or any(v<0 for m in maps[1:] for v in m.values()): reject(SchedulerRejectReason.POLICY_INVALID,'tenant limits invalid')
        if any(v<0 for v in p.priority_rank.values()) or any(v<0 for v in p.max_wait_seconds_by_priority.values()): reject(SchedulerRejectReason.POLICY_INVALID,'priority limits invalid')
        bounds=(p.deficit_quantum,p.max_deficit_units,p.max_request_tokens,p.max_request_memory_units,p.max_global_slots,p.max_global_reserved_tokens,p.max_global_memory_units,p.max_batch_size,p.max_batch_reserved_tokens,p.max_batch_memory_units,p.max_manifest_age_seconds,p.max_future_skew_seconds)
        if any(v<0 for v in bounds) or min(p.deficit_quantum,p.max_request_tokens,p.max_request_memory_units,p.max_global_slots,p.max_batch_size)<=0: reject(SchedulerRejectReason.POLICY_INVALID,'scheduler bounds invalid')
    def _validate_manifest(self,m:InferenceSchedulerManifest):
        if m.schema_version!=P10B_SCHEMA_VERSION or m.manifest_id!=self.policy.expected_manifest_id or not self._id(m.manifest_id) or m.created_at_epoch<=0 or m.scheduling_epoch<0: reject(SchedulerRejectReason.MANIFEST_INVALID,'manifest identity/schema/time invalid')
        if not self._sha(m.p10a_assessment_sha256) or not all(map(self._id,(m.upstream_request_id,m.upstream_tenant_id,m.upstream_session_id,m.scheduler_id))): reject(SchedulerRejectReason.MANIFEST_INVALID,'upstream/scheduler evidence malformed')
        if not m.requests or len({r.request_id for r in m.requests})!=len(m.requests): reject(SchedulerRejectReason.MANIFEST_INVALID,'request evidence empty or duplicated')
        for r in m.requests:
            if not all(map(self._id,(r.request_id,r.tenant_id,r.session_id,r.priority_class))) or min(r.sequence_no,r.prompt_tokens,r.max_output_tokens,r.memory_units,r.queue_age_seconds)<0: reject(SchedulerRejectReason.MANIFEST_INVALID,'request evidence malformed')
            if r.running and (not r.admitted or r.cancelled): reject(SchedulerRejectReason.MANIFEST_INVALID,'running request state malformed')
        if len({s.tenant_id for s in m.tenant_states})!=len(m.tenant_states): reject(SchedulerRejectReason.MANIFEST_INVALID,'duplicate tenant scheduler state')
        for s in m.tenant_states:
            if not self._id(s.tenant_id) or min(s.configured_weight,s.deficit_before,s.service_units,s.deficit_after,s.active_requests,s.queued_requests,s.reserved_tokens,s.reserved_memory_units)<0: reject(SchedulerRejectReason.MANIFEST_INVALID,'tenant scheduler state malformed')
        z=m.resources
        if not self._id(z.worker_pool_id) or min(z.total_slots,z.active_slots,z.total_memory_units,z.used_memory_units)<0: reject(SchedulerRejectReason.MANIFEST_INVALID,'resource evidence malformed')
        b=m.selected_batch
        if not all(map(self._id,(b.batch_id,b.scheduler_id,b.tenant_id))) or len(b.request_ids)!=len(set(b.request_ids)) or min(b.total_reserved_tokens,b.total_memory_units)<0: reject(SchedulerRejectReason.MANIFEST_INVALID,'batch plan malformed')
        if len(m.prior_admitted_request_ids)!=len(set(m.prior_admitted_request_ids)) or not all(map(self._id,m.prior_admitted_request_ids)) or not self._sha(m.prior_admitted_ledger_sha256) or m.network_operations<0: reject(SchedulerRejectReason.MANIFEST_INVALID,'admitted ledger/network evidence malformed')
    def _upstream_ok(self,a:VerifiedInferenceTenantIsolationAssessment)->bool:
        flags=(a.upstream_deployment_bound,a.upstream_promotion_bound,a.route_identity_verified,a.request_identity_verified,a.batch_isolation_verified,a.kv_and_prefix_cache_isolation_verified,a.output_binding_verified,a.request_replay_clear)
        nonclaims=(a.caller_declared_safety_trusted,a.production_inference_gateway_integrated,a.production_scheduler_isolation_enforced,a.production_kv_cache_memory_isolation_verified,a.side_channel_resistance_validated,a.hardware_attestation_verified)
        return a.decision==InferenceDecision.ALLOW and not a.risks and all(flags) and not any(nonclaims) and a.assessment_schema_version==P10A_ASSESSMENT_SCHEMA_VERSION and a.assessment_mode==P10A_ASSESSMENT_MODE
    def _greedy_batch(self,requests,tenant):
        p=self.policy
        eligible=[r for r in requests if r.tenant_id==tenant and r.admitted and not r.running and not r.cancelled]
        eligible.sort(key=lambda r:(-p.priority_rank.get(r.priority_class,-1),-r.queue_age_seconds,r.request_id))
        chosen=[]; tok=mem=0
        for r in eligible:
            rt=r.prompt_tokens+r.max_output_tokens
            if len(chosen)>=p.max_batch_size: break
            if tok+rt<=p.max_batch_reserved_tokens and mem+r.memory_units<=p.max_batch_memory_units:
                chosen.append(r.request_id); tok+=rt; mem+=r.memory_units
        return tuple(chosen),tok,mem
    def derive(self,m:InferenceSchedulerManifest,a:VerifiedInferenceTenantIsolationAssessment):
        self._validate_manifest(m); p=self.policy; R=set(); reqs=m.requests; states={s.tenant_id:s for s in m.tenant_states}; batch=m.selected_batch
        if not self._upstream_ok(a): R.add(SchedulerRisk.UPSTREAM_P10A_INVALID)
        if m.p10a_assessment_sha256.casefold()!=p.expected_p10a_assessment_sha256.casefold() or a.assessment_evidence_sha256.casefold()!=p.expected_p10a_assessment_sha256.casefold() or (m.upstream_request_id,m.upstream_tenant_id,m.upstream_session_id)!=(p.expected_upstream_request_id,p.expected_upstream_tenant_id,p.expected_upstream_session_id) or (a.request_id,a.tenant_id,a.session_id)!=(m.upstream_request_id,m.upstream_tenant_id,m.upstream_session_id): R.add(SchedulerRisk.UPSTREAM_BINDING_MISMATCH)
        if m.scheduler_id not in p.allowed_scheduler_ids or batch.scheduler_id!=m.scheduler_id or m.resources.worker_pool_id not in p.allowed_worker_pool_ids: R.add(SchedulerRisk.SCHEDULER_IDENTITY_MISMATCH)
        if m.upstream_request_id not in {r.request_id for r in reqs}: R.add(SchedulerRisk.REQUEST_COVERAGE_MISMATCH)
        if any(r.tenant_id not in p.allowed_tenant_ids or not r.session_id.startswith(f'tenant/{r.tenant_id}/session/') for r in reqs): R.add(SchedulerRisk.REQUEST_TENANT_MISMATCH)
        upstream_rows=[r for r in reqs if r.request_id==m.upstream_request_id]
        if len(upstream_rows)!=1 or (upstream_rows[0].tenant_id,upstream_rows[0].session_id)!=(m.upstream_tenant_id,m.upstream_session_id): R.add(SchedulerRisk.REQUEST_TENANT_MISMATCH)
        if any(r.request_id in m.prior_admitted_request_ids for r in reqs): R.add(SchedulerRisk.DUPLICATE_REQUEST)
        if set(states)!=set(p.allowed_tenant_ids): R.add(SchedulerRisk.REQUEST_COVERAGE_MISMATCH)
        by_tenant={t:[r for r in reqs if r.tenant_id==t] for t in p.allowed_tenant_ids}
        global_reserved_tokens=global_reserved_mem=active_total=0
        for r in reqs:
            if r.priority_class not in p.allowed_priority_classes: R.add(SchedulerRisk.PRIORITY_POLICY_MISMATCH)
            rt=r.prompt_tokens+r.max_output_tokens
            if rt>p.max_request_tokens or r.memory_units>p.max_request_memory_units: R.add(SchedulerRisk.REQUEST_RESOURCE_LIMIT_EXCEEDED)
            if r.admitted and not r.cancelled: global_reserved_tokens+=rt; global_reserved_mem+=r.memory_units
            if r.running: active_total+=1
            if r.admitted and not r.running and not r.cancelled and r.priority_class in p.max_wait_seconds_by_priority and r.queue_age_seconds>p.max_wait_seconds_by_priority[r.priority_class]: R.add(SchedulerRisk.STARVATION_BOUND_EXCEEDED)
        for t,items in by_tenant.items():
            st=states.get(t)
            if st is None: continue
            active=sum(r.running for r in items); queued=sum((not r.running and not r.cancelled) for r in items); reserved_tokens=sum((r.prompt_tokens+r.max_output_tokens) for r in items if r.admitted and not r.cancelled); reserved_mem=sum(r.memory_units for r in items if r.admitted and not r.cancelled)
            if active>p.max_concurrent_by_tenant[t]: R.add(SchedulerRisk.TENANT_CONCURRENCY_EXCEEDED)
            if queued>p.max_queue_depth_by_tenant[t]: R.add(SchedulerRisk.TENANT_QUEUE_DEPTH_EXCEEDED)
            if reserved_tokens>p.max_reserved_tokens_by_tenant[t]: R.add(SchedulerRisk.TENANT_TOKEN_BUDGET_EXCEEDED)
            if reserved_mem>p.max_reserved_memory_by_tenant[t]: R.add(SchedulerRisk.TENANT_MEMORY_BUDGET_EXCEEDED)
            expected_service=batch.total_reserved_tokens if batch.tenant_id==t else 0
            expected_after=st.deficit_before+p.tenant_weights[t]*p.deficit_quantum-expected_service
            if st.configured_weight!=p.tenant_weights[t] or st.deficit_before>p.max_deficit_units or st.service_units!=expected_service or st.deficit_after!=expected_after or (st.active_requests,st.queued_requests,st.reserved_tokens,st.reserved_memory_units)!=(active,queued,reserved_tokens,reserved_mem): R.add(SchedulerRisk.FAIRNESS_STATE_MISMATCH)
        z=m.resources
        if z.total_slots>p.max_global_slots or z.active_slots>z.total_slots or z.active_slots!=active_total or z.total_memory_units>p.max_global_memory_units or z.used_memory_units>z.total_memory_units or z.used_memory_units!=sum(r.memory_units for r in reqs if r.running) or global_reserved_tokens>p.max_global_reserved_tokens or global_reserved_mem>p.max_global_memory_units: R.add(SchedulerRisk.GLOBAL_CAPACITY_EXCEEDED)
        eligible_tenants=[]
        for t,items in by_tenant.items():
            if any(r.admitted and not r.running and not r.cancelled for r in items) and t in states:
                eligible_tenants.append(t)
        if eligible_tenants:
            expected_tenant=min(eligible_tenants,key=lambda t:(-(states[t].deficit_before+p.tenant_weights[t]*p.deficit_quantum),t))
            if batch.tenant_id!=expected_tenant: R.add(SchedulerRisk.FAIRNESS_SELECTION_MISMATCH)
        else: R.add(SchedulerRisk.BATCH_PLAN_MISMATCH)
        ids={r.request_id:r for r in reqs}
        if batch.tenant_id not in p.allowed_tenant_ids or any(i not in ids or ids[i].tenant_id!=batch.tenant_id for i in batch.request_ids): R.add(SchedulerRisk.BATCH_PLAN_MISMATCH)
        expected_ids,expected_tok,expected_mem=self._greedy_batch(reqs,batch.tenant_id)
        if batch.request_ids!=expected_ids or batch.total_reserved_tokens!=expected_tok or batch.total_memory_units!=expected_mem: R.add(SchedulerRisk.BATCH_PLAN_MISMATCH)
        if len(batch.request_ids)>p.max_batch_size or batch.total_reserved_tokens>p.max_batch_reserved_tokens or batch.total_memory_units>p.max_batch_memory_units: R.add(SchedulerRisk.BATCH_CAPACITY_EXCEEDED)
        ledger=admitted_ledger_digest(m.prior_admitted_request_ids)
        if ledger.casefold()!=m.prior_admitted_ledger_sha256.casefold() or ledger.casefold()!=p.expected_prior_admitted_ledger_sha256.casefold(): R.add(SchedulerRisk.ADMITTED_LEDGER_MISMATCH)
        if m.network_operations: R.add(SchedulerRisk.NETWORK_OPERATION_UNEXPECTED)
        return tuple(sorted(R,key=lambda x:x.value))
    def evaluate(self,request:InferenceSchedulerRequest,m:InferenceSchedulerManifest,a:VerifiedInferenceTenantIsolationAssessment):
        self._validate_manifest(m); actual=inference_scheduler_manifest_digest(m)
        if actual.casefold()!=self.policy.expected_manifest_sha256.casefold(): reject(SchedulerRejectReason.MANIFEST_DIGEST_MISMATCH,'scheduler manifest differs from policy-pinned evidence')
        if request.manifest_id!=m.manifest_id or request.manifest_sha256.casefold()!=actual.casefold(): reject(SchedulerRejectReason.REQUEST_INVALID,'request manifest binding mismatch')
        if request.evaluated_at_epoch<m.created_at_epoch-self.policy.max_future_skew_seconds or request.evaluated_at_epoch>m.created_at_epoch+self.policy.max_manifest_age_seconds: reject(SchedulerRejectReason.REQUEST_INVALID,'scheduler manifest freshness invalid')
        admitted=tuple(r.request_id for r in m.requests if r.admitted and not r.cancelled); b=m.selected_batch
        if (request.declared_scheduler_id,request.declared_batch_id,request.declared_selected_tenant_id,request.declared_admitted_request_ids,request.declared_batch_request_ids)!=(m.scheduler_id,b.batch_id,b.tenant_id,admitted,b.request_ids): reject(SchedulerRejectReason.DECLARED_SUMMARY_MISMATCH,'caller scheduler identity summary disagrees with evidence')
        risks=self.derive(m,a); decision=SchedulerDecision.ALLOW if not risks else SchedulerDecision.DENY; safe=not risks
        flags=(request.declared_upstream_p10a_bound,request.declared_admission_limits_safe,request.declared_resource_isolation_safe,request.declared_weighted_fairness_safe,request.declared_starvation_bounds_safe,request.declared_batch_plan_safe,request.declared_scheduler_safe)
        if flags!=(safe,)*7: reject(SchedulerRejectReason.DECLARED_SUMMARY_MISMATCH,'caller scheduler safety summary disagrees with derived evidence')
        tenant_ids=tuple(sorted({r.tenant_id for r in m.requests})); total_tok=sum(r.prompt_tokens+r.max_output_tokens for r in m.requests if r.admitted and not r.cancelled); total_mem=sum(r.memory_units for r in m.requests if r.admitted and not r.cancelled)
        admission_bad={SchedulerRisk.REQUEST_RESOURCE_LIMIT_EXCEEDED,SchedulerRisk.TENANT_CONCURRENCY_EXCEEDED,SchedulerRisk.TENANT_QUEUE_DEPTH_EXCEEDED,SchedulerRisk.TENANT_TOKEN_BUDGET_EXCEEDED,SchedulerRisk.TENANT_MEMORY_BUDGET_EXCEEDED,SchedulerRisk.GLOBAL_CAPACITY_EXCEEDED}; fairness_bad={SchedulerRisk.FAIRNESS_STATE_MISMATCH,SchedulerRisk.FAIRNESS_SELECTION_MISMATCH}; batch_bad={SchedulerRisk.BATCH_PLAN_MISMATCH,SchedulerRisk.BATCH_CAPACITY_EXCEEDED}; sha=digest_json({'manifest_id':m.manifest_id,'scheduler_id':m.scheduler_id,'batch_id':b.batch_id,'selected_tenant_id':b.tenant_id,'risks':risks,'decision':decision,'schema':P10B_ASSESSMENT_SCHEMA_VERSION,'mode':P10B_ASSESSMENT_MODE})
        return VerifiedInferenceSchedulerAssessment(m.manifest_id,m.scheduler_id,b.batch_id,b.tenant_id,decision,risks,m.p10a_assessment_sha256,admitted,b.request_ids,tenant_ids,total_tok,total_mem,SchedulerRisk.UPSTREAM_P10A_INVALID not in risks and SchedulerRisk.UPSTREAM_BINDING_MISMATCH not in risks,SchedulerRisk.SCHEDULER_IDENTITY_MISMATCH not in risks,not bool(set(risks)&admission_bad),not bool(set(risks)&{SchedulerRisk.TENANT_TOKEN_BUDGET_EXCEEDED,SchedulerRisk.TENANT_MEMORY_BUDGET_EXCEEDED,SchedulerRisk.GLOBAL_CAPACITY_EXCEEDED}),not bool(set(risks)&fairness_bad),SchedulerRisk.STARVATION_BOUND_EXCEEDED not in risks,not bool(set(risks)&batch_bad),False,False,False,False,False,False,P10B_ASSESSMENT_SCHEMA_VERSION,P10B_ASSESSMENT_MODE,sha)
