from __future__ import annotations
import re
from .scheduler_security_types import P10B_ASSESSMENT_MODE,P10B_ASSESSMENT_SCHEMA_VERSION,SchedulerDecision,VerifiedInferenceSchedulerAssessment
from .cache_lifecycle_types import *

_SHA=re.compile(r'^[0-9a-fA-F]{64}$'); _ID=re.compile(r'^[a-z0-9][a-z0-9._:/@-]{2,127}$')
class InferenceCacheLifecycleAnalyzer:
    def __init__(self,policy:InferenceCacheLifecyclePolicy): self.policy=policy; self._validate_policy()
    @staticmethod
    def _sha(v): return bool(_SHA.fullmatch(str(v)))
    @staticmethod
    def _id(v): return bool(_ID.fullmatch(str(v)))
    def _validate_policy(self):
        p=self.policy
        if p.policy_version!=P10C_POLICY_VERSION: reject(CacheRejectReason.POLICY_INVALID,'unexpected policy version')
        if not all(map(self._id,(p.expected_manifest_id,p.expected_upstream_scheduler_id,p.expected_upstream_batch_id))): reject(CacheRejectReason.POLICY_INVALID,'policy identity pins invalid')
        if not all(map(self._sha,(p.expected_manifest_sha256,p.expected_p10b_assessment_sha256,p.expected_zeroization_method_sha256,p.expected_prior_retired_ledger_sha256,*p.rollback_authorization_sha256_by_tenant.values(),*p.expected_entry_key_sha256_by_id.values(),*p.expected_entry_payload_sha256_by_id.values()))): reject(CacheRejectReason.POLICY_INVALID,'policy digest pins invalid')
        tenants=set(p.allowed_tenant_ids); expected_entries=set(p.expected_entry_ids)
        if not tenants or len(tenants)!=len(p.allowed_tenant_ids) or set(p.rollback_authorization_sha256_by_tenant)!=tenants or set(p.max_active_entries_by_tenant)!=tenants: reject(CacheRejectReason.POLICY_INVALID,'tenant policy maps incomplete')
        if not expected_entries or len(expected_entries)!=len(p.expected_entry_ids) or set(p.expected_entry_key_sha256_by_id)!=expected_entries or set(p.expected_entry_payload_sha256_by_id)!=expected_entries: reject(CacheRejectReason.POLICY_INVALID,'entry digest policy maps incomplete')
        if any(v<0 for v in p.max_active_entries_by_tenant.values()) or any(v<0 for v in p.min_generation_by_namespace.values()): reject(CacheRejectReason.POLICY_INVALID,'cache bounds invalid')
        if not p.min_generation_by_namespace or any(not self._id(k) for k in p.min_generation_by_namespace): reject(CacheRejectReason.POLICY_INVALID,'generation floor map invalid')
        if min(p.max_active_entry_age_seconds,p.max_manifest_age_seconds,p.max_future_skew_seconds)<0: reject(CacheRejectReason.POLICY_INVALID,'freshness bounds invalid')
    def _validate_manifest(self,m:InferenceCacheLifecycleManifest):
        if m.schema_version!=P10C_SCHEMA_VERSION or m.manifest_id!=self.policy.expected_manifest_id or not self._id(m.manifest_id) or m.created_at_epoch<=0 or m.cache_epoch<0: reject(CacheRejectReason.MANIFEST_INVALID,'manifest identity/schema/time invalid')
        if not self._sha(m.p10b_assessment_sha256) or not all(map(self._id,(m.upstream_scheduler_id,m.upstream_batch_id))) or not self._sha(m.zeroization_method_sha256): reject(CacheRejectReason.MANIFEST_INVALID,'upstream/cache method malformed')
        if not m.entries or len({e.entry_id for e in m.entries})!=len(m.entries): reject(CacheRejectReason.MANIFEST_INVALID,'cache entries empty or duplicated')
        for e in m.entries:
            ids=(e.entry_id,e.tenant_id,e.session_id,e.namespace)
            if not all(map(self._id,ids)) or (e.parent_entry_id and not self._id(e.parent_entry_id)) or min(e.epoch,e.generation,e.created_at_epoch,e.last_access_epoch,e.evicted_at_epoch,e.zeroized_at_epoch)<0 or not all(map(self._sha,(e.key_sha256,e.payload_sha256,e.zeroization_receipt_sha256))): reject(CacheRejectReason.MANIFEST_INVALID,'cache entry malformed')
            if e.last_access_epoch<e.created_at_epoch: reject(CacheRejectReason.MANIFEST_INVALID,'cache timestamps malformed')
        if len({r.operation_id for r in m.reuses})!=len(m.reuses): reject(CacheRejectReason.MANIFEST_INVALID,'reuse operation duplicated')
        for r in m.reuses:
            if not all(map(self._id,(r.operation_id,r.source_entry_id,r.target_entry_id,r.request_id,r.tenant_id,r.session_id))) or min(r.source_generation,r.target_generation)<0 or not all(map(self._sha,(r.source_key_sha256,r.target_key_sha256))): reject(CacheRejectReason.MANIFEST_INVALID,'reuse evidence malformed')
        b=m.rollback
        if not all(map(self._id,(b.operation_id,b.tenant_id,b.session_id,b.namespace,b.target_entry_id))) or min(b.current_generation,b.target_generation)<0 or not self._sha(b.authorization_sha256): reject(CacheRejectReason.MANIFEST_INVALID,'rollback evidence malformed')
        if len(m.prior_retired_entry_ids)!=len(set(m.prior_retired_entry_ids)) or not all(map(self._id,m.prior_retired_entry_ids)) or not self._sha(m.prior_retired_ledger_sha256) or m.network_operations<0: reject(CacheRejectReason.MANIFEST_INVALID,'retired ledger/network malformed')
    def _upstream_ok(self,a:VerifiedInferenceSchedulerAssessment)->bool:
        flags=(a.upstream_p10a_bound,a.scheduler_identity_verified,a.admission_limits_verified,a.tenant_resource_isolation_verified,a.weighted_fairness_verified,a.starvation_bounds_verified,a.batch_plan_verified)
        nonclaims=(a.caller_declared_safety_trusted,a.production_scheduler_integrated,a.production_gpu_quota_enforced,a.production_distributed_fairness_validated,a.production_autoscaler_integrated,a.side_channel_resistance_validated)
        return a.decision==SchedulerDecision.ALLOW and not a.risks and all(flags) and not any(nonclaims) and a.assessment_schema_version==P10B_ASSESSMENT_SCHEMA_VERSION and a.assessment_mode==P10B_ASSESSMENT_MODE
    @staticmethod
    def _zero_receipt(e:CacheEntryEvidence,method_sha:str)->str:
        return digest_json({'entry_id':e.entry_id,'payload_sha256':e.payload_sha256,'zeroization_method_sha256':method_sha})
    def derive(self,m:InferenceCacheLifecycleManifest,a:VerifiedInferenceSchedulerAssessment):
        self._validate_manifest(m); p=self.policy; R=set(); entries={e.entry_id:e for e in m.entries}
        if not self._upstream_ok(a): R.add(CacheRisk.UPSTREAM_P10B_INVALID)
        if m.p10b_assessment_sha256.casefold()!=p.expected_p10b_assessment_sha256.casefold() or a.assessment_evidence_sha256.casefold()!=p.expected_p10b_assessment_sha256.casefold() or (m.upstream_scheduler_id,m.upstream_batch_id)!=(p.expected_upstream_scheduler_id,p.expected_upstream_batch_id) or (a.scheduler_id,a.batch_id)!=(m.upstream_scheduler_id,m.upstream_batch_id): R.add(CacheRisk.UPSTREAM_BINDING_MISMATCH)
        if m.zeroization_method_sha256.casefold()!=p.expected_zeroization_method_sha256.casefold(): R.add(CacheRisk.ZEROIZATION_RECEIPT_MISMATCH)
        if set(entries)!=set(p.expected_entry_ids): R.add(CacheRisk.CACHE_ENTRY_COVERAGE_MISMATCH)
        active_by_tenant={t:0 for t in p.allowed_tenant_ids}
        for e in m.entries:
            if e.entry_id in p.expected_entry_key_sha256_by_id and (e.key_sha256.casefold()!=p.expected_entry_key_sha256_by_id[e.entry_id].casefold() or e.payload_sha256.casefold()!=p.expected_entry_payload_sha256_by_id[e.entry_id].casefold()): R.add(CacheRisk.CACHE_ENTRY_DIGEST_MISMATCH)
            if e.tenant_id not in p.allowed_tenant_ids or not e.session_id.startswith(f'tenant/{e.tenant_id}/'): R.add(CacheRisk.CACHE_OWNER_MISMATCH)
            expected_ns=(f'{e.session_id}/kv/epoch/{e.epoch}/gen/{e.generation}' if e.kind==CacheKind.KV else f'tenant/{e.tenant_id}/prefix-cache/epoch/{e.epoch}/gen/{e.generation}')
            if e.namespace!=expected_ns: R.add(CacheRisk.CACHE_NAMESPACE_MISMATCH)
            if e.epoch!=m.cache_epoch: R.add(CacheRisk.CACHE_EPOCH_MISMATCH)
            floor=p.min_generation_by_namespace.get(e.namespace)
            if floor is None: R.add(CacheRisk.CACHE_NAMESPACE_MISMATCH)
            elif e.generation<floor: R.add(CacheRisk.CACHE_GENERATION_ROLLBACK)
            if e.entry_id in m.prior_retired_entry_ids and e.state==CacheState.ACTIVE: R.add(CacheRisk.RETIRED_ENTRY_RESURRECTED)
            if e.state==CacheState.ACTIVE:
                if e.tenant_id in active_by_tenant: active_by_tenant[e.tenant_id]+=1
                if m.created_at_epoch-e.last_access_epoch>p.max_active_entry_age_seconds: R.add(CacheRisk.STALE_ACTIVE_ENTRY)
                if e.evicted_at_epoch or e.zeroized_at_epoch: R.add(CacheRisk.EVICTION_STATE_MISMATCH)
            elif e.state==CacheState.EVICTED:
                R.add(CacheRisk.ZEROIZATION_MISSING)
                if e.evicted_at_epoch<=0 or e.zeroized_at_epoch: R.add(CacheRisk.EVICTION_STATE_MISMATCH)
            elif e.state==CacheState.ZEROIZED:
                if e.evicted_at_epoch<=0 or e.zeroized_at_epoch<e.evicted_at_epoch: R.add(CacheRisk.EVICTION_STATE_MISMATCH)
                if e.zeroization_receipt_sha256.casefold()!=self._zero_receipt(e,m.zeroization_method_sha256).casefold(): R.add(CacheRisk.ZEROIZATION_RECEIPT_MISMATCH)
        if any(active_by_tenant[t]>p.max_active_entries_by_tenant[t] for t in active_by_tenant): R.add(CacheRisk.CACHE_CAPACITY_EXCEEDED)
        for r in m.reuses:
            s=entries.get(r.source_entry_id); t=entries.get(r.target_entry_id)
            if s is None or t is None: R.add(CacheRisk.PREFIX_REUSE_MISMATCH); continue
            if r.tenant_id!=s.tenant_id or r.tenant_id!=t.tenant_id: R.add(CacheRisk.CROSS_TENANT_REUSE)
            if (r.source_generation,r.target_generation)!=(s.generation,t.generation) or t.generation!=s.generation+1 or t.parent_entry_id!=s.entry_id: R.add(CacheRisk.PREFIX_REUSE_MISMATCH)
            if (r.source_key_sha256.casefold(),r.target_key_sha256.casefold())!=(s.key_sha256.casefold(),t.key_sha256.casefold()): R.add(CacheRisk.PREFIX_REUSE_MISMATCH)
            if s.key_sha256.casefold()!=t.key_sha256.casefold(): R.add(CacheRisk.PREFIX_REUSE_MISMATCH)
            if s.kind!=t.kind: R.add(CacheRisk.PREFIX_REUSE_MISMATCH)
            if r.session_id!=s.session_id or r.session_id!=t.session_id:
                if s.kind==CacheKind.KV: R.add(CacheRisk.CROSS_SESSION_KV_REUSE)
                else: R.add(CacheRisk.PREFIX_REUSE_MISMATCH)
            if s.kind==CacheKind.PREFIX and (r.tenant_id!=s.tenant_id or r.tenant_id!=t.tenant_id): R.add(CacheRisk.CROSS_TENANT_REUSE)
            if s.state!=CacheState.ACTIVE or t.state!=CacheState.ACTIVE: R.add(CacheRisk.PREFIX_REUSE_MISMATCH)
        b=m.rollback
        if b.requested:
            target=entries.get(b.target_entry_id)
            auth=p.rollback_authorization_sha256_by_tenant.get(b.tenant_id,'')
            if b.tenant_id not in p.allowed_tenant_ids or b.authorization_sha256.casefold()!=auth.casefold(): R.add(CacheRisk.ROLLBACK_UNAUTHORIZED)
            if target is None or target.state!=CacheState.ACTIVE or target.tenant_id!=b.tenant_id or target.session_id!=b.session_id or target.namespace!=b.namespace or target.generation!=b.target_generation or b.target_generation>=b.current_generation: R.add(CacheRisk.ROLLBACK_TARGET_MISMATCH)
            if target and target.entry_id in m.prior_retired_entry_ids: R.add(CacheRisk.RETIRED_ENTRY_RESURRECTED)
            if target:
                floor=p.min_generation_by_namespace.get(target.namespace)
                if floor is None or b.target_generation<floor: R.add(CacheRisk.CACHE_GENERATION_ROLLBACK)
        ledger=retired_ledger_digest(m.prior_retired_entry_ids)
        if ledger.casefold()!=m.prior_retired_ledger_sha256.casefold() or ledger.casefold()!=p.expected_prior_retired_ledger_sha256.casefold(): R.add(CacheRisk.RETIRED_LEDGER_MISMATCH)
        if m.network_operations: R.add(CacheRisk.NETWORK_OPERATION_UNEXPECTED)
        return tuple(sorted(R,key=lambda x:x.value))
    def evaluate(self,request:InferenceCacheLifecycleRequest,m:InferenceCacheLifecycleManifest,a:VerifiedInferenceSchedulerAssessment):
        self._validate_manifest(m); actual=inference_cache_lifecycle_manifest_digest(m)
        if actual.casefold()!=self.policy.expected_manifest_sha256.casefold(): reject(CacheRejectReason.MANIFEST_DIGEST_MISMATCH,'cache manifest differs from policy-pinned evidence')
        if request.manifest_id!=m.manifest_id or request.manifest_sha256.casefold()!=actual.casefold(): reject(CacheRejectReason.REQUEST_INVALID,'request manifest binding mismatch')
        if request.evaluated_at_epoch<m.created_at_epoch-self.policy.max_future_skew_seconds or request.evaluated_at_epoch>m.created_at_epoch+self.policy.max_manifest_age_seconds: reject(CacheRejectReason.REQUEST_INVALID,'cache manifest freshness invalid')
        active=tuple(e.entry_id for e in m.entries if e.state==CacheState.ACTIVE); zeroized=tuple(e.entry_id for e in m.entries if e.state==CacheState.ZEROIZED)
        if (request.declared_scheduler_id,request.declared_batch_id,request.declared_cache_epoch,request.declared_active_entry_ids,request.declared_zeroized_entry_ids)!=(m.upstream_scheduler_id,m.upstream_batch_id,m.cache_epoch,active,zeroized): reject(CacheRejectReason.DECLARED_SUMMARY_MISMATCH,'caller cache identity summary disagrees with evidence')
        risks=self.derive(m,a); decision=CacheDecision.ALLOW if not risks else CacheDecision.DENY; safe=not risks
        flags=(request.declared_upstream_p10b_bound,request.declared_ownership_safe,request.declared_reuse_isolation_safe,request.declared_eviction_safe,request.declared_zeroization_safe,request.declared_rollback_safe,request.declared_cache_lifecycle_safe)
        if flags!=(safe,)*7: reject(CacheRejectReason.DECLARED_SUMMARY_MISMATCH,'caller cache safety summary disagrees with derived evidence')
        ownership_bad={CacheRisk.CACHE_ENTRY_COVERAGE_MISMATCH,CacheRisk.CACHE_ENTRY_DIGEST_MISMATCH,CacheRisk.CACHE_OWNER_MISMATCH,CacheRisk.CACHE_NAMESPACE_MISMATCH,CacheRisk.CACHE_EPOCH_MISMATCH,CacheRisk.CACHE_CAPACITY_EXCEEDED,CacheRisk.STALE_ACTIVE_ENTRY}; reuse_bad={CacheRisk.CROSS_TENANT_REUSE,CacheRisk.CROSS_SESSION_KV_REUSE,CacheRisk.PREFIX_REUSE_MISMATCH}; eviction_bad={CacheRisk.EVICTION_STATE_MISMATCH,CacheRisk.ZEROIZATION_MISSING}; rollback_bad={CacheRisk.ROLLBACK_UNAUTHORIZED,CacheRisk.ROLLBACK_TARGET_MISMATCH,CacheRisk.CACHE_GENERATION_ROLLBACK,CacheRisk.RETIRED_ENTRY_RESURRECTED}; sha=digest_json({'manifest_id':m.manifest_id,'scheduler_id':m.upstream_scheduler_id,'batch_id':m.upstream_batch_id,'cache_epoch':m.cache_epoch,'risks':risks,'decision':decision,'schema':P10C_ASSESSMENT_SCHEMA_VERSION,'mode':P10C_ASSESSMENT_MODE})
        return VerifiedInferenceCacheLifecycleAssessment(m.manifest_id,m.upstream_scheduler_id,m.upstream_batch_id,m.cache_epoch,decision,risks,m.p10b_assessment_sha256,active,zeroized,m.prior_retired_entry_ids,CacheRisk.UPSTREAM_P10B_INVALID not in risks and CacheRisk.UPSTREAM_BINDING_MISMATCH not in risks,not bool(set(risks)&ownership_bad),not bool(set(risks)&reuse_bad),not bool(set(risks)&eviction_bad),CacheRisk.ZEROIZATION_RECEIPT_MISMATCH not in risks and CacheRisk.ZEROIZATION_MISSING not in risks,not bool(set(risks)&rollback_bad),False,False,False,False,False,False,P10C_ASSESSMENT_SCHEMA_VERSION,P10C_ASSESSMENT_MODE,sha)
