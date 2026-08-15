from __future__ import annotations
import re
from .data_provenance_types import P9A_ASSESSMENT_MODE,P9A_ASSESSMENT_SCHEMA_VERSION,TrainingDataDecision
from .data_poisoning_types import *
_SHA=re.compile(r'^[0-9a-fA-F]{64}$')
class TrainingDataPoisoningAnalyzer:
    def __init__(self, policy:TrainingPoisoningPolicy): self.policy=policy; self._validate_policy()
    @staticmethod
    def _sha(v): return bool(_SHA.fullmatch(str(v)))
    def _validate_policy(self):
        p=self.policy
        if p.policy_version!=P9B_POLICY_VERSION: reject(PoisoningRejectReason.POLICY_INVALID,'unexpected policy version')
        if not p.expected_manifest_id or not p.expected_dataset_id or not p.expected_dataset_version: reject(PoisoningRejectReason.POLICY_INVALID,'identity pins required')
        if not all(self._sha(x) for x in (p.expected_manifest_sha256,p.expected_p9a_assessment_sha256,p.expected_p9a_final_dataset_sha256)): reject(PoisoningRejectReason.POLICY_INVALID,'digest pins must be sha256')
        keys=set(p.expected_record_sha256_by_id)
        for m in (p.expected_source_by_record_id,p.expected_contributor_by_record_id,p.expected_label_by_record_id):
            if set(m)!=keys: reject(PoisoningRejectReason.POLICY_INVALID,'record maps must cover identical IDs')
        if set(p.contributor_trust_by_id)!=set(p.contributor_weight_bps_by_id): reject(PoisoningRejectReason.POLICY_INVALID,'contributor maps mismatch')
        if not (0<=p.minimum_review_weight_bps<=10000 and 0<p.max_contributor_share_bps<=10000 and 0<=p.max_anomaly_score_bps<=10000 and 0<=p.min_label_confidence_bps<=10000 and p.max_duplicate_cluster_size>0): reject(PoisoningRejectReason.POLICY_INVALID,'invalid thresholds')
        if p.max_manifest_age_seconds<0 or p.max_future_skew_seconds<0: reject(PoisoningRejectReason.POLICY_INVALID,'invalid freshness')
    def _validate_manifest(self,m:TrainingPoisoningManifest):
        if m.schema_version!=P9B_SCHEMA_VERSION or m.manifest_id!=self.policy.expected_manifest_id or m.dataset_id!=self.policy.expected_dataset_id or m.dataset_version!=self.policy.expected_dataset_version: reject(PoisoningRejectReason.MANIFEST_INVALID,'manifest identity/schema mismatch')
        if not self._sha(m.p9a_assessment_sha256) or not self._sha(m.p9a_final_dataset_sha256): reject(PoisoningRejectReason.MANIFEST_INVALID,'upstream digests invalid')
        for seq,name in ((m.contributors,'contributor'),(m.records,'record'),(m.reviews,'review')):
            ids=[getattr(x,name+'_id') for x in seq]
            if len(ids)!=len(set(ids)): reject(PoisoningRejectReason.MANIFEST_INVALID,f'duplicate {name} IDs')
        if len(m.included_record_ids)!=len(set(m.included_record_ids)): reject(PoisoningRejectReason.MANIFEST_INVALID,'duplicate included record IDs')
        for c in m.contributors:
            if not c.contributor_id or not 0<=c.trust_weight_bps<=10000: reject(PoisoningRejectReason.MANIFEST_INVALID,'invalid contributor evidence')
        for r in m.records:
            if not r.record_id or not r.source_id or not r.contributor_id or not r.label or not self._sha(r.payload_sha256): reject(PoisoningRejectReason.MANIFEST_INVALID,'invalid record evidence')
            if not 0<=r.label_confidence_bps<=10000 or not 0<=r.anomaly_score_bps<=10000: reject(PoisoningRejectReason.MANIFEST_INVALID,'invalid record scores')
            if len(r.poisoning_signal_ids)!=len(set(r.poisoning_signal_ids)) or len(r.review_ids)!=len(set(r.review_ids)): reject(PoisoningRejectReason.MANIFEST_INVALID,'duplicate record signal/review IDs')
        for v in m.reviews:
            if not v.review_id or not v.record_id or not v.reviewer_id or not self._sha(v.reviewed_payload_sha256) or not self._sha(v.evidence_sha256): reject(PoisoningRejectReason.MANIFEST_INVALID,'invalid review evidence')
    def _validate_upstream(self,a):
        flags=(getattr(a,'exact_manifest_binding_verified',False),getattr(a,'trusted_source_snapshots_verified',False),getattr(a,'record_hash_coverage_verified',False),getattr(a,'split_isolation_verified',False),getattr(a,'transform_lineage_verified',False))
        return (getattr(a,'decision',None)==TrainingDataDecision.ALLOW and not getattr(a,'risks',()) and all(flags) and getattr(a,'dataset_id',None)==self.policy.expected_dataset_id and getattr(a,'dataset_version',None)==self.policy.expected_dataset_version and not getattr(a,'caller_declared_training_data_safety_trusted',True) and not getattr(a,'production_data_lake_integration',True) and not getattr(a,'production_training_pipeline_attestation',True) and not getattr(a,'cryptographic_source_authentication',True) and getattr(a,'assessment_schema_version',None)==P9A_ASSESSMENT_SCHEMA_VERSION and getattr(a,'assessment_mode',None)==P9A_ASSESSMENT_MODE and getattr(a,'network_operations',1)==0)
    def derive(self,m:TrainingPoisoningManifest,p9a,now:int):
        self._validate_manifest(m); p=self.policy; risks=set()
        if not self._validate_upstream(p9a): risks.add(PoisoningRisk.UPSTREAM_P9A_INVALID)
        if m.p9a_assessment_sha256.casefold()!=p.expected_p9a_assessment_sha256.casefold() or getattr(p9a,'assessment_evidence_sha256','').casefold()!=p.expected_p9a_assessment_sha256.casefold() or m.p9a_final_dataset_sha256.casefold()!=p.expected_p9a_final_dataset_sha256.casefold() or getattr(p9a,'final_dataset_sha256','').casefold()!=p.expected_p9a_final_dataset_sha256.casefold(): risks.add(PoisoningRisk.UPSTREAM_BINDING_MISMATCH)
        contributors={c.contributor_id:c for c in m.contributors}; records={r.record_id:r for r in m.records}; reviews={v.review_id:v for v in m.reviews}
        expected_ids=set(p.expected_record_sha256_by_id)
        if set(records)!=expected_ids: risks.add(PoisoningRisk.RECORD_COVERAGE_MISMATCH)
        expected_contributors=set(p.contributor_trust_by_id)
        if set(contributors)!=expected_contributors: risks.add(PoisoningRisk.CONTRIBUTOR_IDENTITY_MISMATCH)
        for cid in expected_contributors & set(contributors):
            c=contributors[cid]
            if c.trust!=p.contributor_trust_by_id[cid]: risks.add(PoisoningRisk.CONTRIBUTOR_TRUST_MISMATCH)
            if c.trust_weight_bps!=p.contributor_weight_bps_by_id[cid]: risks.add(PoisoningRisk.CONTRIBUTOR_WEIGHT_MISMATCH)
        counts={cid:0 for cid in contributors}
        cluster_counts={}
        computed_quarantine=set(); reviewed_count=0; weighted_score=0
        allowed_signals=set(p.allowed_poisoning_signal_ids)
        for rid in sorted(expected_ids & set(records)):
            r=records[rid]
            if r.payload_sha256.casefold()!=p.expected_record_sha256_by_id[rid].casefold(): risks.add(PoisoningRisk.RECORD_DIGEST_MISMATCH)
            if r.source_id!=p.expected_source_by_record_id[rid]: risks.add(PoisoningRisk.RECORD_SOURCE_MISMATCH)
            if r.contributor_id in contributors:
                counts[r.contributor_id]=counts.get(r.contributor_id,0)+1
            if r.contributor_id!=p.expected_contributor_by_record_id[rid] or r.contributor_id not in contributors:
                risks.add(PoisoningRisk.CONTRIBUTOR_IDENTITY_MISMATCH)
            if r.label!=p.expected_label_by_record_id[rid]: risks.add(PoisoningRisk.LABEL_MISMATCH)
            if r.label_confidence_bps<p.min_label_confidence_bps: risks.add(PoisoningRisk.LABEL_CONFIDENCE_INVALID)
            if r.anomaly_score_bps>p.max_anomaly_score_bps: risks.add(PoisoningRisk.ANOMALY_SCORE_EXCEEDED); computed_quarantine.add(rid)
            if set(r.poisoning_signal_ids)-allowed_signals: risks.add(PoisoningRisk.POISONING_SIGNAL_PRESENT); computed_quarantine.add(rid)
            cluster_counts[r.duplicate_cluster_id]=cluster_counts.get(r.duplicate_cluster_id,0)+1
            c=contributors.get(r.contributor_id)
            weight=0 if c is None else c.trust_weight_bps
            weighted_score += ((10000-weight)*(r.anomaly_score_bps+1000*len(r.poisoning_signal_ids)))//10000
            required_review=weight<p.minimum_review_weight_bps
            valid_reviews=[]
            for review_id in r.review_ids:
                v=reviews.get(review_id)
                if v is None or v.record_id!=rid or v.reviewer_id not in p.trusted_reviewer_ids or v.reviewed_payload_sha256.casefold()!=r.payload_sha256.casefold() or v.evidence_sha256.casefold()!=review_evidence_digest(v).casefold(): risks.add(PoisoningRisk.REVIEW_INVALID); continue
                valid_reviews.append(v)
            if valid_reviews: reviewed_count+=1
            if required_review and not valid_reviews: risks.add(PoisoningRisk.REVIEW_REQUIRED); computed_quarantine.add(rid)
            approved={v.approved_label for v in valid_reviews if v.decision==ReviewDecision.APPROVE}
            rejected=any(v.decision==ReviewDecision.REJECT for v in valid_reviews)
            if len(approved)>1 or (approved and r.label not in approved) or rejected: risks.add(PoisoningRisk.REVIEW_CONFLICT); computed_quarantine.add(rid)
            if r.quarantined and rid not in computed_quarantine: risks.add(PoisoningRisk.QUARANTINE_BYPASS)
        total=max(1,len(records))
        if any((count*10000)//total>p.max_contributor_share_bps for count in counts.values()): risks.add(PoisoningRisk.CONTRIBUTOR_CONCENTRATION)
        if any(v>p.max_duplicate_cluster_size for k,v in cluster_counts.items() if k): risks.add(PoisoningRisk.DUPLICATE_CLUSTER_ABUSE)
        declared_q={r.record_id for r in m.records if r.quarantined}
        if computed_quarantine-declared_q: risks.add(PoisoningRisk.QUARANTINE_REQUIRED)
        expected_included=tuple(sorted(set(records)-declared_q))
        if tuple(sorted(m.included_record_ids))!=expected_included: risks.add(PoisoningRisk.INCLUDED_RECORD_SET_MISMATCH)
        return tuple(sorted(risks,key=lambda x:x.value)), expected_included, tuple(sorted(declared_q)), reviewed_count, weighted_score
    def evaluate(self,req:TrainingPoisoningRequest,m:TrainingPoisoningManifest,p9a):
        self._validate_manifest(m); actual=training_poisoning_manifest_digest(m)
        if actual.casefold()!=self.policy.expected_manifest_sha256.casefold(): reject(PoisoningRejectReason.MANIFEST_DIGEST_MISMATCH,'manifest differs from policy pin')
        if req.manifest_id!=m.manifest_id or req.manifest_sha256.casefold()!=actual or req.dataset_id!=m.dataset_id or req.dataset_version!=m.dataset_version: reject(PoisoningRejectReason.REQUEST_INVALID,'request binding mismatch')
        if req.evaluated_at_epoch<m.created_at_epoch-self.policy.max_future_skew_seconds or req.evaluated_at_epoch>m.created_at_epoch+self.policy.max_manifest_age_seconds: reject(PoisoningRejectReason.REQUEST_INVALID,'manifest freshness invalid')
        risks,included,quarantined,reviewed,score=self.derive(m,p9a,req.evaluated_at_epoch); decision=PoisoningDecision.DENY if risks else PoisoningDecision.ALLOW
        if tuple(sorted(req.declared_included_record_ids))!=included or tuple(sorted(req.declared_quarantined_record_ids))!=quarantined or req.declared_weighted_risk_score!=score or req.declared_training_data_safe!=(decision==PoisoningDecision.ALLOW) or req.declared_label_integrity_verified!=(PoisoningRisk.LABEL_MISMATCH not in risks): reject(PoisoningRejectReason.DECLARED_SUMMARY_MISMATCH,'caller summary differs from evidence')
        s=set(risks); assessment_sha=digest_json({'manifest':m.manifest_id,'p9a':m.p9a_assessment_sha256,'risks':risks,'decision':decision,'included':included,'quarantined':quarantined,'score':score,'schema':P9B_ASSESSMENT_SCHEMA_VERSION,'mode':P9B_ASSESSMENT_MODE})
        return VerifiedTrainingPoisoningAssessment(m.manifest_id,m.dataset_id,m.dataset_version,decision,risks,len(m.records),included,quarantined,len(m.contributors),reviewed,score,not bool(s&{PoisoningRisk.UPSTREAM_P9A_INVALID,PoisoningRisk.UPSTREAM_BINDING_MISMATCH}),not bool(s&{PoisoningRisk.RECORD_COVERAGE_MISMATCH,PoisoningRisk.RECORD_DIGEST_MISMATCH,PoisoningRisk.RECORD_SOURCE_MISMATCH}),PoisoningRisk.LABEL_MISMATCH not in s,not bool(s&{PoisoningRisk.CONTRIBUTOR_IDENTITY_MISMATCH,PoisoningRisk.CONTRIBUTOR_TRUST_MISMATCH,PoisoningRisk.CONTRIBUTOR_WEIGHT_MISMATCH,PoisoningRisk.CONTRIBUTOR_CONCENTRATION}),not bool(s&{PoisoningRisk.ANOMALY_SCORE_EXCEEDED,PoisoningRisk.POISONING_SIGNAL_PRESENT,PoisoningRisk.DUPLICATE_CLUSTER_ABUSE}),False,False,False,False,P9B_ASSESSMENT_SCHEMA_VERSION,P9B_ASSESSMENT_MODE,assessment_sha)
