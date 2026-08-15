from __future__ import annotations
from dataclasses import replace
import hashlib
from aegis.training.data_provenance_types import VerifiedTrainingDatasetAssessment,TrainingDataDecision,P9A_ASSESSMENT_MODE,P9A_ASSESSMENT_SCHEMA_VERSION
from aegis.training.data_poisoning_types import *
NOW=1_800_010_000
MANIFEST_ID='p9b-training-poisoning-manifest-001'; DATASET_ID='aegisdesk-helpdesk-training'; DATASET_VERSION='2026.08-p9a'
def h(s): return hashlib.sha256(s.encode()).hexdigest()
RECORD_IDS=tuple(f'record-{i:02d}' for i in range(1,9))
CONTRIBUTORS=('contrib-curated-a','contrib-curated-b','contrib-reviewed-c')
LABELS=('benign','benign','security','security','benign','security','benign','security')
SOURCES=('src-helpdesk','src-helpdesk','src-security','src-security','src-helpdesk','src-security','src-synthetic','src-synthetic')
CONTRIB_BY_RECORD={rid:('contrib-curated-a' if i<3 else 'contrib-curated-b' if i<6 else 'contrib-reviewed-c') for i,rid in enumerate(RECORD_IDS)}
P9A_ASSESSMENT_SHA=h('p9a-clean-assessment:p9b-bound'); P9A_FINAL_SHA=h('p9a-final-dataset:p9b-bound')

def _review(review_id,rid,label):
    base=LabelReviewEvidence(review_id,rid,'reviewer-security',ReviewDecision.APPROVE,label,h(f'payload:{rid}:canonical-v1'),ZERO_SHA256)
    return replace(base,evidence_sha256=review_evidence_digest(base))

def build_fixture():
    contributors=(ContributorEvidence('contrib-curated-a',ContributorTrust.TRUSTED,10000),ContributorEvidence('contrib-curated-b',ContributorTrust.TRUSTED,9000),ContributorEvidence('contrib-reviewed-c',ContributorTrust.REVIEWED,7000))
    reviews=(_review('review-07','record-07',LABELS[6]),_review('review-08','record-08',LABELS[7]))
    records=[]
    anomalies=(200,300,400,500,600,700,400,500)
    for i,rid in enumerate(RECORD_IDS):
        review_ids=(f'review-{i+1:02d}',) if i>=6 else ()
        records.append(TrainingRecordSecurityEvidence(rid,h(f'payload:{rid}:canonical-v1'),SOURCES[i],CONTRIB_BY_RECORD[rid],LABELS[i],9800,anomalies[i],(),f'cluster-{(i//2)+1}',False,review_ids))
    manifest=TrainingPoisoningManifest(P9B_SCHEMA_VERSION,MANIFEST_ID,DATASET_ID,DATASET_VERSION,NOW,P9A_ASSESSMENT_SHA,P9A_FINAL_SHA,contributors,tuple(records),reviews,tuple(sorted(RECORD_IDS)))
    policy=TrainingPoisoningPolicy(P9B_POLICY_VERSION,MANIFEST_ID,DATASET_ID,DATASET_VERSION,training_poisoning_manifest_digest(manifest),P9A_ASSESSMENT_SHA,P9A_FINAL_SHA,{r.record_id:r.payload_sha256 for r in records},{r.record_id:r.source_id for r in records},CONTRIB_BY_RECORD,{rid:LABELS[i] for i,rid in enumerate(RECORD_IDS)},{c.contributor_id:c.trust for c in contributors},{c.contributor_id:c.trust_weight_bps for c in contributors},('reviewer-security','reviewer-ml-safety'),8000,5000,7500,2,(),9000,300,5)
    p9a=VerifiedTrainingDatasetAssessment('p9a-training-dataset-manifest-001',DATASET_ID,DATASET_VERSION,TrainingDataDecision.ALLOW,(),3,12,{},3,P9A_FINAL_SHA,True,True,True,True,True,False,False,False,False,0,P9A_ASSESSMENT_SCHEMA_VERSION,P9A_ASSESSMENT_MODE,P9A_ASSESSMENT_SHA)
    # canonical weighted score = 450
    request=TrainingPoisoningRequest(MANIFEST_ID,training_poisoning_manifest_digest(manifest),DATASET_ID,DATASET_VERSION,NOW,tuple(sorted(RECORD_IDS)),(),450,True,True)
    return {'manifest':manifest,'policy':policy,'request':request,'p9a':p9a}

def rebind(f,manifest=None,p9a=None,**request_updates):
    out=dict(f); manifest=manifest or f['manifest']; p9a=p9a or f['p9a']; digest=training_poisoning_manifest_digest(manifest)
    out['manifest']=manifest; out['p9a']=p9a; out['policy']=replace(f['policy'],expected_manifest_sha256=digest)
    included=tuple(sorted(manifest.included_record_ids)); quarantined=tuple(sorted(r.record_id for r in manifest.records if r.quarantined))
    req=replace(f['request'],manifest_sha256=digest,declared_included_record_ids=included,declared_quarantined_record_ids=quarantined,**request_updates)
    out['request']=req; return out
