from __future__ import annotations
from dataclasses import replace
import hashlib,json
from aegis.training.data_poisoning_security import TrainingDataPoisoningAnalyzer
from aegis.training.data_poisoning_types import *
from aegis.vulnerable.training_data_poisoning import VulnerableCallerDeclaredTrainingDataSafety
from .p9b_fixture import build_fixture,rebind,h

def _mut_record(m,index,**kw):
    rs=list(m.records); rs[index]=replace(rs[index],**kw); return replace(m,records=tuple(rs))
def _mut_contrib(m,index,**kw):
    xs=list(m.contributors); xs[index]=replace(xs[index],**kw); return replace(m,contributors=tuple(xs))
def _mut_review(m,index,**kw):
    xs=list(m.reviews); x=replace(xs[index],**kw)
    if 'evidence_sha256' not in kw: x=replace(x,evidence_sha256=review_evidence_digest(x))
    xs[index]=x; return replace(m,reviews=tuple(xs))

def build_attacks():
    f=build_fixture(); m=f['manifest']; p=f['p9a']; attacks=[]
    def add(name,fx): attacks.append((name,fx))
    add('upstream-deny',rebind(f,p9a=replace(p,decision=__import__('aegis.training.data_provenance_types',fromlist=['TrainingDataDecision']).TrainingDataDecision.DENY)))
    for field in ('exact_manifest_binding_verified','trusted_source_snapshots_verified','record_hash_coverage_verified','split_isolation_verified','transform_lineage_verified'): add('upstream-'+field,rebind(f,p9a=replace(p,**{field:False})))
    add('upstream-caller-trust',rebind(f,p9a=replace(p,caller_declared_training_data_safety_trusted=True)))
    add('upstream-network',rebind(f,p9a=replace(p,network_operations=1)))
    add('upstream-assessment-hash',rebind(f,p9a=replace(p,assessment_evidence_sha256=h('swap'))))
    add('upstream-final-hash',rebind(f,p9a=replace(p,final_dataset_sha256=h('swap-final'))))
    add('upstream-schema',rebind(f,p9a=replace(p,assessment_schema_version='wrong-schema')))
    add('upstream-mode',rebind(f,p9a=replace(p,assessment_mode='wrong-mode')))
    add('upstream-dataset-id',rebind(f,p9a=replace(p,dataset_id='wrong-dataset')))
    add('upstream-dataset-version',rebind(f,p9a=replace(p,dataset_version='wrong-version')))
    add('upstream-production-data-lake-claim',rebind(f,p9a=replace(p,production_data_lake_integration=True)))
    add('upstream-production-pipeline-claim',rebind(f,p9a=replace(p,production_training_pipeline_attestation=True)))
    add('upstream-source-auth-claim',rebind(f,p9a=replace(p,cryptographic_source_authentication=True)))
    for i in range(8):
        add(f'record-digest-{i}',rebind(f,_mut_record(m,i,payload_sha256=h(f'evil-{i}'))))
        add(f'record-source-{i}',rebind(f,_mut_record(m,i,source_id='src-unknown')))
        add(f'record-label-{i}',rebind(f,_mut_record(m,i,label='poisoned-label')))
        add(f'record-confidence-{i}',rebind(f,_mut_record(m,i,label_confidence_bps=100)))
        add(f'record-anomaly-{i}',rebind(f,_mut_record(m,i,anomaly_score_bps=9000)))
        add(f'record-signal-{i}',rebind(f,_mut_record(m,i,poisoning_signal_ids=('trigger-correlation',))))
        add(f'record-contributor-{i}',rebind(f,_mut_record(m,i,contributor_id='contrib-reviewed-c' if i<6 else 'contrib-curated-a')))
    add('record-coverage-missing',rebind(f,replace(m,records=m.records[:-1],included_record_ids=m.included_record_ids[:-1])))
    ghost=replace(m.records[0],record_id='record-ghost',payload_sha256=h('ghost'))
    add('record-coverage-extra',rebind(f,replace(m,records=m.records+(ghost,),included_record_ids=m.included_record_ids+('record-ghost',))))
    for i in range(3):
        add(f'contributor-trust-{i}',rebind(f,_mut_contrib(m,i,trust=ContributorTrust.UNTRUSTED)))
        add(f'contributor-weight-{i}',rebind(f,_mut_contrib(m,i,trust_weight_bps=100)))
    add('contributor-coverage-missing',rebind(f,replace(m,contributors=m.contributors[:-1])))
    add('contributor-coverage-extra',rebind(f,replace(m,contributors=m.contributors+(ContributorEvidence('attacker',ContributorTrust.TRUSTED,10000),))))
    for i in range(2):
        add(f'review-untrusted-{i}',rebind(f,_mut_review(m,i,reviewer_id='attacker')))
        add(f'review-payload-{i}',rebind(f,_mut_review(m,i,reviewed_payload_sha256=h('wrong'))))
        add(f'review-label-{i}',rebind(f,_mut_review(m,i,approved_label='wrong')))
        add(f'review-reject-{i}',rebind(f,_mut_review(m,i,decision=ReviewDecision.REJECT)))
        add(f'review-signature-{i}',rebind(f,_mut_review(m,i,evidence_sha256=h('forged'))))
    for i in (6,7): add(f'missing-review-{i}',rebind(f,_mut_record(m,i,review_ids=())))
    rs=tuple(replace(r,contributor_id='contrib-curated-a') for r in m.records); add('contributor-concentration',rebind(f,replace(m,records=rs)))
    rs=list(m.records)
    for i in range(4): rs[i]=replace(rs[i],duplicate_cluster_id='cluster-abuse')
    add('duplicate-cluster-abuse',rebind(f,replace(m,records=tuple(rs))))
    add('unnecessary-quarantine',rebind(f,_mut_record(m,0,quarantined=True),declared_weighted_risk_score=450))
    add('included-set-drop',rebind(f,replace(m,included_record_ids=tuple(sorted(m.included_record_ids[1:])))))
    add('included-set-extra',rebind(f,replace(m,included_record_ids=tuple(sorted(m.included_record_ids+('ghost-record',))))))
    add('manifest-p9a-hash',rebind(f,replace(m,p9a_assessment_sha256=h('other-p9a'))))
    add('manifest-final-hash',rebind(f,replace(m,p9a_final_dataset_sha256=h('other-final'))))
    add('request-manifest-id',{**f,'request':replace(f['request'],manifest_id='wrong')})
    add('request-manifest-sha',{**f,'request':replace(f['request'],manifest_sha256=h('wrong'))})
    add('request-dataset-id',{**f,'request':replace(f['request'],dataset_id='wrong')})
    add('request-version',{**f,'request':replace(f['request'],dataset_version='wrong')})
    add('request-time-old',{**f,'request':replace(f['request'],evaluated_at_epoch=m.created_at_epoch-10)})
    add('request-time-stale',{**f,'request':replace(f['request'],evaluated_at_epoch=m.created_at_epoch+1000)})
    add('request-risk-score',{**f,'request':replace(f['request'],declared_weighted_risk_score=0)})
    add('request-included',{**f,'request':replace(f['request'],declared_included_record_ids=())})
    add('request-quarantine',{**f,'request':replace(f['request'],declared_quarantined_record_ids=('record-01',))})
    duplicate_review=replace(m,reviews=m.reviews+(m.reviews[0],))
    add('duplicate-review-id',rebind(f,duplicate_review))
    return attacks

def run():
    f=build_fixture(); hard=TrainingDataPoisoningAnalyzer(f['policy']); vul=VulnerableCallerDeclaredTrainingDataSafety(); clean=hard.evaluate(f['request'],f['manifest'],f['p9a'])
    attacks=build_attacks(); va=ha=0
    for _,fx in attacks:
        if vul.evaluate(fx['request'],fx['manifest'],fx['p9a']): va+=1
        try:
            a=TrainingDataPoisoningAnalyzer(fx['policy']).evaluate(fx['request'],fx['manifest'],fx['p9a'])
            if a.decision==PoisoningDecision.ALLOW: ha+=1
        except TrainingDataPoisoningRejected: pass
    benign_fixtures=[f]
    benign_fixtures.append(rebind(f,replace(f['manifest'],contributors=tuple(reversed(f['manifest'].contributors)))))
    benign_fixtures.append(rebind(f,replace(f['manifest'],records=tuple(reversed(f['manifest'].records)),included_record_ids=tuple(reversed(f['manifest'].included_record_ids)))))
    reviews=[]
    for v in f['manifest'].reviews:
        x=replace(v,reviewer_id='reviewer-ml-safety')
        x=replace(x,evidence_sha256=review_evidence_digest(x)); reviews.append(x)
    benign_fixtures.append(rebind(f,replace(f['manifest'],reviews=tuple(reviews))))
    benign=[]
    for bx in benign_fixtures:
        benign.append(TrainingDataPoisoningAnalyzer(bx['policy']).evaluate(bx['request'],bx['manifest'],bx['p9a']).decision==PoisoningDecision.ALLOW)
    dataset_sha=hashlib.sha256(json.dumps([n for n,_ in attacks],separators=(',',':')).encode()).hexdigest()
    fixture_sha=hashlib.sha256((training_poisoning_manifest_digest(f['manifest'])+clean.assessment_evidence_sha256).encode()).hexdigest()
    out={'adversarial_cases':len(attacks),'vulnerable_asr':f'{va}/{len(attacks)}','hardened_asr':f'{ha}/{len(attacks)}','hardened_fpr':f'{len(benign)-sum(benign)}/{len(benign)}','safe_task_rate':f'{sum(benign)}/{len(benign)}','manifest_sha256':training_poisoning_manifest_digest(f['manifest']),'dataset_sha256':dataset_sha,'fixture_sha256':fixture_sha,'clean_assessment_sha256':clean.assessment_evidence_sha256}
    print(json.dumps(out,sort_keys=True)); return out
if __name__=='__main__': run()
