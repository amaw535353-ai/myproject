from __future__ import annotations
from dataclasses import replace
import hashlib
from aegis.inference.tenant_isolation_types import *
from aegis.inference.scheduler_security_types import *

NOW=1_800_030_100
MANIFEST_ID='p10b-scheduler-admission-001'
P10A_CLEAN_ASSESSMENT_SHA256='3fcd0475ddc05727dad597f375bd3929e2f96bd665aa0cf137d33ea9fc28904d'
def h(label:str)->str: return hashlib.sha256(label.encode()).hexdigest()
def p10a_assessment():
    return VerifiedInferenceTenantIsolationAssessment('p10a-inference-isolation-001','request-acme-0001','acme','principal-acme-agent','tenant/acme/session/s-001','deployment-aegisdesk-prod-001','endpoint-helpdesk-001','aegisdesk-helpdesk-security','rev-2026-08-p9h','adapter-security-policy','batch-acme-001',InferenceDecision.ALLOW,(),h('p5h-deployment-attestation-001'),'8daa403475acdf99254740ac7ba1c6384696acd4eb3fb1b57b09d98232946888',True,True,True,True,True,True,True,True,False,False,False,False,False,False,P10A_ASSESSMENT_SCHEMA_VERSION,P10A_ASSESSMENT_MODE,P10A_CLEAN_ASSESSMENT_SHA256)
def _requests():
    return (
      SchedulerRequestEvidence('request-acme-0001','acme','tenant/acme/session/s-001',7,'high',100,100,2,30,True,False,False),
      SchedulerRequestEvidence('request-acme-peer-0002','acme','tenant/acme/session/s-002',8,'normal',80,120,2,20,True,False,False),
      SchedulerRequestEvidence('request-beta-0001','beta','tenant/beta/session/s-009',9,'high',120,80,2,40,True,False,False),
      SchedulerRequestEvidence('request-beta-0002','beta','tenant/beta/session/s-010',10,'normal',50,50,1,10,True,False,False),
      SchedulerRequestEvidence('request-gamma-0001','gamma','tenant/gamma/session/s-005',3,'normal',100,100,2,100,True,False,False),
    )
def _manifest():
    prior=('request-global-served-0001','request-global-served-0002')
    return InferenceSchedulerManifest(P10B_SCHEMA_VERSION,MANIFEST_ID,NOW,P10A_CLEAN_ASSESSMENT_SHA256,'request-acme-0001','acme','tenant/acme/session/s-001','scheduler-inference-01',42,_requests(),(
      TenantSchedulerState('acme',2,100,400,500,0,2,400,4),
      TenantSchedulerState('beta',1,200,0,600,0,2,300,3),
      TenantSchedulerState('gamma',1,50,0,450,0,1,200,2),
    ),SchedulerResourceEvidence('worker-pool-gpu-a',4,0,16,0),SchedulerBatchPlanEvidence('sched-batch-0042','scheduler-inference-01','acme',('request-acme-0001','request-acme-peer-0002'),400,4),prior,admitted_ledger_digest(prior),0)
def request_for(m):
    admitted=tuple(r.request_id for r in m.requests if r.admitted and not r.cancelled)
    b=m.selected_batch
    return InferenceSchedulerRequest(m.manifest_id,inference_scheduler_manifest_digest(m),m.created_at_epoch+10,m.scheduler_id,b.batch_id,b.tenant_id,admitted,b.request_ids,True,True,True,True,True,True,True)
def build_fixture():
    m=_manifest(); p=InferenceSchedulerPolicy(P10B_POLICY_VERSION,MANIFEST_ID,inference_scheduler_manifest_digest(m),P10A_CLEAN_ASSESSMENT_SHA256,'request-acme-0001','acme','tenant/acme/session/s-001',('scheduler-inference-01','scheduler-inference-02'),('worker-pool-gpu-a','worker-pool-gpu-b'),('acme','beta','gamma'),{'acme':2,'beta':1,'gamma':1},{'acme':2,'beta':2,'gamma':1},{'acme':4,'beta':4,'gamma':3},{'acme':600,'beta':500,'gamma':400},{'acme':6,'beta':6,'gamma':4},('high','normal','low'),{'high':3,'normal':2,'low':1},{'high':120,'normal':300,'low':600},400,5000,300,4,4,1200,16,2,500,6,m.prior_admitted_ledger_sha256,300,5)
    return {'manifest':m,'policy':p,'request':request_for(m),'p10a':p10a_assessment()}
def rebind(f,m,*,keep_policy_pins=True):
    p=f['policy']
    if not keep_policy_pins: p=replace(p,expected_manifest_id=m.manifest_id,expected_manifest_sha256=inference_scheduler_manifest_digest(m))
    return {'manifest':m,'policy':p,'request':request_for(m),'p10a':f['p10a']}
def safe_beta_selected_fixture():
    f=build_fixture(); m=f['manifest']; states=(replace(m.tenant_states[0],deficit_before=0,service_units=0,deficit_after=800),replace(m.tenant_states[1],deficit_before=500,service_units=300,deficit_after=600),replace(m.tenant_states[2],deficit_before=0,service_units=0,deficit_after=400)); b=replace(m.selected_batch,batch_id='sched-batch-0043',tenant_id='beta',request_ids=('request-beta-0001','request-beta-0002'),total_reserved_tokens=300,total_memory_units=3); return rebind(f,replace(m,scheduling_epoch=43,tenant_states=states,selected_batch=b),keep_policy_pins=False)
