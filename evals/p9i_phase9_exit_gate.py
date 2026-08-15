from __future__ import annotations

from dataclasses import replace
import hashlib, json
from typing import Callable

from aegis.training.phase9_exit_security import Phase9IntegratedExitGate, machine_readable_phase9_exit
from aegis.training.phase9_exit_types import MILESTONE_ORDER, PRODUCTION_CLAIM_FIELDS, SCENARIO_ORDER, Phase9ExitDecision, Phase9ExitRejected, Phase9VerificationStatus
from aegis.vulnerable.phase9_exit_security import VulnerableCallerDeclaredPhase9Exit
from evals.p9i_fixture import build_fixture, h, rebind

Fixture=dict[str,object]; Attack=Callable[[Fixture],Fixture]

def _milestone(f:Fixture,index:int,**changes)->Fixture:
    m=f['manifest']; items=list(m.milestone_evidence); items[index]=replace(items[index],**changes); return rebind(f,replace(m,milestone_evidence=tuple(items)),keep_policy_pins=False)
def _scenario(f:Fixture,index:int,**changes)->Fixture:
    m=f['manifest']; items=list(m.compromise_exercises); items[index]=replace(items[index],**changes); return rebind(f,replace(m,compromise_exercises=tuple(items)),keep_policy_pins=False)
def _verification(f:Fixture,vid:str,**changes)->Fixture:
    m=f['manifest']; items=list(m.verification_records)
    for i,item in enumerate(items):
        if item.verification_id==vid: items[i]=replace(item,**changes); break
    return rebind(f,replace(m,verification_records=tuple(items)),keep_policy_pins=False)

def _globals()->list[tuple[str,Attack]]:
    c=[]
    c += [
      ('manifest-schema',lambda f: rebind(f,replace(f['manifest'],schema_version='wrong-schema'),keep_policy_pins=False)),
      ('manifest-id',lambda f: rebind(f,replace(f['manifest'],manifest_id='other-phase9-exit'),keep_policy_pins=False)),
      ('training-lineage',lambda f: rebind(f,replace(f['manifest'],training_lineage_id='other-training-lineage'),keep_policy_pins=False)),
      ('milestone-drop',lambda f: rebind(f,replace(f['manifest'],milestone_evidence=f['manifest'].milestone_evidence[:-1]),keep_policy_pins=False)),
      ('milestone-reorder',lambda f: _reorder(f,'milestone_evidence')),
      ('scenario-drop',lambda f: rebind(f,replace(f['manifest'],compromise_exercises=f['manifest'].compromise_exercises[:-1]),keep_policy_pins=False)),
      ('scenario-reorder',lambda f: _reorder(f,'compromise_exercises')),
      ('scenario-duplicate',lambda f: rebind(f,replace(f['manifest'],compromise_exercises=f['manifest'].compromise_exercises+(f['manifest'].compromise_exercises[0],)),keep_policy_pins=False)),
      ('assumption-drop',lambda f: rebind(f,replace(f['manifest'],synthetic_assumptions=f['manifest'].synthetic_assumptions[:-1]),keep_policy_pins=False)),
      ('assumption-extra',lambda f: rebind(f,replace(f['manifest'],synthetic_assumptions=f['manifest'].synthetic_assumptions+('unsupported-production-proof',)),keep_policy_pins=False)),
    ]
    for field in PRODUCTION_CLAIM_FIELDS:
        c.append((f'unsupported-claim-{field}',lambda f,field=field: _claim(f,field)))
    c += [
      ('remote-blocked-runner-started',lambda f:_verification(f,'remote-phase9-ci',runner_started=True)),
      ('remote-blocked-steps-executed',lambda f:_verification(f,'remote-phase9-ci',steps_executed=1)),
      ('remote-blocked-unknown-reason',lambda f:_verification(f,'remote-phase9-ci',reason_code='unknown-provider-error')),
      ('remote-ci-executed-failure',lambda f:build_fixture(Phase9VerificationStatus.REMOTE_CI_FAIL)),
      ('remote-pass-no-runner',lambda f:_verification(build_fixture(Phase9VerificationStatus.REMOTE_CI_PASS),'remote-phase9-ci',runner_started=False)),
      ('remote-pass-zero-steps',lambda f:_verification(build_fixture(Phase9VerificationStatus.REMOTE_CI_PASS),'remote-phase9-ci',steps_executed=0)),
      ('remote-pass-with-reason',lambda f:_verification(build_fixture(Phase9VerificationStatus.REMOTE_CI_PASS),'remote-phase9-ci',reason_code='billing-warning')),
      ('duplicate-remote-record',_duplicate_remote),
      ('request-manifest-id-lie',lambda f:{**f,'request':replace(f['request'],manifest_id='caller-other-manifest')}),
      ('request-manifest-digest-lie',lambda f:{**f,'request':replace(f['request'],manifest_sha256=h('caller-forged-manifest'))}),
      ('request-policy-lie',lambda f:{**f,'request':replace(f['request'],policy_version='caller-policy')}),
      ('request-stale',lambda f:{**f,'request':replace(f['request'],evaluated_at_epoch=f['manifest'].created_at_epoch+3601)}),
      ('request-too-early',lambda f:{**f,'request':replace(f['request'],evaluated_at_epoch=f['manifest'].created_at_epoch-31)}),
      ('request-decision-lie',lambda f:{**f,'request':replace(f['request'],declared_exit_decision=Phase9ExitDecision.PASS)}),
      ('request-assessment-lie',_request_assessment),('request-scenario-detection-lie',_request_detection),('request-scenario-block-lie',_request_block),('request-verification-lie',_request_verification),
      ('policy-version',lambda f:{**f,'policy':replace(f['policy'],policy_version='wrong-policy')}),
      ('policy-scenario-order',lambda f:{**f,'policy':replace(f['policy'],expected_scenario_order=tuple(reversed(SCENARIO_ORDER)))}),
    ]
    return c

def _reorder(f,field):
    m=f['manifest']; items=list(getattr(m,field)); items[0],items[1]=items[1],items[0]; return rebind(f,replace(m,**{field:tuple(items)}),keep_policy_pins=False)
def _claim(f,field):
    m=f['manifest']; return rebind(f,replace(m,claim_profile=replace(m.claim_profile,**{field:True})),keep_policy_pins=False)
def _duplicate_remote(f):
    m=f['manifest']; r=[x for x in m.verification_records if x.verification_id=='remote-phase9-ci'][0]; return rebind(f,replace(m,verification_records=m.verification_records+(replace(r,verification_id='remote-phase9-ci-duplicate'),)),keep_policy_pins=False)
def _request_assessment(f):
    r=f['request']; d=dict(r.declared_assessment_sha256_by_milestone); d['P9-H']=h('caller-forged-p9h-assessment'); return {**f,'request':replace(r,declared_assessment_sha256_by_milestone=d)}
def _request_detection(f):
    r=f['request']; d=dict(r.declared_scenario_detection_by_id); d[SCENARIO_ORDER[0]]=False; return {**f,'request':replace(r,declared_scenario_detection_by_id=d)}
def _request_block(f):
    r=f['request']; d=dict(r.declared_scenario_promotion_blocked_by_id); d[SCENARIO_ORDER[0]]=False; return {**f,'request':replace(r,declared_scenario_promotion_blocked_by_id=d)}
def _request_verification(f):
    r=f['request']; d=dict(r.declared_verification_status_by_id); d['remote-phase9-ci']=Phase9VerificationStatus.REMOTE_CI_PASS.value; return {**f,'request':replace(r,declared_verification_status_by_id=d)}

CASES=_globals()
for index,mid in enumerate(MILESTONE_ORDER):
    cur=build_fixture()['manifest'].milestone_evidence[index]
    muts=[('domain',{'control_domain':f'wrong-{cur.control_domain}'}),('step-index',{'step_index':99}),('lineage',{'training_lineage_id':'forged-lineage'}),('manifest-digest',{'manifest_sha256':h(f'forged:{mid}:manifest')}),('assessment-digest',{'assessment_sha256':h(f'forged:{mid}:assessment')}),('predecessor',{'predecessor_assessment_sha256':h(f'forged:{mid}:predecessor')}),('input-state',{'input_state_sha256':h(f'forged:{mid}:input')}),('output-state',{'output_state_sha256':h(f'forged:{mid}:output')}),('unsafe',{'safe':False}),('caller-trust',{'caller_declared_safety_trusted':True}),('network-ops',{'network_operations':1}),('assessment-schema',{'assessment_schema_version':'forged-assessment-schema'}),('assessment-mode',{'assessment_mode':'caller-declared-safe-mode'}),('milestone-id',{'milestone_id':f'P9-X{index:02d}'})]
    for label,changes in muts: CASES.append((f'{mid.lower()}-{label}',lambda f,index=index,changes=changes:_milestone(f,index,**changes)))
for index,sid in enumerate(SCENARIO_ORDER):
    cur=build_fixture()['manifest'].compromise_exercises[index]; entry='P9-B' if cur.entry_milestone_id!='P9-B' else 'P9-C'; detection='P9-H' if cur.detection_milestone_id!='P9-H' else 'P9-G'; path=cur.propagation_path[:-1] if len(cur.propagation_path)>1 else ('P9-G','P9-H')
    muts=[('attack-class',{'attack_class':f'forged-{cur.attack_class}'}),('entry',{'entry_milestone_id':entry}),('path',{'propagation_path':path}),('attack-digest',{'attack_input_sha256':h(f'forged:{sid}:attack')}),('detection-milestone',{'detection_milestone_id':detection}),('not-detected',{'detected':False}),('promotion-not-blocked',{'promotion_blocked':False}),('recovery-digest',{'recovery_state_sha256':h(f'forged:{sid}:recovery')}),('network-ops',{'network_operations':1}),('scenario-id',{'scenario_id':f'forged-{sid}'})]
    for label,changes in muts: CASES.append((f'scenario-{sid}-{label}',lambda f,index=index,changes=changes:_scenario(f,index,**changes)))
for mid in MILESTONE_ORDER:
    vid=f'local-{mid.lower()}'
    CASES += [(f'{mid.lower()}-local-not-run',lambda f,vid=vid:_verification(f,vid,status=Phase9VerificationStatus.NOT_RUN)),(f'{mid.lower()}-local-runner-not-started',lambda f,vid=vid:_verification(f,vid,runner_started=False)),(f'{mid.lower()}-local-zero-steps',lambda f,vid=vid:_verification(f,vid,steps_executed=0))]
EXPECTED_ADVERSARIAL_CASES=len(CASES); assert EXPECTED_ADVERSARIAL_CASES==254,EXPECTED_ADVERSARIAL_CASES

def _hardened(f):
    try:
        a=Phase9IntegratedExitGate(f['policy']).evaluate(f['request'],f['manifest']); return a.decision in {Phase9ExitDecision.PASS,Phase9ExitDecision.PASS_WITH_EXTERNAL_CI_LIMITATION}
    except Phase9ExitRejected: return False
def _safe():
    out=[]
    for status in (Phase9VerificationStatus.REMOTE_CI_BLOCKED,Phase9VerificationStatus.REMOTE_CI_PASS):
        for offset in (10,20):
            f=build_fixture(status); f['request']=replace(f['request'],evaluated_at_epoch=f['manifest'].created_at_epoch+offset); out.append(f)
    return out
def _dataset_digest(): return hashlib.sha256('\n'.join(name for name,_ in CASES).encode()).hexdigest()
def _fixture_digest():
    f=build_fixture(); material={'manifest':f['request'].manifest_sha256,'policy':f['policy'].policy_version,'cases':_dataset_digest(),'scenario_order':SCENARIO_ORDER}; return hashlib.sha256(json.dumps(material,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def run():
    vulnerable=VulnerableCallerDeclaredPhase9Exit(); va=ha=0
    for _,attack in CASES:
        f=attack(build_fixture()); va+=int(vulnerable.accepts(replace(f['request'],declared_exit_decision=Phase9ExitDecision.PASS))); ha+=int(_hardened(f))
    safe=_safe(); failures=sum(not _hardened(f) for f in safe); canonical=build_fixture(); assessment=Phase9IntegratedExitGate(canonical['policy']).evaluate(canonical['request'],canonical['manifest'])
    return {'adversarial_cases':len(CASES),'vulnerable_asr':f'{va}/{len(CASES)}','hardened_asr':f'{ha}/{len(CASES)}','hardened_fpr':f'{failures}/{len(safe)}','safe_task_rate':f'{len(safe)-failures}/{len(safe)}','exit_decision':assessment.decision.value,'remote_ci_status':assessment.remote_ci_status,'compromise_scenarios':assessment.compromise_scenario_count,'promotion_fail_closed_verified':assessment.promotion_fail_closed_verified,'phase9_exit_manifest_sha256':canonical['request'].manifest_sha256,'adversarial_dataset_sha256':_dataset_digest(),'fixture_evaluator_sha256':_fixture_digest(),'clean_assessment_sha256':assessment.assessment_evidence_sha256,'machine_readable_exit':machine_readable_phase9_exit(assessment)}
if __name__=='__main__': print(json.dumps(run(),sort_keys=True,indent=2))
