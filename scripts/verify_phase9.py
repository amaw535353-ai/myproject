from __future__ import annotations
import argparse, json, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
FOCUSED={
'p9a':('tests/security/test_p9a_training_data_provenance.py','evals.p9a_training_data_provenance'),
'p9b':('tests/security/test_p9b_training_data_poisoning.py','evals.p9b_training_data_poisoning'),
'p9c':('tests/security/test_p9c_fine_tuning_admission.py','evals.p9c_fine_tuning_admission'),
'p9d':('tests/security/test_p9d_training_execution_provenance.py','evals.p9d_training_execution_provenance'),
'p9e':('tests/security/test_p9e_checkpoint_integrity.py','evals.p9e_checkpoint_integrity'),
'p9f':('tests/security/test_p9f_evaluation_governance.py','evals.p9f_evaluation_governance'),
'p9g':('tests/security/test_p9g_sensitive_data_governance.py','evals.p9g_sensitive_data_governance'),
'p9h':('tests/security/test_p9h_model_promotion.py','evals.p9h_model_promotion'),
}
def run(args): subprocess.run(args,cwd=ROOT,check=True)
def main():
    parser=argparse.ArgumentParser(description='Reproducible local Phase 9 verification')
    group=parser.add_mutually_exclusive_group()
    for phase in FOCUSED: group.add_argument(f'--focused-{phase}',action='store_true',help=f'Run only {phase.upper()} security tests/evaluator.')
    args=parser.parse_args(); selected=next((p for p in FOCUSED if getattr(args,f'focused_{p}')),None)
    if selected:
        test,evaluator=FOCUSED[selected]; run([sys.executable,'-m','pytest','-q',test]); run([sys.executable,'-m',evaluator]); scope=f'{selected}_focused'; status='LOCAL_FOCUSED_PASS'
    else:
        run([sys.executable,'-m','pytest'])
        for _,evaluator in FOCUSED.values(): run([sys.executable,'-m',evaluator])
        scope='phase9_repository'; status='LOCAL_FULL_PASS'
    print(json.dumps({'phase':'P9','scope':scope,'verification_status':status,'hosted_ci_execution_verified':False,'production_validation_claimed':False},sort_keys=True)); return 0
if __name__=='__main__': raise SystemExit(main())
