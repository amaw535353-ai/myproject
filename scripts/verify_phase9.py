from __future__ import annotations
import argparse, json
from pathlib import Path
import subprocess, sys
ROOT=Path(__file__).resolve().parents[1]
def run_command(args:list[str])->None: subprocess.run(args,cwd=ROOT,check=True)
def main()->int:
    parser=argparse.ArgumentParser(description='Reproducible local Phase 9 verification')
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--focused-p9a',action='store_true',help='Run only P9-A security tests/evaluator.')
    group.add_argument('--focused-p9b',action='store_true',help='Run only P9-B security tests/evaluator.')
    group.add_argument('--focused-p9c',action='store_true',help='Run only P9-C security tests/evaluator.')
    group.add_argument('--focused-p9d',action='store_true',help='Run only P9-D security tests/evaluator.')
    args=parser.parse_args()
    if args.focused_p9a:
        run_command([sys.executable,'-m','pytest','-q','tests/security/test_p9a_training_data_provenance.py'])
        run_command([sys.executable,'-m','evals.p9a_training_data_provenance'])
        scope='p9a_training_data_provenance'; status='LOCAL_FOCUSED_PASS'
    elif args.focused_p9b:
        run_command([sys.executable,'-m','pytest','-q','tests/security/test_p9b_training_data_poisoning.py'])
        run_command([sys.executable,'-m','evals.p9b_training_data_poisoning'])
        scope='p9b_training_data_poisoning'; status='LOCAL_FOCUSED_PASS'
    elif args.focused_p9c:
        run_command([sys.executable,'-m','pytest','-q','tests/security/test_p9c_fine_tuning_admission.py'])
        run_command([sys.executable,'-m','evals.p9c_fine_tuning_admission'])
        scope='p9c_fine_tuning_admission'; status='LOCAL_FOCUSED_PASS'
    elif args.focused_p9d:
        run_command([sys.executable,'-m','pytest','-q','tests/security/test_p9d_training_execution_provenance.py'])
        run_command([sys.executable,'-m','evals.p9d_training_execution_provenance'])
        scope='p9d_training_execution_provenance'; status='LOCAL_FOCUSED_PASS'
    else:
        run_command([sys.executable,'-m','pytest'])
        run_command([sys.executable,'-m','evals.p9a_training_data_provenance'])
        run_command([sys.executable,'-m','evals.p9b_training_data_poisoning'])
        run_command([sys.executable,'-m','evals.p9c_fine_tuning_admission'])
        run_command([sys.executable,'-m','evals.p9d_training_execution_provenance'])
        scope='phase9_repository'; status='LOCAL_FULL_PASS'
    print(json.dumps({'phase':'P9','scope':scope,'verification_status':status,'hosted_ci_execution_verified':False,'production_validation_claimed':False},sort_keys=True))
    return 0
if __name__=='__main__': raise SystemExit(main())
