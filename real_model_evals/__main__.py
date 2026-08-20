import argparse
import json

from real_model_evals.runner import EvaluationConfig, run_evaluation

parser = argparse.ArgumentParser(description="Run explicitly classified model-boundary evaluations")
parser.add_argument(
    "--live", action="store_true", help="require an explicitly configured live model"
)
args = parser.parse_args()
report = run_evaluation(EvaluationConfig(mode="live" if args.live else "offline_fake"))
print(json.dumps(report, indent=2, sort_keys=True))
raise SystemExit(0 if report["status"] == "VERIFIED" else 2)
