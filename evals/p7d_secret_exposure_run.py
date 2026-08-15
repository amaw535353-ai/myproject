from __future__ import annotations

import json

from aegis.architecture.secrets_exposure import SecretExposureRejected
from aegis.vulnerable.secret_exposure import VulnerableSecretExposureReporter

from . import p7d_secret_exposure as cases
from .p7d_fixture import CTRL_BUILD_SECRET, CTRL_TELEMETRY_REDACTION, build_fixture


def benign_fixtures():
    return [
        ("all controls satisfied", build_fixture()),
        ("build-secret exception explicitly surfaced", build_fixture(exceptioned_control=CTRL_BUILD_SECRET)),
        ("telemetry redaction not evaluated explicitly surfaced", build_fixture(not_evaluated_control=CTRL_TELEMETRY_REDACTION)),
    ]


def run_evaluation() -> dict[str, object]:
    vulnerable = VulnerableSecretExposureReporter()
    adversarial = cases.adversarial_cases()
    vulnerable_successes = 0
    hardened_successes = 0
    for _, mutation in adversarial:
        if vulnerable.evaluate(declared_graph_complete=True, declared_exposed_path_count=0, declared_max_blast_radius_score=0).safe:
            vulnerable_successes += 1
        fixture = mutation(build_fixture())
        try:
            cases._hardened(fixture)
        except SecretExposureRejected:
            continue
        hardened_successes += 1

    benign_results = []
    false_positives = 0
    for name, fixture in benign_fixtures():
        try:
            benign_results.append((name, cases._hardened(fixture)))
        except SecretExposureRejected:
            false_positives += 1

    metrics = {
        "adversarial_cases": len(adversarial),
        "vulnerable_asr": f"{vulnerable_successes}/{len(adversarial)}",
        "hardened_asr": f"{hardened_successes}/{len(adversarial)}",
        "hardened_fpr": f"{false_positives}/{len(benign_fixtures())}",
        "safe_task_rate": f"{len(benign_results)}/{len(benign_fixtures())}",
        "dataset_sha256": cases._dataset_sha256(),
        "fixture_sha256": cases._fixture_sha256(),
        "secret_graph_sha256": cases.secret_exposure_manifest_digest(build_fixture()["manifest"]),
    }
    return {"metrics": metrics, "benign": benign_results}


def main() -> None:
    result = run_evaluation()
    print(json.dumps(result["metrics"], sort_keys=True))
    for name, assessment in result["benign"]:
        print(json.dumps({
            "benign": name,
            "assessment_evidence_sha256": assessment.assessment_evidence_sha256,
            "controlled_paths": assessment.controlled_path_count,
            "exposed_paths": assessment.exposed_path_count,
            "max_blast_radius_score": assessment.max_blast_radius_score,
        }, sort_keys=True))


if __name__ == "__main__":
    main()
