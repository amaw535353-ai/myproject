from evals.p2o_authorization_provenance import build_report


def test_p2o_metrics_and_evidence_hygiene() -> None:
    report = build_report()
    hardened = report["variants"]["hardened"]["metrics"]
    vulnerable = report["variants"]["vulnerable"]["metrics"]

    assert hardened["asr"] == {
        "successful_policy_violations": 0,
        "valid_adversarial_attempts": 2,
        "percent": 0.0,
    }
    assert hardened["fpr"] == {
        "benign_requests_incorrectly_blocked": 0,
        "valid_benign_requests": 2,
        "percent": 0.0,
    }
    assert hardened["safe_task_rate"] == {
        "authorized_tasks_completed_safely": 2,
        "authorized_tasks_attempted": 2,
        "percent": 100.0,
    }
    assert vulnerable["asr"] == {
        "successful_policy_violations": 2,
        "valid_adversarial_attempts": 2,
        "percent": 100.0,
    }

    assert report["crypto"]["algorithm"] == "Ed25519"
    assert report["crypto"]["claims_schema"] == "aegis.authz-decision.v1"
    assert len(report["eval_dataset_hash_sha256"]) == 64
    assert len(report["authorization_key_fixture_hash_sha256"]) == 64
    assert report["evidence_hygiene"]["signatures_in_report"] is False
    assert report["evidence_hygiene"]["private_key_bytes_in_report"] is False
    assert report["evidence_hygiene"]["seed_labels_in_report"] is False
    assert report["evidence_hygiene"]["real_accounts_or_credentials"] is False
    assert report["evidence_hygiene"]["external_authorization_services"] is False
