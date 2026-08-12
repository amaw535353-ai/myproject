from evals.p2g_resource_exhaustion import build_report


def test_hardened_blocks_duplicate_and_context_loops() -> None:
    report = build_report()
    attempts = report["variants"]["hardened"]["adversarial_attempts"]
    assert len(attempts) == 2
    assert all(attempt["valid"] for attempt in attempts)
    assert all(not attempt["success"] for attempt in attempts)
    assert attempts[0]["blocked_dimension"] == "same_tool_call_count"
    assert attempts[1]["blocked_dimension"] == "context_bytes"


def test_vulnerable_runner_exceeds_both_resource_limits() -> None:
    report = build_report()
    attempts = report["variants"]["vulnerable"]["adversarial_attempts"]
    assert len(attempts) == 2
    assert all(attempt["valid"] for attempt in attempts)
    assert all(attempt["success"] for attempt in attempts)
    assert all(attempt["lab_ceiling_reached"] for attempt in attempts)


def test_p2g_benign_tasks_complete_under_budget() -> None:
    report = build_report()
    attempts = report["variants"]["hardened"]["benign_attempts"]
    assert len(attempts) == 2
    assert all(attempt["valid"] for attempt in attempts)
    assert all(attempt["safe_completion"] for attempt in attempts)
    assert all(not attempt["incorrectly_blocked"] for attempt in attempts)
