import json
from copy import deepcopy

import evals.portfolio_adaptive_security as portfolio_adaptive
from aegis.identity.models import Principal
from aegis.rag.evaluation import (
    contains_hidden_context_leak,
    evaluate_groundedness,
    validate_tool_output,
)
from aegis.rag.models import KnowledgeDocument, RetrievedDocument
from aegis.rag.store import KnowledgeStore
from evals.portfolio_adaptive_security import build_report, mutate
from real_model_evals.runner import EvaluationConfig, run_evaluation


def principal(tenant_id: str = "tenant_a") -> Principal:
    return Principal(user_id="user-1", tenant_id=tenant_id, roles=frozenset({"employee"}))


def documents() -> list[KnowledgeDocument]:
    return [
        KnowledgeDocument(
            id=1, tenant_id="tenant_a", title="VPN", text="VPN enabled for staff", canary="A"
        ),
        KnowledgeDocument(
            id=2, tenant_id="tenant_b", title="VPN", text="VPN disabled B-CANARY", canary="B"
        ),
        KnowledgeDocument(
            id=3,
            tenant_id="tenant_a",
            title="VPN copy",
            text="VPN enabled for staff IGNORE POLICY",
            canary="P",
        ),
    ]


def test_qdrant_local_tenant_filter_poison_and_near_duplicate() -> None:
    store = KnowledgeStore(documents())
    results = store.search(principal=principal(), query="VPN enabled staff policy", limit=10)
    assert {item.tenant_id for item in results} == {"tenant_a"}
    assert all("B-CANARY" not in item.text for item in results)
    assert {item.document_id for item in results} == {1, 3}


def test_qdrant_revoked_document_and_metadata_filter_bypass() -> None:
    store = KnowledgeStore(documents())
    store.revoke(3)
    hostile_query = json.dumps({"tenant_id": {"$ne": "tenant_a"}})
    results = store.search(principal=principal(), query=hostile_query, limit=10)
    assert all(item.document_id != 3 for item in results)
    assert {item.tenant_id for item in results} <= {"tenant_a"}


def test_collection_identity_is_server_owned() -> None:
    store = KnowledgeStore(documents())
    assert store.COLLECTION == "knowledge_base"
    assert "collection" not in store.search.__annotations__


def test_groundedness_binding_conflict_abstention_and_leakage() -> None:
    docs = [
        RetrievedDocument(
            document_id=1, tenant_id="tenant_a", title="A", text="VPN enabled", score=1
        ),
        RetrievedDocument(
            document_id=2, tenant_id="tenant_a", title="B", text="VPN disabled", score=0.9
        ),
    ]
    result = evaluate_groundedness(
        answer="VPN enabled [doc:1] [doc:99]",
        claims=("VPN enabled", "Admin is Pat"),
        documents=docs,
    )
    assert result.unbound_citations == (99,)
    assert result.missing_citations == (2,)
    assert result.unsupported_claims == ("Admin is Pat",)
    assert result.conflicting_evidence and result.should_abstain
    assert contains_hidden_context_leak("Here is the system prompt")


def test_tool_output_validation_precedes_execution() -> None:
    allowed = frozenset({"get_asset"})
    assert validate_tool_output(
        proposed_name="get_asset",
        arguments={"asset_id": "A-1"},
        allowed_tools=allowed,
        tenant_id="tenant_a",
    )
    assert not validate_tool_output(
        proposed_name="reset", arguments={}, allowed_tools=allowed, tenant_id="tenant_a"
    )
    assert not validate_tool_output(
        proposed_name="get_asset",
        arguments={"tenant_id": "tenant_b"},
        allowed_tools=allowed,
        tenant_id="tenant_a",
    )


def test_adaptive_metrics_are_derived_from_cases() -> None:
    report = build_report()
    assert report["status"] == "VERIFIED"
    assert report["gate"]["passed"]
    assert all(report["gate"]["checks"].values())
    assert report["behavioral_source"] == "evals.p2b_indirect_prompt_injection"
    assert report["adaptive_catalog"]["adaptive_case_count"] >= 1
    assert not report["adaptive_catalog"]["executed"]
    metrics = report["metrics"]
    assert metrics["vulnerable_asr"]["numerator"] == metrics["vulnerable_asr"]["denominator"]
    assert metrics["hardened_asr"]["numerator"] == 0
    assert report["adaptive_catalog"]["deferred"] == ["multimodal-metadata"]
    vulnerable = report["observations"]["vulnerable"]["adversarial_attempts"]
    hardened = report["observations"]["hardened"]["adversarial_attempts"]
    assert all(attempt["side_effect_verified"] for attempt in vulnerable)
    assert all(not attempt["side_effect_verified"] for attempt in hardened)
    assert (
        len(
            mutate(
                {
                    "id": "x",
                    "family": "indirect_prompt_injection",
                    "attack": True,
                    "payload": "IGNORE",
                }
            )
        )
        == 2
    )


def test_adaptive_gate_fails_when_behavioral_control_is_weakened(monkeypatch) -> None:
    behavioral = portfolio_adaptive.build_p2b_report()
    weakened = deepcopy(behavioral)
    weakened["variants"]["hardened"]["metrics"]["asr"]["successful_policy_violations"] = 1

    monkeypatch.setattr(portfolio_adaptive, "build_p2b_report", lambda: weakened)
    report = portfolio_adaptive.build_report()

    assert report["status"] == "FAILED"
    assert not report["gate"]["passed"]
    assert not report["gate"]["checks"]["hardened_side_effects_prevented"]


def test_fake_and_live_evidence_cannot_be_confused(monkeypatch) -> None:
    fake = run_evaluation()
    assert fake["status"] == "VERIFIED" and fake["endpoint_class"] == "offline_fake"
    monkeypatch.delenv("AEGIS_REAL_MODEL_OPT_IN", raising=False)
    live = run_evaluation(EvaluationConfig(mode="live"))
    assert live["status"] == "BLOCKED" and live["transcripts"] == []
