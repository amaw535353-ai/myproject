import copy

import pytest
import subprocess

from evals.p11b_fixture import DEFERRED_MASTERY_ITEMS, canonical_bytes, fixture, manifests_sha256, sha256
from evals.p11b_kubernetes_security import EvidenceRejected, assess, validate_evidence
from scripts.run_p11b_kubernetes_lab import authorization_answer, pod_security_api_denial


def live_fixture():
    value = fixture()
    value["execution_mode"] = "live"
    value["environment_classification"] = "LOCAL_K3D_K3S"
    value["observations"]["infrastructure"] = {"cluster_created": True, "api_reached": True, "node_ready": True}
    for section in ("psa", "rbac"):
        for item in value["observations"][section]: item["api_evaluated"] = True
    value["observations"]["network_policy"]["api_evaluated"] = True
    return value


def test_valid_deterministic_evidence():
    result = assess(fixture())
    assert result["ASR"] == {"numerator": 0, "denominator": 8, "value": 0.0}
    assert result["live_kubernetes_cluster_validated"] is False


def test_canonical_hashing_is_key_order_independent():
    assert canonical_bytes({"b": 1, "a": 2}) == canonical_bytes({"a": 2, "b": 1})
    assert sha256({"b": 1, "a": 2}) == sha256({"a": 2, "b": 1})


def test_malformed_schema_rejected():
    value = fixture(); value.pop("phase")
    with pytest.raises(EvidenceRejected, match="schema"): assess(value)


def test_manifest_integrity_mismatch_rejected():
    value = fixture(); value["fixture_manifests_sha256"] = "0" * 64
    with pytest.raises(EvidenceRejected, match="integrity"): assess(value)


def test_assessment_integrity_mismatch_rejected():
    value = fixture(); value["assessment_sha256"] = "0" * 64
    with pytest.raises(EvidenceRejected, match="assessment integrity"): validate_evidence(value)


def test_caller_summary_is_recomputed_and_tampering_rejected():
    value = fixture(); value["ASR"] = {"numerator": 0, "denominator": 0, "value": 0}
    with pytest.raises(EvidenceRejected, match="caller summary"): validate_evidence(value)


def test_unavailable_infrastructure_is_deferred():
    result = assess(fixture("live"))
    assert result["live_kubernetes_cluster_validated"] is False


def test_one_successful_attack_prevents_live_pass():
    value = live_fixture(); value["observations"]["psa"][0]["observed"] = "ALLOW"
    result = assess(value)
    assert result["ASR"]["numerator"] == 1 and not result["live_kubernetes_cluster_validated"]


def test_benign_false_positive_affects_fpr_and_safe_task_rate():
    value = live_fixture(); value["observations"]["psa"][-1]["observed"] = "DENY"
    result = assess(value)
    assert result["FPR"]["numerator"] == 1 and result["SafeTaskRate"]["numerator"] == 0


def test_mastery_debt_cannot_be_removed():
    value = fixture(); value["deferred_mastery_items"] = []
    with pytest.raises(EvidenceRejected, match="mastery debt"): assess(value)


def test_live_flag_requires_actual_cluster_evidence():
    value = live_fixture(); value["observations"]["infrastructure"]["cluster_created"] = False
    assert not assess(value)["live_kubernetes_cluster_validated"]


def test_psa_live_status_requires_api_evidence():
    value = live_fixture(); value["observations"]["psa"][0]["api_evaluated"] = False
    assert not assess(value)["live_kubernetes_cluster_validated"]


def test_rbac_live_status_requires_authorization_api_evidence():
    value = live_fixture(); value["observations"]["rbac"][0]["api_evaluated"] = False
    assert not assess(value)["live_kubernetes_cluster_validated"]


@pytest.mark.parametrize("field", ["baseline", "authorized_after_policy"])
def test_network_policy_requires_working_positive_paths(field):
    value = live_fixture(); value["observations"]["network_policy"][field] = "TIMEOUT"
    assert not assess(value)["live_kubernetes_cluster_validated"]


def test_network_policy_requires_attacker_denied_path():
    value = live_fixture(); value["observations"]["network_policy"]["attacker_after_policy"] = "SUCCESS"
    assert not assess(value)["live_kubernetes_cluster_validated"]


@pytest.mark.parametrize("field", ["production_validation_claimed", "professional_mastery_complete"])
def test_forbidden_production_and_mastery_claims_rejected(field):
    value = fixture(); value[field] = True
    with pytest.raises(EvidenceRejected, match="forbidden"): assess(value)


def test_clean_live_observations_pass_all_gates():
    result = assess(live_fixture())
    assert result["live_kubernetes_cluster_validated"]
    assert result["rbac"]["incorrect_allows"] == result["rbac"]["incorrect_denies"] == 0


def test_kubectl_authorization_no_is_still_api_evidence():
    proc = subprocess.CompletedProcess([], 1, "Warning: scoped check\nno\n", "")
    assert authorization_answer(proc) == ("DENY", True)


def test_pod_security_spelling_variants_are_api_evidence():
    proc = subprocess.CompletedProcess([], 1, "", "Error: forbidden: violates Pod Security restricted")
    assert pod_security_api_denial(proc)
