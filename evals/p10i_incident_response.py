from __future__ import annotations

from dataclasses import replace
import hashlib
import json

from aegis.inference.incident_response_security import InferenceIncidentResponseAnalyzer
from aegis.inference.incident_response_types import *
from aegis.inference.replica_routing_types import ReplicaDecision, ReplicaRisk
from aegis.vulnerable.incident_response import VulnerableCallerDeclaredIncidentResponseSafety
from evals.p10i_fixture import *


def _attack(name: str, f: dict) -> tuple[str, dict]:
    return name, f


def _manifest_attack(name: str, mutate, *, refresh_policy: bool = True):
    f = build_fixture()
    m = mutate(f["manifest"])
    return _attack(name, rebind(f, m, safe=True, refresh_policy=refresh_policy))


def _upstream_attack(name: str, **kwargs):
    f = build_fixture()
    return _attack(name, {**f, "p10h": replace(f["p10h"], **kwargs)})


def adversarial_fixtures() -> list[tuple[str, dict]]:
    cases: list[tuple[str, dict]] = []
    # Upstream trust contract.
    cases += [
        _upstream_attack("upstream_decision_deny", decision=ReplicaDecision.DENY),
        _upstream_attack("upstream_has_risk", risks=(ReplicaRisk.UPSTREAM_P10G_INVALID,)),
        _upstream_attack("upstream_schema", assessment_schema_version="wrong"),
        _upstream_attack("upstream_mode", assessment_mode="wrong"),
        _upstream_attack("upstream_digest", assessment_evidence_sha256=h("wrong-upstream")),
    ]
    for field in (
        "upstream_p10g_bound", "replica_identity_verified", "health_and_capacity_verified",
        "routing_generation_verified", "autoscaling_verified", "failover_fencing_verified",
        "idempotency_replay_verified", "lineage_verified",
    ):
        cases.append(_upstream_attack(f"upstream_positive_{field}", **{field: False}))
    for field in (
        "caller_declared_safety_trusted", "production_service_mesh_integrated",
        "production_orchestrator_integrated", "distributed_consensus_validated",
        "cross_zone_failover_validated", "load_balancer_stickiness_validated",
        "production_autoscaler_validated", "network_partition_resistance_validated",
        "exactly_once_delivery_validated",
    ):
        cases.append(_upstream_attack(f"upstream_nonclaim_{field}", **{field: True}))

    # Outer / route / incident binding.
    route_fields = {
        "p10h_assessment_sha256": h("other-p10h"), "request_id": "request-beta-9",
        "tenant_id": "beta", "session_id": "tenant/beta/session/x", "target_model_id": "other-model",
        "target_model_revision": "other-rev", "adapter_ids": ("adapter-security-policy",),
        "adapter_generation": 11, "partition_ids": ("other-partition",), "stream_id": "other-stream",
        "router_id": "router-other", "router_generation": 41, "replica_ids": ("replica-inference-b", "replica-inference-c"),
        "routing_ids": ("route-other",), "incident_id": "incident-other", "compromised_replica_id": "replica-inference-b",
    }
    for field, value in route_fields.items():
        cases.append(_manifest_attack(f"route_{field}", lambda m, field=field, value=value: replace(m, **{field: value})))
    cases.append(_manifest_attack("network_operation", lambda m: replace(m, network_operations=1)))
    cases.append(_manifest_attack("manifest_digest_outer", lambda m: replace(m, created_at_epoch=m.created_at_epoch + 1), refresh_policy=False))

    # Signal evidence.
    for idx in range(3):
        cases.append(_manifest_attack(f"signal_seq_{idx}", lambda m, idx=idx: replace(m, signals=tuple(replace(s, sequence_no=s.sequence_no + 7) if i == idx else s for i, s in enumerate(m.signals)))))
        cases.append(_manifest_attack(f"signal_chain_{idx}", lambda m, idx=idx: replace(m, signals=tuple(replace(s, previous_signal_sha256=h(f'bad-chain-{idx}')) if i == idx else s for i, s in enumerate(m.signals)))))
        cases.append(_manifest_attack(f"signal_request_{idx}", lambda m, idx=idx: replace(m, signals=tuple(replace(s, request_id='request-other') if i == idx else s for i, s in enumerate(m.signals)))))
        cases.append(_manifest_attack(f"signal_tenant_{idx}", lambda m, idx=idx: replace(m, signals=tuple(replace(s, tenant_id='beta') if i == idx else s for i, s in enumerate(m.signals)))))
        cases.append(_manifest_attack(f"signal_session_{idx}", lambda m, idx=idx: replace(m, signals=tuple(replace(s, session_id='tenant/beta/session/x') if i == idx else s for i, s in enumerate(m.signals)))))
        cases.append(_manifest_attack(f"signal_late_{idx}", lambda m, idx=idx: replace(m, signals=tuple(replace(s, observed_at_epoch=m.detection_started_at_epoch + 99) if i == idx else s for i, s in enumerate(m.signals)))))
    cases.append(_manifest_attack("signal_drop", lambda m: replace(m, signals=m.signals[:-1])))
    cases.append(_manifest_attack("signal_type", lambda m: replace(m, signals=(replace(m.signals[0], signal_type="unknown_signal"),) + m.signals[1:])))
    cases.append(_manifest_attack("signal_id", lambda m: replace(m, signals=(replace(m.signals[0], signal_id="signal-other"),) + m.signals[1:])))

    # Containment.
    for idx in range(3):
        cases.append(_manifest_attack(f"contain_seq_{idx}", lambda m, idx=idx: replace(m, containment_actions=tuple(replace(a, sequence_no=a.sequence_no + 4) if i == idx else a for i, a in enumerate(m.containment_actions)))))
        cases.append(_manifest_attack(f"contain_chain_{idx}", lambda m, idx=idx: replace(m, containment_actions=tuple(replace(a, previous_action_sha256=h(f'bad-action-chain-{idx}')) if i == idx else a for i, a in enumerate(m.containment_actions)))))
        cases.append(_manifest_attack(f"contain_auth_{idx}", lambda m, idx=idx: replace(m, containment_actions=tuple(replace(a, authorization_sha256=h(f'bad-auth-{idx}')) if i == idx else a for i, a in enumerate(m.containment_actions)))))
        cases.append(_manifest_attack(f"contain_target_{idx}", lambda m, idx=idx: replace(m, containment_actions=tuple(replace(a, target_id='wrong-target') if i == idx else a for i, a in enumerate(m.containment_actions)))))
        cases.append(_manifest_attack(f"contain_late_{idx}", lambda m, idx=idx: replace(m, containment_actions=tuple(replace(a, completed_at_epoch=m.detection_started_at_epoch + 99) if i == idx else a for i, a in enumerate(m.containment_actions)))))
    cases.append(_manifest_attack("contain_drop", lambda m: replace(m, containment_actions=m.containment_actions[:-1])))
    cases.append(_manifest_attack("contain_type", lambda m: replace(m, containment_actions=(replace(m.containment_actions[0], action_type="log_only"),) + m.containment_actions[1:])))

    # Recovery.
    for idx in range(3):
        cases.append(_manifest_attack(f"recovery_seq_{idx}", lambda m, idx=idx: replace(m, recovery_steps=tuple(replace(r, sequence_no=r.sequence_no + 3) if i == idx else r for i, r in enumerate(m.recovery_steps)))))
        cases.append(_manifest_attack(f"recovery_chain_{idx}", lambda m, idx=idx: replace(m, recovery_steps=tuple(replace(r, previous_recovery_sha256=h(f'bad-recovery-chain-{idx}')) if i == idx else r for i, r in enumerate(m.recovery_steps)))))
        cases.append(_manifest_attack(f"recovery_rollback_{idx}", lambda m, idx=idx: replace(m, recovery_steps=tuple(replace(r, observed_generation=1) if i == idx else r for i, r in enumerate(m.recovery_steps)))))
        cases.append(_manifest_attack(f"recovery_unverified_{idx}", lambda m, idx=idx: replace(m, recovery_steps=tuple(replace(r, verified=False) if i == idx else r for i, r in enumerate(m.recovery_steps)))))
    cases.append(_manifest_attack("recovery_drop", lambda m: replace(m, recovery_steps=m.recovery_steps[:-1])))
    cases.append(_manifest_attack("recovery_type", lambda m: replace(m, recovery_steps=(replace(m.recovery_steps[0], recovery_type="restart_without_verify"),) + m.recovery_steps[1:])))

    # Forensics.
    for idx in range(3):
        cases.append(_manifest_attack(f"forensic_chain_{idx}", lambda m, idx=idx: replace(m, forensic_artifacts=tuple(replace(f, previous_artifact_sha256=h(f'bad-forensic-prev-{idx}')) if i == idx else f for i, f in enumerate(m.forensic_artifacts)))))
        cases.append(_manifest_attack(f"forensic_custody_{idx}", lambda m, idx=idx: replace(m, forensic_artifacts=tuple(replace(f, chain_of_custody_sha256=h(f'bad-custody-{idx}')) if i == idx else f for i, f in enumerate(m.forensic_artifacts)))))
        cases.append(_manifest_attack(f"forensic_mutable_{idx}", lambda m, idx=idx: replace(m, forensic_artifacts=tuple(replace(f, immutable_snapshot=False) if i == idx else f for i, f in enumerate(m.forensic_artifacts)))))
    cases.append(_manifest_attack("forensic_drop", lambda m: replace(m, forensic_artifacts=m.forensic_artifacts[:-1])))
    cases.append(_manifest_attack("forensic_kind", lambda m: replace(m, forensic_artifacts=(replace(m.forensic_artifacts[0], artifact_kind="unknown"),) + m.forensic_artifacts[1:])))
    cases.append(_manifest_attack("forensic_id", lambda m: replace(m, forensic_artifacts=(replace(m.forensic_artifacts[0], artifact_id="forensic-other"),) + m.forensic_artifacts[1:])))

    # Exit gate / claim boundaries.
    gate_mutations = {
        "gate_required_controls": lambda g: replace(g, required_controls=g.required_controls[:-1]),
        "gate_validated_controls": lambda g: replace(g, validated_controls=g.validated_controls[:-1]),
        "gate_runtime": lambda g: replace(g, local_runtime_gates=g.local_runtime_gates[:-1]),
        "gate_debt": lambda g: replace(g, deferred_mastery_items=()),
        "gate_hosted_ci_claim": lambda g: replace(g, hosted_ci_execution_verified=True),
        "gate_production_claim": lambda g: replace(g, production_validation_claimed=True),
        "gate_mastery_claim": lambda g: replace(g, professional_mastery_complete=True),
        "gate_exit_false": lambda g: replace(g, phase10_exit_eligible=False),
        "gate_wrong_status": lambda g: replace(g, status=ExitGateStatus.PASS),
    }
    for name, fn in gate_mutations.items():
        cases.append(_manifest_attack(name, lambda m, fn=fn: replace(m, exit_gate=fn(m.exit_gate))))
    return cases


def safe_fixtures() -> list[tuple[str, dict]]:
    return [
        ("canonical", build_fixture()),
        ("wider_timing", safe_wider_timing_fixture()),
        ("uppercase_digest", safe_uppercase_digest_fixture()),
        ("delayed_evaluation", safe_delayed_evaluation_fixture()),
    ]


def _fixture_eval_digest() -> str:
    payload = open(__file__.replace("p10i_incident_response.py", "p10i_fixture.py"), "rb").read() + open(__file__, "rb").read()
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    vulnerable = VulnerableCallerDeclaredIncidentResponseSafety()
    attacks = adversarial_fixtures()
    safe = safe_fixtures()
    vulnerable_success = 0
    hardened_success = 0
    for _, f in attacks:
        vulnerable_success += int(vulnerable.accepts(f["request"]))
        try:
            result = InferenceIncidentResponseAnalyzer(f["policy"]).evaluate(f["manifest"], f["request"], f["p10h"])
            hardened_success += int(result.decision == IncidentDecision.ALLOW)
        except InferenceIncidentResponseRejected:
            pass
    false_positives = 0
    safe_success = 0
    clean = None
    for name, f in safe:
        result = InferenceIncidentResponseAnalyzer(f["policy"]).evaluate(f["manifest"], f["request"], f["p10h"])
        accepted = result.decision == IncidentDecision.ALLOW
        safe_success += int(accepted)
        false_positives += int(not accepted)
        if name == "canonical":
            clean = result
    report = {
        "phase": "P10-I",
        "adversarial_cases": len(attacks),
        "vulnerable_asr": f"{vulnerable_success}/{len(attacks)}",
        "hardened_asr": f"{hardened_success}/{len(attacks)}",
        "hardened_fpr": f"{false_positives}/{len(safe)}",
        "safe_task_rate": f"{safe_success}/{len(safe)}",
        "manifest_sha256": inference_incident_response_manifest_digest(build_fixture()["manifest"]),
        "adversarial_dataset_sha256": digest_json(tuple(name for name, _ in attacks)),
        "fixture_evaluator_sha256": _fixture_eval_digest(),
        "clean_assessment_sha256": clean.assessment_evidence_sha256 if clean else "",
        "clean_decision": clean.decision.value if clean else "",
        "exit_gate_status": clean.exit_gate_status.value if clean else "",
        "professional_mastery_complete": clean.professional_mastery_complete if clean else None,
        "hosted_ci_execution_verified": clean.hosted_ci_execution_verified if clean else None,
        "production_validation_claimed": clean.production_validation_claimed if clean else None,
    }
    print(json.dumps(report, sort_keys=True))
    return 0 if vulnerable_success == len(attacks) and hardened_success == 0 and false_positives == 0 and safe_success == len(safe) else 1


if __name__ == "__main__":
    raise SystemExit(main())
