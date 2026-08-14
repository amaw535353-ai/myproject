from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


P4Q_PHASE4_EXIT_POLICY_VERSION = "phase4-claim-evidence-exit-v1"


class Phase4EvidencePosture(StrEnum):
    DEFAULT_LOCAL = "default_local"
    POLICY_BOUNDARY = "policy_boundary"
    SYNTHETIC_LAB = "synthetic_lab"


@dataclass(frozen=True)
class Phase4Control:
    milestone: str
    title: str
    threat_model: str
    eval_module: str
    posture: Phase4EvidencePosture
    evidence_paths: tuple[str, ...]
    supported_claims: tuple[str, ...]
    residual_assumptions: tuple[str, ...]
    production_ready: bool = False
    operationally_external: bool = False
    independent_failure_domain: bool = False

    @property
    def eval_command(self) -> str:
        return f"python -m {self.eval_module}"


PHASE4_PROHIBITED_CLAIMS: tuple[str, ...] = (
    "production checkpoint durability",
    "production external trust",
    "production disaster recovery",
    "exactly-once execution",
    "distributed transaction",
    "distributed consensus",
    "independent failure domain",
)


PHASE4_BOUNDARY_CLAIMS: dict[str, bool] = {
    "default_local_checkpoint_hardening": True,
    "synthetic_external_contract_evidence": True,
    "authenticated_local_lifecycle_recovery_evidence": True,
    "production_external_checkpoint_adapter": False,
    "production_external_lifecycle_provider": False,
    "production_checkpoint_durability": False,
    "production_disaster_recovery": False,
    "distributed_transaction": False,
    "distributed_consensus": False,
    "exactly_once_execution": False,
    "independent_failure_domain": False,
    "real_external_trust_operations": False,
    "network_operations_required": False,
}


PHASE4_RESIDUAL_ASSUMPTIONS: tuple[str, ...] = (
    "default checkpoint storage and trust material remain local to the application host",
    "synthetic external checkpoint and lifecycle providers are in-process lab contracts",
    "local SQLite and HMAC artifacts can share rollback and compromise fate",
    "no production KMS HSM or independent rollback-resistant trust service is included",
    "no cross-host transaction consensus or distributed fencing protocol is included",
    "backup and recovery evidence is lab-scoped and is not a disaster-recovery guarantee",
)


PHASE4_CONTROLS: tuple[Phase4Control, ...] = (
    Phase4Control(
        "P4-A",
        "strict checkpoint serialization",
        "docs/threat-model/p4a-strict-checkpoint-serialization.md",
        "evals.p4a_strict_checkpoint_serialization",
        Phase4EvidencePosture.DEFAULT_LOCAL,
        ("aegis/agent/checkpoint_security.py",),
        ("strict allowlisted checkpoint deserialization in the default local runtime",),
        ("serializer policy is application-specific and does not validate model artifacts",),
    ),
    Phase4Control(
        "P4-B",
        "durable checkpoint integrity",
        "docs/threat-model/p4b-durable-checkpoint-integrity.md",
        "evals.p4b_durable_checkpoint_integrity",
        Phase4EvidencePosture.DEFAULT_LOCAL,
        ("aegis/agent/checkpoint_durability.py",),
        ("authenticated local checkpoint and pending-write integrity with monotonic local heads",),
        ("integrity key and anchor remain local synthetic trust material",),
    ),
    Phase4Control(
        "P4-C",
        "checkpoint confidentiality",
        "docs/threat-model/p4c-checkpoint-confidentiality.md",
        "evals.p4c_checkpoint_confidentiality",
        Phase4EvidencePosture.DEFAULT_LOCAL,
        ("aegis/agent/checkpoint_confidentiality.py",),
        ("authenticated encryption of dynamic checkpoint and pending-write payloads at rest",),
        ("structural SQLite identifiers and minimized control metadata remain plaintext by design",),
    ),
    Phase4Control(
        "P4-D",
        "checkpoint encryption-key lifecycle",
        "docs/threat-model/p4d-checkpoint-key-lifecycle.md",
        "evals.p4d_checkpoint_key_lifecycle",
        Phase4EvidencePosture.DEFAULT_LOCAL,
        (
            "aegis/agent/checkpoint_key_lifecycle.py",
            "aegis/agent/checkpoint_keys.py",
        ),
        ("explicit local key states rotation migration and revoked-key rejection",),
        ("key custody is local synthetic material rather than a production key-management service",),
    ),
    Phase4Control(
        "P4-E",
        "authenticated checkpoint backup and restore",
        "docs/threat-model/p4e-checkpoint-backup-restore.md",
        "evals.p4e_checkpoint_backup_restore",
        Phase4EvidencePosture.DEFAULT_LOCAL,
        (
            "aegis/agent/checkpoint_backup.py",
            "aegis/agent/checkpoint_backup_restore.py",
        ),
        ("authenticated encrypted local checkpoint backup packages with rollback and fork checks",),
        ("local backup evidence is not a production disaster-recovery or independent-custody guarantee",),
    ),
    Phase4Control(
        "P4-F",
        "checkpoint deployment trust-provider boundary",
        "docs/threat-model/p4f-checkpoint-trust-provider-boundary.md",
        "evals.p4f_checkpoint_trust_provider_posture",
        Phase4EvidencePosture.POLICY_BOUNDARY,
        ("aegis/agent/checkpoint_trust.py",),
        ("explicit policy descriptors for five checkpoint trust surfaces",),
        ("a complete external descriptor proves policy shape only and does not instantiate a provider",),
    ),
    Phase4Control(
        "P4-G",
        "synthetic external checkpoint adapter contract",
        "docs/threat-model/p4g-checkpoint-external-adapter-contract-harness.md",
        "evals.p4g_checkpoint_external_contract_harness",
        Phase4EvidencePosture.SYNTHETIC_LAB,
        ("aegis/agent/checkpoint_external_contracts.py",),
        ("synthetic external-style checkpoint operation contract coverage",),
        ("provider is in-process synthetic and performs no real external trust operation",),
    ),
    Phase4Control(
        "P4-H",
        "checkpoint runtime operation-provider seam",
        "docs/threat-model/p4h-checkpoint-runtime-provider-seam.md",
        "evals.p4h_checkpoint_runtime_provider_seam",
        Phase4EvidencePosture.DEFAULT_LOCAL,
        (
            "aegis/agent/checkpoint_operation_runtime.py",
            "aegis/agent/checkpoint_runtime_contracts.py",
        ),
        ("default checkpoint runtime routes security operations through explicit provider interfaces",),
        ("default injected providers remain local synthetic implementations",),
    ),
    Phase4Control(
        "P4-I",
        "checkpoint lifecycle capability boundary",
        "docs/threat-model/p4i-checkpoint-lifecycle-capabilities.md",
        "evals.p4i_checkpoint_lifecycle_capabilities",
        Phase4EvidencePosture.DEFAULT_LOCAL,
        ("aegis/agent/checkpoint_lifecycle_capabilities.py",),
        ("migration snapshot and restore require explicit lifecycle capabilities and anchor binding",),
        ("default lifecycle coordination remains single-host local behavior",),
    ),
    Phase4Control(
        "P4-J",
        "synthetic external lifecycle contract",
        "docs/threat-model/p4j-external-lifecycle-contract.md",
        "evals.p4j_external_lifecycle_contract",
        Phase4EvidencePosture.SYNTHETIC_LAB,
        (
            "aegis/agent/checkpoint_external_lifecycle.py",
            "aegis/agent/checkpoint_external_runtime_bridge.py",
        ),
        ("synthetic external-style migration snapshot and restore lifecycle contract coverage",),
        ("coordination is in-process compensating logic rather than distributed atomicity",),
    ),
    Phase4Control(
        "P4-K",
        "checkpoint lifecycle deployment trust boundary",
        "docs/threat-model/p4k-checkpoint-lifecycle-trust-boundary.md",
        "evals.p4k_checkpoint_lifecycle_trust",
        Phase4EvidencePosture.POLICY_BOUNDARY,
        ("aegis/agent/checkpoint_lifecycle_trust.py",),
        ("production eligibility policy rejects included synthetic lifecycle providers",),
        ("policy acceptance of an external descriptor would not prove a real provider implementation",),
    ),
    Phase4Control(
        "P4-L",
        "lifecycle failure and fencing semantics",
        "docs/threat-model/p4l-checkpoint-lifecycle-failure-fencing.md",
        "evals.p4l_checkpoint_lifecycle_fencing",
        Phase4EvidencePosture.SYNTHETIC_LAB,
        ("aegis/agent/checkpoint_lifecycle_fencing.py",),
        ("deterministic in-process lifecycle command fencing and ambiguous-response handling",),
        ("fence and receipts are not distributed or durable across process restart in this milestone",),
    ),
    Phase4Control(
        "P4-M",
        "durable lifecycle command journal",
        "docs/threat-model/p4m-durable-lifecycle-command-journal.md",
        "evals.p4m_durable_lifecycle_journal",
        Phase4EvidencePosture.SYNTHETIC_LAB,
        ("aegis/agent/checkpoint_lifecycle_journal.py",),
        ("authenticated local durable lifecycle command identity fencing and restart reconciliation",),
        ("journal and HMAC key remain same-host local artifacts",),
    ),
    Phase4Control(
        "P4-N",
        "lifecycle journal witness",
        "docs/threat-model/p4n-lifecycle-journal-witness.md",
        "evals.p4n_lifecycle_journal_witness",
        Phase4EvidencePosture.SYNTHETIC_LAB,
        ("aegis/agent/checkpoint_lifecycle_journal_witness.py",),
        ("separate local authenticated witness detects modeled caller-journal rollback",),
        ("journal and witness remain local and do not create a production independent failure domain",),
    ),
    Phase4Control(
        "P4-O",
        "provider-owned lifecycle outcome receipts",
        "docs/threat-model/p4o-provider-outcome-receipts.md",
        "evals.p4o_provider_outcome_receipts",
        Phase4EvidencePosture.SYNTHETIC_LAB,
        ("aegis/agent/checkpoint_lifecycle_outcome_receipts.py",),
        ("authenticated provider-owned exact-command outcome evidence supports caller reconciliation",),
        ("lifecycle mutation and provider outcome persistence remain separate local durability events",),
    ),
    Phase4Control(
        "P4-P",
        "provider-internal crash-safe command state",
        "docs/threat-model/p4p-provider-crash-safe-state.md",
        "evals.p4p_provider_crash_safe_state",
        Phase4EvidencePosture.SYNTHETIC_LAB,
        ("aegis/agent/checkpoint_lifecycle_provider_state_machine.py",),
        ("provider-owned command state and proof-based recovery close the modeled mutation-to-receipt ambiguity",),
        ("proof-based local convergence is not an atomic exactly-once or distributed transaction guarantee",),
    ),
)


def expected_phase4_milestones() -> tuple[str, ...]:
    return tuple(f"P4-{chr(code)}" for code in range(ord("A"), ord("P") + 1))


def phase4_evidence_register() -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "milestone": item.milestone,
            "title": item.title,
            "threat_model": item.threat_model,
            "eval_module": item.eval_module,
            "eval_command": item.eval_command,
            "posture": item.posture.value,
            "evidence_paths": item.evidence_paths,
            "supported_claims": item.supported_claims,
            "residual_assumptions": item.residual_assumptions,
            "production_ready": item.production_ready,
            "operationally_external": item.operationally_external,
            "independent_failure_domain": item.independent_failure_domain,
        }
        for item in PHASE4_CONTROLS
    )
