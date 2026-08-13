from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aegis.approvals.durable import DurableApprovalStore
from aegis.effects.durable import DurableApprovedEffectPipeline, TransactionalEffectCoordinator
from aegis.effects.revalidation import (
    RevalidatingDurableEffectWorker,
    RevalidatingEffectOutboxStore,
    SyntheticAuthorizationStateStore,
    SyntheticRevalidatingEffectService,
)


VULNERABLE_P3A_POLICY_VERSION = "p2m-default-no-n-through-s-chain-v1"


@dataclass(frozen=True)
class VulnerableP2MDefaultStack:
    policy_version: str
    effect_service: SyntheticRevalidatingEffectService
    pipeline: DurableApprovedEffectPipeline


def build_vulnerable_p2m_default_stack(
    *,
    state_database_path: Path,
    execution_database_path: Path,
    approval_store: DurableApprovalStore,
    authorization_store: SyntheticAuthorizationStateStore,
) -> VulnerableP2MDefaultStack:
    outbox = RevalidatingEffectOutboxStore(state_database_path)
    service = SyntheticRevalidatingEffectService(
        execution_database_path,
        authorization_store=authorization_store,
    )
    worker = RevalidatingDurableEffectWorker(outbox_store=outbox, effect_service=service)
    pipeline = DurableApprovedEffectPipeline(
        coordinator=TransactionalEffectCoordinator(approval_store),
        worker=worker,
    )
    return VulnerableP2MDefaultStack(
        policy_version=VULNERABLE_P3A_POLICY_VERSION,
        effect_service=service,
        pipeline=pipeline,
    )
