from __future__ import annotations

from aegis.effects.durable import EffectOutboxRecord, SyntheticEffectExecution
from aegis.effects.rollback_anchor import AnchoredAuthorizationDecision
from aegis.effects.signed_authorization import ProvenanceFencedSyntheticEffectService


class VulnerableRollbackBlindEffectService(ProvenanceFencedSyntheticEffectService):
    """Intentionally trusts only the rolled-back local execution database state."""

    def execute_with_anchored_decision(
        self,
        record: EffectOutboxRecord,
        envelope: AnchoredAuthorizationDecision,
    ) -> SyntheticEffectExecution:
        # INTENTIONALLY VULNERABLE: P2-O provenance and freshness checks remain,
        # but the independent control-plane generation and its envelope signature
        # are ignored. An internally consistent old execution DB can therefore
        # make obsolete authorization state look current again.
        return super().execute_with_decision(record, envelope.payload.decision)
