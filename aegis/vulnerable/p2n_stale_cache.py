from __future__ import annotations

from pathlib import Path

from aegis.effects.durable import (
    EffectBindingError,
    EffectOutboxRecord,
    SyntheticEffectExecution,
    SyntheticIdempotentEffectService,
)
from aegis.effects.revalidation import ExecutionAuthorizationReason
from aegis.effects.versioned_revalidation import (
    AuthorizationVersionStore,
    CachedAuthorizationDecision,
    authorization_record_binding,
)


class VulnerableCachedAuthorizationEffectService(SyntheticIdempotentEffectService):
    """Intentionally trusts a cached allow decision without an authoritative version fence."""

    def __init__(
        self,
        database_path: Path,
        *,
        authoritative_versions: AuthorizationVersionStore,
        clock=None,
    ) -> None:
        database_path = Path(database_path)
        if authoritative_versions.database_path != database_path:
            raise ValueError("authoritative versions and effect ledger must share one SQLite database")
        self.authoritative_versions = authoritative_versions
        if clock is None:
            super().__init__(database_path)
        else:
            super().__init__(database_path, clock=clock)

    def execute_with_decision(
        self,
        record: EffectOutboxRecord,
        decision: CachedAuthorizationDecision,
    ) -> SyntheticEffectExecution:
        if decision.tenant_id != record.tenant_id:
            raise EffectBindingError("cached authorization tenant binding mismatch")
        if decision.record_binding_hash != authorization_record_binding(record):
            raise EffectBindingError("cached authorization record binding mismatch")
        if decision.reason is not ExecutionAuthorizationReason.ALLOWED:
            raise PermissionError("cached authorization denied")
        # INTENTIONALLY VULNERABLE: authoritative policy_version and revocation_epoch
        # are available but never checked before the synthetic effect.
        return super().execute(record)
