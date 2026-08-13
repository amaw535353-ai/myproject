from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from aegis.effects.durable import EffectBindingError, EffectOutboxRecord, SyntheticEffectExecution, SyntheticIdempotentEffectService
from aegis.effects.revalidation import ExecutionAuthorizationReason
from aegis.effects.signed_authorization import SignedAuthorizationDecision
from aegis.effects.versioned_revalidation import AuthorizationVersionStore, authorization_record_binding


class VulnerableUnsignedAuthorizationEffectService(SyntheticIdempotentEffectService):
    """Intentionally trusts provenance metadata without verifying signature or key epoch."""

    def __init__(
        self,
        database_path: Path,
        *,
        authoritative_versions: AuthorizationVersionStore,
        expected_issuer_id: str,
        expected_audience: str,
        clock=None,
    ) -> None:
        database_path = Path(database_path)
        if authoritative_versions.database_path != database_path:
            raise ValueError("authoritative versions and effect ledger must share one SQLite database")
        self.authoritative_versions = authoritative_versions
        self.expected_issuer_id = expected_issuer_id
        self.expected_audience = expected_audience
        if clock is None:
            super().__init__(database_path)
            self._decision_clock = lambda: datetime.now(timezone.utc)
        else:
            super().__init__(database_path, clock=clock)
            self._decision_clock = clock

    def execute_with_decision(
        self,
        record: EffectOutboxRecord,
        decision: SignedAuthorizationDecision,
    ) -> SyntheticEffectExecution:
        claims = decision.claims
        if claims.issuer_id != self.expected_issuer_id:
            raise EffectBindingError("authorization issuer mismatch")
        if claims.audience != self.expected_audience:
            raise EffectBindingError("authorization audience mismatch")
        if claims.tenant_id != record.tenant_id:
            raise EffectBindingError("authorization tenant binding mismatch")
        if claims.record_binding_hash != authorization_record_binding(record):
            raise EffectBindingError("authorization record binding mismatch")

        authoritative = self.authoritative_versions.get(record.tenant_id)
        if claims.revocation_epoch != authoritative.revocation_epoch:
            raise PermissionError("authorization revocation epoch mismatch")
        if claims.policy_version != authoritative.policy_version:
            raise PermissionError("authorization policy version mismatch")
        now = int(self._decision_clock().timestamp())
        if claims.issued_at > now or claims.expires_at <= now:
            raise PermissionError("authorization decision outside validity window")
        if claims.reason is not ExecutionAuthorizationReason.ALLOWED:
            raise PermissionError("authorization decision denied")

        # INTENTIONALLY VULNERABLE: the signature is never verified and the
        # signing key epoch is never compared with the authoritative trust epoch.
        return super().execute(record)
