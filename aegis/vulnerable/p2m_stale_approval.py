from __future__ import annotations

from pathlib import Path

from aegis.effects.durable import SyntheticIdempotentEffectService
from aegis.effects.revalidation import SyntheticAuthorizationStateStore


class VulnerableApprovalOnlyEffectService(SyntheticIdempotentEffectService):
    """Intentionally vulnerable P2-M baseline.

    Current authorization state may record revocation or policy drift, but this
    service ignores it and treats a historical approved outbox record as sufficient.
    It performs only the same local synthetic ledger effect used by the hardened lab.
    """

    def __init__(
        self,
        database_path: Path,
        *,
        authorization_store: SyntheticAuthorizationStateStore,
    ) -> None:
        database_path = Path(database_path)
        if authorization_store.database_path != database_path:
            raise ValueError("authorization state and effect ledger must share one SQLite database")
        self.authorization_store = authorization_store
        super().__init__(database_path)
