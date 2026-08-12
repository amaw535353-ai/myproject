from __future__ import annotations

from dataclasses import dataclass
from threading import Lock

from aegis.downstream.auth import (
    INVENTORY_AUDIENCE,
    resolve_synthetic_token,
    token_fingerprint,
)
from aegis.helpdesk.models import AssetView
from aegis.helpdesk.stores import AssetStore
from aegis.identity.models import Principal


class InventoryAuthorizationError(RuntimeError):
    """Raised when the synthetic downstream rejects its presented credential."""


@dataclass(frozen=True)
class InventoryAuditEvent:
    endpoint: str
    token_fingerprint: str
    credential_class: str
    token_audience: str
    token_subject: str
    authorized: bool


class SyntheticInventoryService:
    """Local protected resource used to exercise downstream credential boundaries.

    The service never stores a raw bearer token in its audit events. It records only
    a short fingerprint and non-secret claim classifications needed for regression
    evidence.
    """

    def __init__(self, asset_store: AssetStore) -> None:
        self._asset_store = asset_store
        self._events: list[InventoryAuditEvent] = []
        self._lock = Lock()

    def get_my_assets(
        self,
        *,
        authorization_bearer: str,
        principal: Principal,
    ) -> list[AssetView]:
        claims = resolve_synthetic_token(authorization_bearer)
        authorized = bool(
            claims is not None
            and claims.audience == INVENTORY_AUDIENCE
            and ({"assets:read", "inventory:admin"} & claims.scopes)
        )

        with self._lock:
            self._events.append(
                InventoryAuditEvent(
                    endpoint="get_my_assets",
                    token_fingerprint=token_fingerprint(authorization_bearer),
                    credential_class=(
                        claims.credential_class if claims is not None else "unknown"
                    ),
                    token_audience=claims.audience if claims is not None else "unknown",
                    token_subject=claims.subject if claims is not None else "unknown",
                    authorized=authorized,
                )
            )

        if not authorized:
            raise InventoryAuthorizationError("downstream credential rejected")

        # The service credential authorizes AegisDesk to call the resource server;
        # the trusted Principal still determines whose tenant/user assets are queried.
        return self._asset_store.get_my_assets(principal)

    def events(self) -> tuple[InventoryAuditEvent, ...]:
        with self._lock:
            return tuple(self._events)
