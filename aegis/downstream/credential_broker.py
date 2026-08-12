from __future__ import annotations

from aegis.downstream.auth import INVENTORY_SERVICE_TOKEN
from aegis.downstream.inventory import SyntheticInventoryService
from aegis.helpdesk.models import AssetView
from aegis.identity.models import Principal


class InventoryCredentialBroker:
    """Server-owned downstream credential boundary for the synthetic lab.

    Callers provide only a trusted Principal. The broker owns the separately scoped
    inventory-service credential and never accepts a caller bearer as input.
    """

    def __init__(self, inventory_service: SyntheticInventoryService) -> None:
        self._inventory_service = inventory_service
        self._service_bearer = INVENTORY_SERVICE_TOKEN

    def get_my_assets(self, *, principal: Principal) -> list[AssetView]:
        return self._inventory_service.get_my_assets(
            authorization_bearer=self._service_bearer,
            principal=principal,
        )
