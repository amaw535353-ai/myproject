import inspect
from pathlib import Path

from aegis.downstream.auth import INVENTORY_SERVICE_TOKEN, token_fingerprint
from aegis.downstream.credential_broker import InventoryCredentialBroker
from aegis.downstream.inventory import SyntheticInventoryService
from aegis.helpdesk.stores import AssetStore
from aegis.identity.synthetic_auth import resolve_synthetic_principal


_ASSETS_PATH = Path(__file__).resolve().parents[2] / "synthetic_data" / "assets.json"


def test_broker_api_accepts_principal_not_caller_bearer() -> None:
    parameters = inspect.signature(InventoryCredentialBroker.get_my_assets).parameters

    assert set(parameters) == {"self", "principal"}
    assert "bearer" not in parameters
    assert "token" not in parameters
    assert "authorization" not in parameters


def test_broker_uses_inventory_service_credential() -> None:
    alice = resolve_synthetic_principal("alice@northstar-dynamics.test")
    assert alice is not None
    inventory = SyntheticInventoryService(AssetStore.from_json(_ASSETS_PATH))
    broker = InventoryCredentialBroker(inventory)

    assets = broker.get_my_assets(principal=alice)

    assert assets
    events = inventory.events()
    assert len(events) == 1
    assert events[0].credential_class == "inventory-service"
    assert events[0].token_fingerprint == token_fingerprint(INVENTORY_SERVICE_TOKEN)
    assert events[0].authorized is True
