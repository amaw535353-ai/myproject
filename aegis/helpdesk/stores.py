import json
from pathlib import Path
from threading import Lock

from aegis.helpdesk.models import AssetRecord, AssetView, TicketRecord
from aegis.identity.models import Principal


class AssetStore:
    def __init__(self, assets: list[AssetRecord]) -> None:
        self._assets = tuple(assets)

    @classmethod
    def from_json(cls, path: Path) -> "AssetStore":
        raw_assets = json.loads(path.read_text(encoding="utf-8"))
        return cls([AssetRecord.model_validate(item) for item in raw_assets])

    def get_my_assets(self, principal: Principal) -> list[AssetView]:
        return [
            AssetView(
                asset_id=asset.asset_id,
                asset_type=asset.asset_type,
                label=asset.label,
            )
            for asset in self._assets
            if asset.tenant_id == principal.tenant_id
            and asset.assigned_user_id == principal.user_id
        ]


class TicketStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._records: dict[str, TicketRecord] = {}
        self._next_id = 1

    def create(self, *, principal: Principal, title: str, description: str) -> TicketRecord:
        with self._lock:
            ticket_id = f"TCK-{self._next_id:04d}"
            self._next_id += 1
            record = TicketRecord(
                ticket_id=ticket_id,
                tenant_id=principal.tenant_id,
                created_by_user_id=principal.user_id,
                title=title,
                description=description,
            )
            self._records[ticket_id] = record
            return record

    def get(self, ticket_id: str) -> TicketRecord | None:
        return self._records.get(ticket_id)
