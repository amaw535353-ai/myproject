from pydantic import BaseModel, ConfigDict


class AssetRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    asset_id: str
    tenant_id: str
    assigned_user_id: str
    asset_type: str
    label: str


class AssetView(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    asset_id: str
    asset_type: str
    label: str


class TicketRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    ticket_id: str
    tenant_id: str
    created_by_user_id: str
    title: str
    description: str
    status: str = "created"
