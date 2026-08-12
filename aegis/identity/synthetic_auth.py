from aegis.identity.models import Principal, Role


_SYNTHETIC_PRINCIPALS: dict[str, Principal] = {
    "alice@northstar-dynamics.test": Principal(
        user_id="usr_dyn_alice",
        tenant_id="tenant_northstar_dynamics",
        roles=frozenset({Role.EMPLOYEE}),
    ),
    "bob@northstar-digital.test": Principal(
        user_id="usr_dig_bob",
        tenant_id="tenant_northstar_digital",
        roles=frozenset({Role.EMPLOYEE}),
    ),
}


def resolve_synthetic_principal(handle: str) -> Principal | None:
    """Resolve a synthetic login handle to server-owned identity state."""

    return _SYNTHETIC_PRINCIPALS.get(handle.casefold())
