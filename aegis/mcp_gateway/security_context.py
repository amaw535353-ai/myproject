from contextvars import ContextVar, Token

from aegis.identity.models import Principal


_BOUND_PRINCIPAL: ContextVar[Principal | None] = ContextVar(
    "aegis_bound_principal", default=None
)


def bind_principal(principal: Principal) -> Token[Principal | None]:
    return _BOUND_PRINCIPAL.set(principal)


def reset_principal(token: Token[Principal | None]) -> None:
    _BOUND_PRINCIPAL.reset(token)


def require_bound_principal() -> Principal:
    principal = _BOUND_PRINCIPAL.get()
    if principal is None:
        raise RuntimeError("trusted principal is not bound")
    return principal
