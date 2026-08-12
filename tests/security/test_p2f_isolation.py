import inspect

from aegis.memory import service


def test_hardened_memory_service_has_no_vulnerable_import() -> None:
    source = inspect.getsource(service)
    assert "aegis.vulnerable" not in source
    assert "MEMORY_PRINCIPAL_PREFIX" not in source
