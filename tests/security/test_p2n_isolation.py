import inspect

import aegis.effects.versioned_revalidation as hardened_module


def test_p2n_hardened_runtime_does_not_import_vulnerable_baseline() -> None:
    source = inspect.getsource(hardened_module)
    assert "aegis.vulnerable" not in source
    assert "p2n_stale_cache" not in source
