import inspect

import apps.api.main as hardened_module
import apps.vulnerable_api.main as vulnerable_module


def test_hardened_app_does_not_mount_vulnerable_routes() -> None:
    hardened_paths = set(hardened_module.app.openapi()["paths"])
    vulnerable_paths = set(
        vulnerable_module.create_intentionally_vulnerable_lab_app().openapi()["paths"]
    )

    assert "/v1/knowledge/search-unfiltered" not in hardened_paths
    assert "/v1/knowledge/search-client-tenant" not in hardened_paths
    assert "/v1/knowledge/search-unfiltered" in vulnerable_paths
    assert "/v1/knowledge/search-client-tenant" in vulnerable_paths


def test_vulnerable_app_requires_explicit_factory_launch() -> None:
    assert not hasattr(vulnerable_module, "app")


def test_hardened_main_has_no_vulnerable_import_or_feature_flag() -> None:
    source = inspect.getsource(hardened_module)
    assert "aegis.vulnerable" not in source
    assert "apps.vulnerable_api" not in source
    assert "ENABLE_VULNERABLE" not in source
