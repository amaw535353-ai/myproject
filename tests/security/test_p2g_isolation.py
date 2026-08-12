import inspect

from aegis.agent import bounded_loop


def test_hardened_loop_runner_has_no_vulnerable_import() -> None:
    source = inspect.getsource(bounded_loop)
    assert "aegis.vulnerable" not in source
    assert "VulnerableLoopAgentRunner" not in source
