from aegis.network.fetcher import SafeUrlFetcher
from aegis.network.policy import UrlPolicyError, UrlSecurityPolicy
from aegis.network.synthetic_http import (
    SyntheticHttpResponse,
    SyntheticHttpTransport,
    SyntheticResolver,
)
from aegis.vulnerable.ssrf import VulnerableUrlFetcher
from evals.p2e_ssrf_redirects import build_report


_ALLOWED_HOSTS = frozenset(
    {"docs.aegisdesk.test", "status.aegisdesk.test", "rebind.aegisdesk.test"}
)
_DNS = {
    "docs.aegisdesk.test": ("93.184.216.34",),
    "status.aegisdesk.test": ("1.1.1.1",),
    "rebind.aegisdesk.test": ("127.0.0.1",),
}


def test_vulnerable_fetcher_follows_allowlisted_redirect_to_link_local() -> None:
    resolver = SyntheticResolver(_DNS)
    transport = SyntheticHttpTransport(
        {
            "https://docs.aegisdesk.test/start": SyntheticHttpResponse(
                status_code=302,
                location="https://169.254.169.254/latest/meta-data",
            ),
            "https://169.254.169.254/latest/meta-data": SyntheticHttpResponse(
                status_code=200,
                body=b"synthetic metadata",
            ),
        }
    )
    fetcher = VulnerableUrlFetcher(
        allowed_hosts=_ALLOWED_HOSTS,
        resolver=resolver,
        transport=transport,
    )

    result = fetcher.fetch("https://docs.aegisdesk.test/start")

    assert result.status_code == 200
    assert [event.target_class for event in transport.events()] == ["public", "forbidden"]
    assert transport.events()[-1].connect_ip == "169.254.169.254"


def test_hardened_fetcher_blocks_link_local_redirect_before_connection() -> None:
    resolver = SyntheticResolver(_DNS)
    transport = SyntheticHttpTransport(
        {
            "https://docs.aegisdesk.test/start": SyntheticHttpResponse(
                status_code=302,
                location="https://169.254.169.254/latest/meta-data",
            )
        }
    )
    fetcher = SafeUrlFetcher(
        policy=UrlSecurityPolicy(allowed_hosts=_ALLOWED_HOSTS),
        resolver=resolver,
        transport=transport,
    )

    try:
        fetcher.fetch("https://docs.aegisdesk.test/start")
    except UrlPolicyError:
        pass
    else:
        raise AssertionError("link-local redirect was not blocked")

    assert len(transport.events()) == 1
    assert transport.events()[0].target_class == "public"


def test_hardened_fetcher_blocks_private_dns_answer_before_transport() -> None:
    resolver = SyntheticResolver(_DNS)
    transport = SyntheticHttpTransport(
        {
            "https://rebind.aegisdesk.test/admin": SyntheticHttpResponse(
                status_code=200,
                body=b"synthetic loopback admin",
            )
        }
    )
    fetcher = SafeUrlFetcher(
        policy=UrlSecurityPolicy(allowed_hosts=_ALLOWED_HOSTS),
        resolver=resolver,
        transport=transport,
    )

    try:
        fetcher.fetch("https://rebind.aegisdesk.test/admin")
    except UrlPolicyError:
        pass
    else:
        raise AssertionError("private DNS answer was not blocked")

    assert transport.events() == ()


def test_hardened_fetcher_allows_safe_cross_allowlist_redirect() -> None:
    resolver = SyntheticResolver(_DNS)
    transport = SyntheticHttpTransport(
        {
            "https://docs.aegisdesk.test/start": SyntheticHttpResponse(
                status_code=302,
                location="https://status.aegisdesk.test/health",
            ),
            "https://status.aegisdesk.test/health": SyntheticHttpResponse(
                status_code=200,
                body=b"ok",
            ),
        }
    )
    fetcher = SafeUrlFetcher(
        policy=UrlSecurityPolicy(allowed_hosts=_ALLOWED_HOSTS),
        resolver=resolver,
        transport=transport,
    )

    result = fetcher.fetch("https://docs.aegisdesk.test/start")

    assert result.final_url == "https://status.aegisdesk.test/health"
    assert result.status_code == 200
    assert all(event.target_class == "public" for event in transport.events())


def test_p2e_metrics_match_expected_security_delta() -> None:
    report = build_report()
    vulnerable = report["variants"]["vulnerable"]["metrics"]
    hardened = report["variants"]["hardened"]["metrics"]

    assert vulnerable["asr"] == {
        "successful_policy_violations": 2,
        "valid_adversarial_attempts": 2,
        "percent": 100.0,
    }
    assert hardened["asr"] == {
        "successful_policy_violations": 0,
        "valid_adversarial_attempts": 2,
        "percent": 0.0,
    }
    assert hardened["fpr"] == {
        "benign_requests_incorrectly_blocked": 0,
        "valid_benign_requests": 2,
        "percent": 0.0,
    }
    assert hardened["safe_task_rate"] == {
        "authorized_tasks_completed_safely": 2,
        "authorized_tasks_attempted": 2,
        "percent": 100.0,
    }
    assert report["network_io"] == "synthetic-in-memory-only-no-sockets"
