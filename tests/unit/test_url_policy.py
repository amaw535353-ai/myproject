import pytest

from aegis.network.fetcher import SafeUrlFetcher
from aegis.network.policy import UrlPolicyError, UrlSecurityPolicy
from aegis.network.synthetic_http import (
    SyntheticHttpResponse,
    SyntheticHttpTransport,
    SyntheticResolver,
)


_ALLOWED = frozenset({"docs.aegisdesk.test", "status.aegisdesk.test"})


def _policy() -> UrlSecurityPolicy:
    return UrlSecurityPolicy(allowed_hosts=_ALLOWED, max_redirects=2, max_response_bytes=16)


def test_policy_accepts_exact_https_host_with_public_resolution() -> None:
    resolver = SyntheticResolver({"docs.aegisdesk.test": ("93.184.216.34",)})

    target = _policy().validate(
        "https://DOCS.aegisdesk.test/guide?mode=short#fragment",
        resolver=resolver,
    )

    assert target.hostname == "docs.aegisdesk.test"
    assert target.connect_ip == "93.184.216.34"
    assert target.normalized_url == "https://docs.aegisdesk.test/guide?mode=short"


@pytest.mark.parametrize(
    "url",
    [
        "http://docs.aegisdesk.test/guide",
        "https://user:pass@docs.aegisdesk.test/guide",
        "https://docs.aegisdesk.test:8443/guide",
        "https://not-docs.aegisdesk.test/guide",
    ],
)
def test_policy_rejects_unsafe_authority_variants(url: str) -> None:
    resolver = SyntheticResolver({"docs.aegisdesk.test": ("93.184.216.34",)})

    with pytest.raises(UrlPolicyError):
        _policy().validate(url, resolver=resolver)


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1"])
def test_policy_rejects_non_global_resolved_addresses(address: str) -> None:
    resolver = SyntheticResolver({"docs.aegisdesk.test": (address,)})

    with pytest.raises(UrlPolicyError):
        _policy().validate("https://docs.aegisdesk.test/guide", resolver=resolver)


def test_policy_rejects_mixed_public_and_private_dns_answers() -> None:
    resolver = SyntheticResolver(
        {"docs.aegisdesk.test": ("93.184.216.34", "127.0.0.1")}
    )

    with pytest.raises(UrlPolicyError):
        _policy().validate("https://docs.aegisdesk.test/guide", resolver=resolver)


def test_safe_fetcher_revalidates_redirect_target_before_connection() -> None:
    resolver = SyntheticResolver({"docs.aegisdesk.test": ("93.184.216.34",)})
    transport = SyntheticHttpTransport(
        {
            "https://docs.aegisdesk.test/start": SyntheticHttpResponse(
                status_code=302,
                location="https://169.254.169.254/latest/meta-data",
            )
        }
    )
    fetcher = SafeUrlFetcher(policy=_policy(), resolver=resolver, transport=transport)

    with pytest.raises(UrlPolicyError):
        fetcher.fetch("https://docs.aegisdesk.test/start")

    events = transport.events()
    assert len(events) == 1
    assert events[0].target_class == "public"


def test_safe_fetcher_enforces_redirect_and_body_budgets() -> None:
    resolver = SyntheticResolver(
        {
            "docs.aegisdesk.test": ("93.184.216.34",),
            "status.aegisdesk.test": ("1.1.1.1",),
        }
    )
    redirect_transport = SyntheticHttpTransport(
        {
            "https://docs.aegisdesk.test/a": SyntheticHttpResponse(
                status_code=302,
                location="https://status.aegisdesk.test/b",
            ),
            "https://status.aegisdesk.test/b": SyntheticHttpResponse(
                status_code=302,
                location="https://docs.aegisdesk.test/a",
            ),
        }
    )
    fetcher = SafeUrlFetcher(
        policy=UrlSecurityPolicy(
            allowed_hosts=_ALLOWED,
            max_redirects=1,
            max_response_bytes=16,
        ),
        resolver=resolver,
        transport=redirect_transport,
    )
    with pytest.raises(UrlPolicyError):
        fetcher.fetch("https://docs.aegisdesk.test/a")

    body_transport = SyntheticHttpTransport(
        {
            "https://docs.aegisdesk.test/large": SyntheticHttpResponse(
                status_code=200,
                body=b"x" * 17,
            )
        }
    )
    body_fetcher = SafeUrlFetcher(policy=_policy(), resolver=resolver, transport=body_transport)
    with pytest.raises(UrlPolicyError):
        body_fetcher.fetch("https://docs.aegisdesk.test/large")
