import asyncio

import httpx
import pytest
import respx

from app.core.safety_gate import RequestBlocked, ScanContext
from app.core.settings import settings
from app.services.auth_providers import AuthError
from app.services.auth_token_providers import (
    BearerTokenProvider,
    OAuthClientCredentialsProvider,
)

PUBLIC_IP = "93.184.216.34"
HTTPS = "https://api.example.com/v1/orders"
HTTP = "http://api.example.com/v1/orders"
TOKEN_URL = "https://api.example.com/oauth/token"
JWT = "aaa.bbb.cccc"


@pytest.fixture(autouse=True)
def temp_audit(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.audit.AUDIT_LOG", tmp_path / "audit.log")


def make_ctx():
    return ScanContext(scope_host="api.example.com", scope_port=443,
                       scope_path="/", permission_confirmed=True)


def fixed_resolver(host, port):
    return [PUBLIC_IP]


def token_response(expires_in=300, **extra):
    body = {"access_token": "tok-abcdefghij", "token_type": "Bearer",
            "expires_in": expires_in, "scope": "read"}
    body.update(extra)
    return httpx.Response(200, json=body)


def make_oauth(**kw):
    return OAuthClientCredentialsProvider(TOKEN_URL, "test-client",
                                          "test-secret-123", scope="read", **kw)


# ---------- Bearer / JWT ----------

def test_bearer_valid_header():
    assert BearerTokenProvider(JWT).apply({}, HTTPS)["Authorization"] == "Bearer " + JWT


def test_bearer_none_has_no_header_even_over_http():
    assert "Authorization" not in BearerTokenProvider(JWT).apply({}, HTTP, "none")


def test_bearer_refused_over_http():
    with pytest.raises(AuthError):
        BearerTokenProvider(JWT).apply({}, HTTP)


def test_bearer_http_allowed_for_lab_only_when_exception_on(monkeypatch):
    p = BearerTokenProvider(JWT)
    lab_url = "http://127.0.0.1:" + str(settings.lab_port) + "/api/orders"
    with pytest.raises(AuthError):
        p.apply({}, lab_url)
    monkeypatch.setattr(settings, "allow_lab_exception", True)
    assert "Authorization" in p.apply({}, lab_url)
    with pytest.raises(AuthError):
        p.apply({}, HTTP)


def test_bearer_wrong_changes_only_the_signature():
    wrong = BearerTokenProvider(JWT).apply({}, HTTPS, "wrong")["Authorization"]
    assert wrong != "Bearer " + JWT
    assert wrong.startswith("Bearer aaa.bbb.ccc")


def test_bearer_wrong_for_plain_token():
    wrong = BearerTokenProvider("plain-token-value").apply({}, HTTPS, "wrong")
    assert wrong["Authorization"] == "Bearer invalid-token"


def test_bearer_malformed():
    h = BearerTokenProvider(JWT).apply({}, HTTPS, "malformed")
    assert h["Authorization"] == "Bearer !!malformed!!"


def test_bearer_expired_uses_supplied_token():
    p = BearerTokenProvider(JWT, expired_token="old.expired.token")
    assert p.apply({}, HTTPS, "expired")["Authorization"] == "Bearer old.expired.token"


def test_bearer_expired_without_token_raises():
    with pytest.raises(AuthError):
        BearerTokenProvider(JWT).apply({}, HTTPS, "expired")


@pytest.mark.parametrize("bad", ["", None, "a\r\nb"])
def test_bearer_bad_token_rejected(bad):
    with pytest.raises(AuthError):
        BearerTokenProvider(bad)


def test_bearer_secret_hidden_in_repr():
    p = BearerTokenProvider("super-secret-token-value")
    assert "super-secret-token-value" not in repr(p) + str(p)


def test_bearer_unknown_variant():
    with pytest.raises(AuthError):
        BearerTokenProvider(JWT).apply({}, HTTPS, "other")


# ---------- OAuth 2.0 client credentials ----------

def test_oauth_gets_token_through_gate_and_applies_it():
    ctx = make_ctx()
    p = make_oauth()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route(host=PUBLIC_IP, method="POST").mock(
            return_value=token_response())
        asyncio.run(p.prepare(ctx, resolver=fixed_resolver))
        body = route.calls.last.request.content
        assert b"grant_type=client_credentials" in body
        assert b"scope=read" in body
    assert p.granted_scope == "read"
    assert p.apply({}, HTTPS)["Authorization"] == "Bearer tok-abcdefghij"
    assert ctx.requests_made == 1


def test_oauth_token_is_reused_until_near_expiry():
    ctx = make_ctx()
    p = make_oauth()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route(host=PUBLIC_IP, method="POST").mock(
            return_value=token_response(expires_in=300))
        asyncio.run(p.prepare(ctx, resolver=fixed_resolver))
        asyncio.run(p.prepare(ctx, resolver=fixed_resolver))
        assert route.call_count == 1


def test_oauth_expired_token_is_renewed():
    ctx = make_ctx()
    p = make_oauth()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route(host=PUBLIC_IP, method="POST").mock(
            return_value=token_response(expires_in=5))
        asyncio.run(p.prepare(ctx, resolver=fixed_resolver))
        asyncio.run(p.prepare(ctx, resolver=fixed_resolver))
        assert route.call_count == 2


def test_oauth_token_endpoint_must_use_https():
    ctx = make_ctx()
    p = OAuthClientCredentialsProvider("http://api.example.com/oauth/token",
                                       "test-client", "test-secret-123")
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route(host=PUBLIC_IP).mock(return_value=token_response())
        with pytest.raises(AuthError):
            asyncio.run(p.prepare(ctx, resolver=fixed_resolver))
        assert route.call_count == 0


def test_oauth_token_endpoint_outside_scope_is_blocked():
    ctx = make_ctx()
    p = OAuthClientCredentialsProvider("https://auth.other.com/token",
                                       "test-client", "test-secret-123")
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route(host=PUBLIC_IP).mock(return_value=token_response())
        with pytest.raises(RequestBlocked):
            asyncio.run(p.prepare(ctx, resolver=fixed_resolver))
        assert route.call_count == 0


def test_oauth_failed_request_does_not_leak_secret():
    ctx = make_ctx()
    p = make_oauth()
    with respx.mock(assert_all_called=False) as mock:
        mock.route(host=PUBLIC_IP).mock(
            return_value=httpx.Response(401, json={"error": "invalid_client"}))
        with pytest.raises(AuthError) as e:
            asyncio.run(p.prepare(ctx, resolver=fixed_resolver))
    assert "test-secret-123" not in str(e.value)
    assert "401" in str(e.value)


@pytest.mark.parametrize("response", [
    httpx.Response(200, content=b"not json"),
    httpx.Response(200, json=["list"]),
    httpx.Response(200, json={"token_type": "Bearer"}),
    httpx.Response(200, json={"access_token": "tok-abcdefghij", "token_type": "mac"}),
    httpx.Response(200, json={"access_token": "bad\r\ntoken", "token_type": "Bearer"}),
])
def test_oauth_bad_token_responses_rejected(response):
    ctx = make_ctx()
    p = make_oauth()
    with respx.mock(assert_all_called=False) as mock:
        mock.route(host=PUBLIC_IP).mock(return_value=response)
        with pytest.raises(AuthError):
            asyncio.run(p.prepare(ctx, resolver=fixed_resolver))


def test_oauth_apply_before_prepare_raises():
    with pytest.raises(AuthError):
        make_oauth().apply({}, HTTPS)


def test_oauth_none_variant_needs_no_token():
    assert "Authorization" not in make_oauth().apply({}, HTTPS, "none")


def test_oauth_secrets_hidden_in_repr():
    p = make_oauth()
    text = repr(p) + str(p)
    assert "test-secret-123" not in text
    assert "test-client" not in text
