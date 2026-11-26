import asyncio
import base64

import httpx
import pytest
import respx

from app.core.masking import mask_headers, mask_secret
from app.core.safety_gate import RequestBlocked, ScanContext, send_request
from app.core.settings import settings
from app.services.auth_providers import ApiKeyProvider, AuthError, BasicAuthProvider

PUBLIC_IP = "93.184.216.34"
URL = "http://api.example.com/v1/users"
HTTPS = "https://api.example.com/v1/users"


@pytest.fixture(autouse=True)
def temp_audit(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.audit.AUDIT_LOG", tmp_path / "audit.log")


def make_ctx():
    return ScanContext(scope_host="api.example.com", scope_port=80,
                       scope_path="/v1", permission_confirmed=True)


def fixed_resolver(host, port):
    return [PUBLIC_IP]


def test_basic_valid_header():
    p = BasicAuthProvider("test-user", "test-pass-123")
    h = p.apply({}, HTTPS)
    expected = "Basic " + base64.b64encode(b"test-user:test-pass-123").decode()
    assert h["Authorization"] == expected


def test_basic_none_sends_no_credentials_even_over_http():
    p = BasicAuthProvider("test-user", "test-pass-123")
    assert "Authorization" not in p.apply({}, URL, "none")


def test_basic_wrong_credentials_differ_and_hide_password():
    p = BasicAuthProvider("test-user", "test-pass-123")
    wrong = p.apply({}, HTTPS, "wrong")["Authorization"]
    assert wrong != p.apply({}, HTTPS, "valid")["Authorization"]
    assert "test-pass-123" not in wrong


def test_basic_refused_over_http():
    p = BasicAuthProvider("test-user", "test-pass-123")
    with pytest.raises(AuthError):
        p.apply({}, URL)


def test_basic_http_allowed_only_for_lab_when_exception_on(monkeypatch):
    p = BasicAuthProvider("test-user", "test-pass-123")
    lab_url = "http://127.0.0.1:" + str(settings.lab_port) + "/api/basic/me"
    with pytest.raises(AuthError):
        p.apply({}, lab_url)
    monkeypatch.setattr(settings, "allow_lab_exception", True)
    assert "Authorization" in p.apply({}, lab_url)
    with pytest.raises(AuthError):
        p.apply({}, URL)


@pytest.mark.parametrize("user,pw", [
    ("", "x"), ("a:b", "x"), ("user", ""), ("user", "bad\r\npass"), (None, "x"),
])
def test_basic_bad_credentials_rejected(user, pw):
    with pytest.raises(AuthError):
        BasicAuthProvider(user, pw)


def test_api_key_header():
    p = ApiKeyProvider("test-key-123456")
    assert p.apply({}, URL)["X-API-Key"] == "test-key-123456"
    assert "X-API-Key" not in p.apply({}, URL, "none")
    assert p.apply({}, URL, "wrong")["X-API-Key"] == "invalid-key"


@pytest.mark.parametrize("name", ["bad name", "X-Key\r\nEvil: 1", "", "a" * 65])
def test_api_key_bad_header_name_rejected(name):
    with pytest.raises(AuthError):
        ApiKeyProvider("test-key-123456", header_name=name)


def test_api_key_newline_rejected():
    with pytest.raises(AuthError):
        ApiKeyProvider("abc\r\nX-Evil: 1")


def test_secrets_hidden_in_repr():
    b = BasicAuthProvider("test-user", "test-pass-123")
    k = ApiKeyProvider("test-key-123456")
    for p in (b, k):
        text = repr(p) + str(p)
        assert "test-pass-123" not in text
        assert "test-key-123456" not in text


def test_unknown_variant_rejected():
    with pytest.raises(AuthError):
        ApiKeyProvider("test-key-123456").apply({}, URL, "other")


def test_apply_does_not_change_input_headers():
    original = {"Accept": "application/json"}
    ApiKeyProvider("test-key-123456").apply(original, URL)
    assert original == {"Accept": "application/json"}


def test_mask_secret():
    assert mask_secret("short") == "****"
    assert mask_secret("abcdefghijkl") == "ab****"


def test_mask_headers():
    masked = mask_headers({
        "Authorization": "Bearer abcdefghijkl",
        "X-API-Key": "supersecretkey",
        "Accept": "application/json",
    })
    assert masked["Authorization"] == "Bearer ab****"
    assert "supersecretkey" not in str(masked)
    assert masked["Accept"] == "application/json"


def test_auth_applied_after_gate_approves():
    ctx = make_ctx()
    provider = ApiKeyProvider("test-key-123456")
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route(host=PUBLIC_IP).mock(return_value=httpx.Response(200))
        asyncio.run(send_request(ctx, "GET", URL, auth=provider,
                                 resolver=fixed_resolver))
        assert route.calls.last.request.headers["x-api-key"] == "test-key-123456"


class CountingProvider(ApiKeyProvider):
    calls = 0

    def apply(self, headers, url, variant="valid"):
        CountingProvider.calls += 1
        return super().apply(headers, url, variant)


def test_auth_not_applied_when_gate_blocks():
    CountingProvider.calls = 0
    ctx = make_ctx()
    provider = CountingProvider("test-key-123456")
    with pytest.raises(RequestBlocked):
        asyncio.run(send_request(ctx, "GET", "http://evil.com/v1", auth=provider,
                                 resolver=fixed_resolver))
    assert CountingProvider.calls == 0
