import asyncio

import httpx
import pytest
import respx

from app.core.safety_gate import (
    RequestBlocked,
    ScanContext,
    evaluate,
    ip_block_reason,
    send_request,
)
from app.core.settings import settings

PUBLIC_IP = "93.184.216.34"
URL = "http://api.example.com/v1/users"


@pytest.fixture(autouse=True)
def temp_audit(tmp_path, monkeypatch):
    path = tmp_path / "audit.log"
    monkeypatch.setattr("app.core.audit.AUDIT_LOG", path)
    return path


def make_ctx(host="api.example.com", port=80, path="/v1", permission=True):
    return ScanContext(scope_host=host, scope_port=port, scope_path=path,
                       permission_confirmed=permission)


def resolver_for(ips):
    calls = []

    def resolver(host, port):
        calls.append(host)
        return ips

    resolver.calls = calls
    return resolver


@pytest.mark.parametrize("ip", [
    "10.0.0.5", "172.16.0.1", "172.31.255.255", "192.168.1.1",
    "127.0.0.1", "::1", "169.254.169.254", "0.0.0.0", "fe80::1",
    "::ffff:127.0.0.1", "100.64.0.1", "fd00:ec2::254",
])
def test_blocked_ip_ranges(ip):
    assert ip_block_reason(ip) is not None


@pytest.mark.parametrize("ip", [PUBLIC_IP, "8.8.8.8"])
def test_public_ips_allowed(ip):
    assert ip_block_reason(ip) is None


def test_good_request_goes_to_validated_ip(temp_audit):
    ctx = make_ctx()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route(host=PUBLIC_IP).mock(
            return_value=httpx.Response(200, text="hello"))
        r = asyncio.run(send_request(ctx, "GET", URL,
                                     resolver=resolver_for([PUBLIC_IP])))
        assert r.status_code == 200
        assert route.call_count == 1
        assert route.calls.last.request.headers["host"] == "api.example.com"
    assert ctx.requests_made == 1


def test_no_permission_blocked():
    ctx = make_ctx(permission=False)
    res = resolver_for([PUBLIC_IP])
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route(host=PUBLIC_IP).mock(return_value=httpx.Response(200))
        with pytest.raises(RequestBlocked):
            asyncio.run(send_request(ctx, "GET", URL, resolver=res))
        assert route.call_count == 0
    assert res.calls == []


@pytest.mark.parametrize("url", [
    "http://evil.com/v1/users",
    "http://api.example.com:80/other",
    "http://api.example.com/v1/../admin",
    "http://api.example.com/v1/%2e%2e/admin",
    "http://api.example.com/v10/users",
    "ftp://api.example.com/v1",
    "http://user:pw@api.example.com/v1",
    "http://api.example.com:6379/v1",
])
def test_out_of_scope_or_bad_url_blocked_without_dns(url):
    ctx = make_ctx()
    res = resolver_for([PUBLIC_IP])
    assert evaluate(ctx, "GET", url, res).allowed is False
    assert res.calls == []


def test_dns_to_private_ip_blocked():
    ctx = make_ctx()
    assert evaluate(ctx, "GET", URL, resolver_for(["10.0.0.5"])).allowed is False


def test_mixed_dns_answer_blocked():
    ctx = make_ctx()
    res = resolver_for([PUBLIC_IP, "169.254.169.254"])
    assert evaluate(ctx, "GET", URL, res).allowed is False


def test_unresolvable_host_blocked():
    ctx = make_ctx()

    def failing(host, port):
        raise OSError("no such host")

    assert evaluate(ctx, "GET", URL, failing).allowed is False


def test_bad_method_blocked():
    ctx = make_ctx()
    assert evaluate(ctx, "TRACE", URL, resolver_for([PUBLIC_IP])).allowed is False
    assert evaluate(ctx, "CONNECT", URL, resolver_for([PUBLIC_IP])).allowed is False


def test_budget_enforced():
    ctx = make_ctx()
    ctx.max_requests = 2
    res = resolver_for([PUBLIC_IP])
    assert evaluate(ctx, "GET", URL, res).allowed is True
    assert evaluate(ctx, "GET", URL, res).allowed is True
    assert evaluate(ctx, "GET", URL, res).allowed is False


def test_budget_cannot_exceed_global_limit(monkeypatch):
    monkeypatch.setattr(settings, "max_requests_per_scan", 1)
    ctx = make_ctx()
    ctx.max_requests = 1000
    res = resolver_for([PUBLIC_IP])
    assert evaluate(ctx, "GET", URL, res).allowed is True
    assert evaluate(ctx, "GET", URL, res).allowed is False


def test_cancelled_scan_blocked():
    ctx = make_ctx()
    ctx.cancelled = True
    res = resolver_for([PUBLIC_IP])
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route(host=PUBLIC_IP).mock(return_value=httpx.Response(200))
        with pytest.raises(RequestBlocked):
            asyncio.run(send_request(ctx, "GET", URL, resolver=res))
        assert route.call_count == 0


def test_redirects_not_followed_by_default():
    ctx = make_ctx()
    with respx.mock(assert_all_called=False) as mock:
        route = mock.route(host=PUBLIC_IP).mock(return_value=httpx.Response(
            302, headers={"location": "http://169.254.169.254/latest/meta-data/"}))
        meta = mock.route(host="169.254.169.254").mock(
            return_value=httpx.Response(200))
        r = asyncio.run(send_request(ctx, "GET", URL,
                                     resolver=resolver_for([PUBLIC_IP])))
        assert r.status_code == 302
        assert route.call_count == 1
        assert meta.call_count == 0


def test_redirect_to_other_host_blocked_when_following(monkeypatch):
    monkeypatch.setattr(settings, "follow_redirects", True)
    ctx = make_ctx()
    with respx.mock(assert_all_called=False) as mock:
        mock.route(host=PUBLIC_IP).mock(return_value=httpx.Response(
            302, headers={"location": "http://169.254.169.254/latest/meta-data/"}))
        meta = mock.route(host="169.254.169.254").mock(
            return_value=httpx.Response(200))
        with pytest.raises(RequestBlocked):
            asyncio.run(send_request(ctx, "GET", URL,
                                     resolver=resolver_for([PUBLIC_IP])))
        assert meta.call_count == 0


def test_response_is_capped(monkeypatch):
    monkeypatch.setattr(settings, "max_response_bytes", 100)
    ctx = make_ctx()
    with respx.mock(assert_all_called=False) as mock:
        mock.route(host=PUBLIC_IP).mock(
            return_value=httpx.Response(200, content=b"x" * 5000))
        r = asyncio.run(send_request(ctx, "GET", URL,
                                     resolver=resolver_for([PUBLIC_IP])))
        assert len(r.body) == 100
        assert r.truncated is True


def test_lab_exception_off_by_default():
    assert settings.allow_lab_exception is False
    ctx = make_ctx(host="127.0.0.1", port=settings.lab_port, path="/")
    url = "http://127.0.0.1:" + str(settings.lab_port) + "/api"
    assert evaluate(ctx, "GET", url, resolver_for(["127.0.0.1"])).allowed is False


def test_lab_exception_allows_only_loopback_on_lab_port(monkeypatch):
    monkeypatch.setattr(settings, "allow_lab_exception", True)
    port = settings.lab_port
    url = "http://127.0.0.1:" + str(port) + "/api"
    ctx = make_ctx(host="127.0.0.1", port=port, path="/")
    assert evaluate(ctx, "GET", url, resolver_for(["127.0.0.1"])).allowed is True
    # a private address is still blocked, even with the exception ON
    ctx2 = make_ctx(host="lab.local", port=port, path="/")
    url2 = "http://lab.local:" + str(port) + "/api"
    assert evaluate(ctx2, "GET", url2, resolver_for(["10.0.0.5"])).allowed is False
    # cloud metadata is still blocked
    assert evaluate(ctx2, "GET", url2, resolver_for(["169.254.169.254"])).allowed is False


def test_blocked_request_writes_audit_event(temp_audit):
    ctx = make_ctx()
    evaluate(ctx, "GET", "http://evil.com/v1", resolver_for([PUBLIC_IP]))
    assert "request_blocked" in temp_audit.read_text()
