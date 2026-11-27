import asyncio
from types import SimpleNamespace

import httpx
import pytest
import respx

from app.core.url_validation import clean_target_url
from app.scanner.auth_checks import (
    AUTH_CHECK_IDS,
    INVALID_TOKEN,
    MAX_ENDPOINTS,
    auth_registry,
    endpoint_urls,
)
from app.schemas.findings import Outcome, ScanState, Severity
from app.services.auth_providers import ApiKeyProvider
from app.services.scan_manager import ScanManager

PUBLIC_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
def temp_audit(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.audit.AUDIT_LOG", tmp_path / "audit.log")


def fixed_resolver(host, port):
    return [PUBLIC_IP]


def make_target(paths):
    target = clean_target_url("http://api.example.com/api")
    target["endpoints"] = [{"method": "GET", "path": p} for p in paths]
    return target


def new_mock():
    return respx.mock(assert_all_called=False)


def serve(mock, path, handler):
    mock.route(host=PUBLIC_IP, path=path).mock(side_effect=handler)


def run_scan(mock, paths, accounts=None):
    async def scenario():
        mgr = ScanManager(auth_registry())
        scan = mgr.create(make_target(paths), True, AUTH_CHECK_IDS,
                          accounts=accounts, resolver=fixed_resolver)
        mgr.start(scan.id)
        await mgr.wait(scan.id)
        return scan

    with mock:
        return asyncio.run(scenario())


def outcomes(scan):
    return {r.check_id: r.outcome for r in scan.results}


def test_open_endpoint_is_found_and_protected_one_passes():
    mock = new_mock()
    serve(mock, "/api/internal/stats", lambda r: httpx.Response(200, json={"users": 3}))
    serve(mock, "/api/orders", lambda r: httpx.Response(401))
    scan = run_scan(mock, ["/api/internal/stats", "/api/orders"])

    assert scan.state == ScanState.COMPLETED
    o = outcomes(scan)
    assert o["auth_no_token"] == Outcome.FINDING
    assert o["auth_invalid_token"] == Outcome.PASSED
    assert o["auth_expired_token"] == Outcome.SKIPPED
    assert o["auth_malformed_token"] == Outcome.PASSED
    assert o["auth_consistency"] == Outcome.FINDING
    assert [f.id for f in scan.findings] == ["API-001", "API-002"]
    assert "/api/internal/stats" in scan.findings[0].endpoint
    assert scan.findings[0].severity == Severity.HIGH
    # 2 baseline + 1 invalid + 1 malformed (only /api/orders is protected)
    assert scan.ctx.requests_made == 4


def test_made_up_token_accepted_is_critical_and_token_is_masked():
    mock = new_mock()
    serve(mock, "/api/data",
          lambda r: httpx.Response(200 if "authorization" in r.headers else 401))
    scan = run_scan(mock, ["/api/data"])

    o = outcomes(scan)
    assert o["auth_no_token"] == Outcome.PASSED
    assert o["auth_invalid_token"] == Outcome.FINDING
    assert o["auth_malformed_token"] == Outcome.FINDING
    assert o["auth_consistency"] == Outcome.SKIPPED
    assert scan.findings[0].severity == Severity.CRITICAL
    assert INVALID_TOKEN not in str(scan.to_dict())


def test_malformed_token_server_error_is_a_medium_finding():
    def handler(request):
        auth = request.headers.get("authorization", "")
        if not auth:
            return httpx.Response(401)
        if "!!!" in auth:
            return httpx.Response(500)
        return httpx.Response(401)

    mock = new_mock()
    serve(mock, "/api/data", handler)
    scan = run_scan(mock, ["/api/data"])

    o = outcomes(scan)
    assert o["auth_invalid_token"] == Outcome.PASSED
    assert o["auth_malformed_token"] == Outcome.FINDING
    assert scan.findings[0].severity == Severity.MEDIUM


def test_expired_token_account_is_used_when_given():
    mock = new_mock()
    serve(mock, "/api/data",
          lambda r: httpx.Response(200 if "x-api-key" in r.headers else 401))
    scan = run_scan(mock, ["/api/data"],
                    accounts={"expired_token": ApiKeyProvider("test-key-123456")})

    o = outcomes(scan)
    assert o["auth_no_token"] == Outcome.PASSED
    assert o["auth_expired_token"] == Outcome.FINDING
    assert "test-key-123456" not in str(scan.to_dict())


def test_everything_protected_gives_a_clean_scan():
    mock = new_mock()
    serve(mock, "/api/a", lambda r: httpx.Response(401))
    serve(mock, "/api/b", lambda r: httpx.Response(403))
    scan = run_scan(mock, ["/api/a", "/api/b"])

    o = outcomes(scan)
    assert o["auth_no_token"] == Outcome.PASSED
    assert o["auth_invalid_token"] == Outcome.PASSED
    assert o["auth_expired_token"] == Outcome.SKIPPED
    assert o["auth_malformed_token"] == Outcome.PASSED
    assert o["auth_consistency"] == Outcome.PASSED
    assert scan.findings == []
    # 2 baseline + 2 invalid + 2 malformed: the baseline answers are reused
    assert scan.ctx.requests_made == 6


def test_endpoint_urls_skips_unsafe_and_public_paths():
    scan = SimpleNamespace(target={
        "url": "http://api.example.com:8080/v1",
        "endpoints": [
            {"method": "GET", "path": "/api/a"},
            {"method": "POST", "path": "/api/b"},
            "/api/c",
            {"method": "GET", "path": "/api/orders/{id}"},
            {"method": "GET", "path": "/health"},
            {"method": "GET", "path": "/api/a"},
        ],
    })
    assert endpoint_urls(scan) == [
        "http://api.example.com:8080/api/a",
        "http://api.example.com:8080/api/c",
    ]


def test_endpoint_urls_without_list_uses_target_url():
    scan = SimpleNamespace(target={"url": "http://api.example.com/v1/x"})
    assert endpoint_urls(scan) == ["http://api.example.com/v1/x"]


def test_endpoint_urls_is_capped():
    scan = SimpleNamespace(target={
        "url": "http://api.example.com",
        "endpoints": ["/api/e" + str(i) for i in range(40)],
    })
    assert len(endpoint_urls(scan)) == MAX_ENDPOINTS
