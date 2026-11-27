import asyncio

import pytest

from app.scanner.authorization import AUTHZ_CHECKS
from app.schemas.findings import Outcome

ENDPOINTS = [{"method": m, "path": "/orders/{id}"} for m in ("GET", "PUT", "PATCH", "DELETE")]
ENDPOINTS.append({"method": "GET", "path": "/admin/users"})
LAB_FN = "app.scanner.authorization._lab_http_allowed"


@pytest.fixture(autouse=True)
def lab_on(monkeypatch):
    monkeypatch.setattr(LAB_FN, lambda url: True)


class R:
    def __init__(self, status, text=""):
        self.status_code, self.text = status, text


class FakeScan:
    def __init__(self, handler, accounts=("user_a", "user_b")):
        self.handler = handler
        self.target = {"url": "http://127.0.0.1:5000", "endpoints": ENDPOINTS}
        self.accounts = {a: object() for a in accounts}
        self.findings, self.calls = [], []

    async def request(self, method, url, account=None, variant="valid",
                      headers=None, json_body=None, content=None):
        self.calls.append((method, url, account))
        return self.handler(method, url, account)

    def add_finding(self, f):
        f.id = "API-%03d" % (len(self.findings) + 1)
        self.findings.append(f)


def run_all(scan):
    async def go():
        out = []
        for check in AUTHZ_CHECKS:
            missing = [a for a in check.requires if a not in scan.accounts]
            if missing:
                out.append(Outcome.SKIPPED)
                continue
            rep = await check.run(scan)
            for f in rep.findings:
                scan.add_finding(f)
            out.append(rep.outcome)
        return out
    return asyncio.run(go())


def vulnerable(method, url, who):
    return R(204 if method == "DELETE" else 200, '{"id":2,"owner":"b"}')


def secure(method, url, who):
    return R(403) if who == "user_a" else R(200, '{"id":2,"owner":"b"}')


def test_vulnerable_is_found_and_merged():
    scan = FakeScan(vulnerable)
    run_all(scan)
    orders = [f for f in scan.findings if f.endpoint == "/orders/{id}"]
    assert len(orders) == 1
    assert set(orders[0].evidence["affected_methods"]) == {"GET", "PUT", "PATCH", "DELETE"}
    assert any(f.endpoint == "/admin/users" for f in scan.findings)


def test_secure_api_passes():
    scan = FakeScan(secure)
    outcomes = run_all(scan)
    assert not scan.findings
    assert outcomes[0] == Outcome.PASSED


def test_missing_user_b_skips():
    scan = FakeScan(vulnerable, accounts=("user_a",))
    assert all(o == Outcome.SKIPPED for o in run_all(scan))


def test_writes_refused_outside_lab(monkeypatch):
    monkeypatch.setattr(LAB_FN, lambda url: False)
    scan = FakeScan(vulnerable)
    run_all(scan)
    assert not [c for c in scan.calls if c[0] in ("PUT", "PATCH", "DELETE")]


def test_no_raw_token_in_evidence():
    def leaky(method, url, who):
        return R(200, '{"token":"abc123","owner":"b"}')
    scan = FakeScan(leaky)
    run_all(scan)
    assert "abc123" not in str([f.evidence for f in scan.findings])