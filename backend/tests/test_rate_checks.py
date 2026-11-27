import asyncio
from types import SimpleNamespace

import pytest

from app.scanner.rate_checks import RATE_CHECKS
from app.schemas.findings import FindingStatus, Outcome, Severity

ENDPOINTS = [
    {"method": "GET", "path": "/products"},
    {"method": "GET", "path": "/login"},
    {"method": "POST", "path": "/orders"},
    {"method": "GET", "path": "/orders/{id}"},
]
SLEPT = []


@pytest.fixture(autouse=True)
def fake_sleep(monkeypatch):
    SLEPT.clear()

    async def no_sleep(seconds):
        SLEPT.append(seconds)
    monkeypatch.setattr("app.scanner.rate_checks._sleep", no_sleep)


class R:
    def __init__(self, status, text="", headers=None):
        self.status_code, self.text, self.headers = status, text, headers or {}


class FakeScan:
    def __init__(self, handler, cancelled=False):
        self.handler = handler
        self.target = {"url": "http://127.0.0.1:5000", "endpoints": ENDPOINTS}
        self.accounts = {}
        self.ctx = SimpleNamespace(cancelled=cancelled)
        self.findings, self.calls = [], []

    async def request(self, method, url, account=None, variant="valid",
                      headers=None, json_body=None, content=None):
        self.calls.append((method, url))
        return self.handler(method, url)

    def add_finding(self, f):
        f.id = "API-%03d" % (len(self.findings) + 1)
        self.findings.append(f)


def run_all(scan):
    async def go():
        reports = []
        for check in RATE_CHECKS:
            rep = await check.run(scan)
            for f in rep.findings:
                scan.add_finding(f)
            reports.append(rep)
        return reports
    return asyncio.run(go())


def limited(limit_after=5, status=429, recovers=True):
    counts = {}

    def handler(method, url):
        n = counts[url] = counts.get(url, 0) + 1
        if n > limit_after and not (recovers and SLEPT):
            return R(status, "Too many requests", {"Retry-After": "2"})
        return R(200, "ok")
    return handler


def test_no_limit_is_found_without_flooding():
    scan = FakeScan(lambda m, u: R(200, "ok"))
    reps = run_all(scan)
    assert reps[0].outcome == Outcome.FINDING
    assert len(scan.findings) == 2
    sev = {f.endpoint: f.severity for f in scan.findings}
    assert sev["GET /login"] == Severity.MEDIUM      # login-like is tested first
    assert sev["GET /products"] == Severity.LOW
    assert all(r.outcome == Outcome.SKIPPED for r in reps[1:])
    assert all(m == "GET" for m, _ in scan.calls)
    assert len(scan.calls) <= 44


def test_limit_found_and_requests_stop_at_429():
    scan = FakeScan(limited(5))
    reps = run_all(scan)
    assert [r.outcome for r in reps] == [Outcome.PASSED] * 4
    assert not scan.findings
    assert "after 6 requests" in reps[1].message
    assert len(scan.calls) == 14   # 6 + 6 probe requests + 1 recovery each


def test_limit_with_403_instead_of_429():
    scan = FakeScan(limited(5, status=403))
    reps = run_all(scan)
    assert reps[0].outcome == Outcome.PASSED
    assert reps[2].outcome == Outcome.FINDING
    assert all(f.severity == Severity.LOW for f in scan.findings)
    assert reps[3].outcome == Outcome.SKIPPED


def test_still_blocked_after_waiting_is_manual_review():
    scan = FakeScan(limited(5, recovers=False))
    reps = run_all(scan)
    assert reps[3].outcome == Outcome.FINDING
    assert all(f.status == FindingStatus.MANUAL for f in scan.findings)
    assert len(SLEPT) == 4         # 2 endpoints x 2 waits
    assert len(scan.calls) == 16


def test_limit_headers_count_as_a_limit():
    scan = FakeScan(lambda m, u: R(200, "ok", {"X-RateLimit-Limit": "100"}))
    reps = run_all(scan)
    assert reps[0].outcome == Outcome.PASSED
    assert "declares a limit of 100" in reps[1].message
    assert not scan.findings


def test_missing_endpoint_is_tested_once_and_skipped():
    scan = FakeScan(lambda m, u: R(404))
    reps = run_all(scan)
    assert all(r.outcome == Outcome.SKIPPED for r in reps)
    assert len(scan.calls) == 2


def test_cancelled_scan_sends_nothing():
    scan = FakeScan(lambda m, u: R(200), cancelled=True)
    reps = run_all(scan)
    assert not scan.calls
    assert all(r.outcome == Outcome.SKIPPED for r in reps)