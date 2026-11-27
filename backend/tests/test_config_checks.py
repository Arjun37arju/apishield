import asyncio

import pytest

from app.scanner.config_checks import CONFIG_CHECKS
from app.schemas.findings import (
    Confidence, Finding, FindingStatus, Outcome, Severity,
)

ENDPOINTS = [
    {"method": "GET", "path": "/products"},
    {"method": "GET", "path": "/orders/{id}"},
    {"method": "GET", "path": "/users"},
    {"method": "POST", "path": "/orders"},
]
GOOD = {"X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'",
        "X-Frame-Options": "DENY"}
LAB_FN = "app.scanner.config_checks._lab_http_allowed"


@pytest.fixture(autouse=True)
def lab_on(monkeypatch):
    monkeypatch.setattr(LAB_FN, lambda url: True)


class R:
    def __init__(self, status, text="", headers=None):
        self.status_code, self.text, self.headers = status, text, headers or {}


class FakeScan:
    def __init__(self, handler, url="http://127.0.0.1:5000", findings=None):
        self.handler = handler
        self.target = {"url": url, "endpoints": ENDPOINTS}
        self.accounts = {}
        self.findings = list(findings or [])
        self.calls = []

    async def request(self, method, url, account=None, variant="valid",
                      headers=None, json_body=None, content=None):
        self.calls.append((method, url, headers))
        return self.handler(method, url, headers or {})

    def add_finding(self, f):
        f.id = "API-%03d" % (len(self.findings) + 1)
        self.findings.append(f)


def run_all(scan):
    async def go():
        reports = []
        for check in CONFIG_CHECKS:
            rep = await check.run(scan)
            for f in rep.findings:
                scan.add_finding(f)
            reports.append(rep)
        return reports
    return asyncio.run(go())


def clean(method, url, headers):
    if "apishield-not-found" in url:
        return R(404, '{"error": "not found"}', dict(GOOD))
    return R(200, '{"ok": true}', dict(GOOD))


def test_clean_api_passes_and_lab_http_is_manual():
    scan = FakeScan(clean)
    reps = run_all(scan)
    assert [r.outcome for r in reps] == [
        Outcome.MANUAL, Outcome.PASSED, Outcome.PASSED, Outcome.PASSED, Outcome.PASSED]
    assert not scan.findings


def test_plain_http_outside_lab_is_a_finding(monkeypatch):
    monkeypatch.setattr(LAB_FN, lambda url: False)
    scan = FakeScan(clean)
    reps = run_all(scan)
    assert reps[0].outcome == Outcome.FINDING
    assert scan.findings[0].severity == Severity.HIGH


def test_https_target_passes_https_check():
    scan = FakeScan(clean, url="https://api.example.com")
    reps = run_all(scan)
    assert reps[0].outcome == Outcome.PASSED
    assert reps[1].outcome == Outcome.FINDING   # no HSTS in the replies


def test_missing_headers_is_a_low_finding():
    scan = FakeScan(lambda m, u, h: R(200, '{"ok": true}', {}))
    reps = run_all(scan)
    assert reps[1].outcome == Outcome.FINDING
    f = [x for x in scan.findings if x.title.startswith("Security headers")][0]
    assert f.severity == Severity.LOW
    assert "Content-Security-Policy" in f.title


def test_header_present_on_some_endpoint_is_not_reported():
    def handler(method, url, headers):
        base = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"}
        if url.endswith("/products"):
            base["Content-Security-Policy"] = "default-src 'none'"
        return R(200, "ok", base)
    scan = FakeScan(handler)
    assert run_all(scan)[1].outcome == Outcome.PASSED


def test_cors_wildcard_is_found_once():
    def handler(method, url, headers):
        h = dict(GOOD)
        if "Origin" in headers:
            h["Access-Control-Allow-Origin"] = "*"
        return R(200, "ok", h)
    scan = FakeScan(handler)
    reps = run_all(scan)
    assert reps[2].outcome == Outcome.FINDING
    cors = [f for f in scan.findings if "CORS" in f.title]
    assert len(cors) == 1
    assert cors[0].severity == Severity.MEDIUM
    assert any(c[2] and "Origin" in c[2] for c in scan.calls)


def test_cors_reflected_origin_with_credentials_is_high():
    def handler(method, url, headers):
        h = dict(GOOD)
        if "Origin" in headers:
            h["Access-Control-Allow-Origin"] = headers["Origin"]
            h["Access-Control-Allow-Credentials"] = "true"
        return R(200, "ok", h)
    scan = FakeScan(handler)
    run_all(scan)
    cors = [f for f in scan.findings if "CORS" in f.title][0]
    assert cors.severity == Severity.HIGH
    assert cors.confidence == Confidence.HIGH


def test_sensitive_data_found_and_masked():
    def handler(method, url, headers):
        if url.endswith("/users"):
            return R(200, '{"users":[{"name":"a","password_hash":"5f4dcc3b5aa765d61d8327deb882cf99"}]}', dict(GOOD))
        return clean(method, url, headers)
    scan = FakeScan(handler)
    reps = run_all(scan)
    assert reps[3].outcome == Outcome.FINDING
    f = [x for x in scan.findings if x.title.startswith("Reply exposes")][0]
    assert f.severity == Severity.HIGH
    assert "5f4dcc3b" not in str(f.evidence)


def test_card_number_is_low_confidence_manual_review():
    def handler(method, url, headers):
        if url.endswith("/products"):
            return R(200, '{"card": "4111 1111 1111 1111"}', dict(GOOD))
        return clean(method, url, headers)
    scan = FakeScan(handler)
    run_all(scan)
    f = [x for x in scan.findings if x.title.startswith("Reply exposes")][0]
    assert f.confidence == Confidence.LOW
    assert f.status == FindingStatus.MANUAL
    assert "4111 1111" not in str(f.evidence)


def test_error_page_with_stack_trace_is_found():
    def handler(method, url, headers):
        if "apishield-not-found" in url:
            return R(404, 'Traceback (most recent call last):\n  File "app.py", line 3', dict(GOOD))
        return clean(method, url, headers)
    scan = FakeScan(handler)
    reps = run_all(scan)
    assert reps[4].outcome == Outcome.FINDING
    assert any(f.title.startswith("Error reply reveals") for f in scan.findings)


def test_server_version_header_is_found():
    def handler(method, url, headers):
        r = clean(method, url, headers)
        r.headers["Server"] = "Werkzeug/3.0.1 Python/3.12.1"
        return r
    scan = FakeScan(handler)
    run_all(scan)
    assert any("version disclosed" in f.title for f in scan.findings)


def test_error_details_already_reported_by_input_checks_are_not_repeated():
    earlier = Finding(title="Error reply shows a stack trace", category="Input and injection",
                      endpoint="GET /products", severity=Severity.MEDIUM,
                      confidence=Confidence.MEDIUM, impact="x", fix="y")

    def handler(method, url, headers):
        if "apishield-not-found" in url:
            return R(404, 'Traceback (most recent call last):\n  File "app.py", line 3', dict(GOOD))
        return clean(method, url, headers)
    scan = FakeScan(handler, findings=[earlier])
    reps = run_all(scan)
    assert reps[4].outcome == Outcome.PASSED
    assert "already reported" in reps[4].message


def test_only_get_requests_and_small_budget():
    scan = FakeScan(clean)
    run_all(scan)
    assert all(c[0] == "GET" for c in scan.calls)
    assert len(scan.calls) <= 12