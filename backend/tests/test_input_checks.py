import asyncio

from app.scanner.input_checks import INPUT_CHECKS, VerboseErrorCheck
from app.schemas.findings import FindingStatus, Outcome, Severity

ENDPOINTS = [
    {"method": "GET", "path": "/orders/{id}"},
    {"method": "GET", "path": "/products"},
    {"method": "POST", "path": "/orders"},
]


class R:
    def __init__(self, status, text=""):
        self.status_code, self.text = status, text


class FakeScan:
    def __init__(self, handler):
        self.handler = handler
        self.target = {"url": "http://127.0.0.1:5000", "endpoints": ENDPOINTS}
        self.accounts = {}
        self.findings, self.calls = [], []

    async def request(self, method, url, account=None, variant="valid",
                      headers=None, json_body=None, content=None):
        self.calls.append((method, url))
        return self.handler(method, url)

    def add_finding(self, f):
        f.id = "API-%03d" % (len(self.findings) + 1)
        self.findings.append(f)


def run_all(scan, checks=INPUT_CHECKS):
    async def go():
        out = []
        for check in checks:
            rep = await check.run(scan)
            for f in rep.findings:
                scan.add_finding(f)
            out.append(rep.outcome)
        return out
    return asyncio.run(go())


def db_error_on_quote(method, url):
    if "%27" in url or "%22" in url:
        return R(500, "You have an error in your SQL syntax near ''")
    return R(200, '{"ok": true}')


def test_db_error_is_found_once_per_endpoint():
    scan = FakeScan(db_error_on_quote)
    outcomes = run_all(scan)
    assert outcomes[0] == Outcome.FINDING
    assert len(scan.findings) == 2          # C5 adds no duplicate
    assert all(f.severity == Severity.HIGH for f in scan.findings)
    assert outcomes[4] == Outcome.PASSED


def test_safe_api_passes_everything():
    def safe(method, url):
        if "%27" in url or "%22" in url or "abc" in url:
            return R(400, '{"error": "invalid input"}')
        return R(200, '{"ok": true}')
    scan = FakeScan(safe)
    outcomes = run_all(scan)
    assert not scan.findings
    assert outcomes == [Outcome.PASSED] * 5


def test_plain_500_is_marked_manual_review():
    def plain500(method, url):
        return R(500, "Internal Server Error") if "%27" in url else R(200, "ok")
    scan = FakeScan(plain500)
    run_all(scan)
    assert scan.findings
    assert all(f.status == FindingStatus.MANUAL for f in scan.findings)
    assert all(f.severity == Severity.LOW for f in scan.findings)


def test_error_already_in_baseline_is_not_flagged():
    scan = FakeScan(lambda m, u: R(200, "sqlite3.OperationalError in a normal reply"))
    run_all(scan)
    assert not scan.findings


def test_endpoint_needing_login_is_skipped_without_payloads():
    scan = FakeScan(lambda m, u: R(401))
    outcomes = run_all(scan)
    assert outcomes[:4] == [Outcome.SKIPPED] * 4
    assert len(scan.calls) == 2             # only the two baselines


def test_only_get_requests_and_budget():
    scan = FakeScan(db_error_on_quote)
    run_all(scan)
    assert all(m == "GET" for m, _ in scan.calls)
    assert len(scan.calls) <= 45


def test_stack_trace_found_when_run_alone():
    def trace(method, url):
        if "%27" in url:
            return R(500, 'Traceback (most recent call last):\n  File "app.py", line 3')
        return R(200, "ok")
    scan = FakeScan(trace)
    outcomes = run_all(scan, [VerboseErrorCheck()])
    assert outcomes == [Outcome.FINDING]