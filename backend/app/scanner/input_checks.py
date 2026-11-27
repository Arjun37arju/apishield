"""Check family C: Input and injection (Step 17).

Five checks, safe GET requests only. Every request goes through
scan.request(), so the safety gate approves it before it is sent.
Run them in this order: C5 reviews what C1 to C4 saw.
"""
import re
from urllib.parse import quote, urlsplit

from app.schemas.findings import (
    Confidence,
    Finding,
    FindingStatus,
    Outcome,
    Severity,
    make_evidence,
)
from app.services.scan_manager import BaseCheck, CheckReport

MAX_ENDPOINTS = 3  # keeps the scan inside the request budget
BASELINE_VALUE = "1"
ID_PARAM = re.compile(r"\{[^}/]+\}")
PUBLIC_HINTS = ("/login", "/register", "/health", "/docs", "/openapi",
                "/static", "/favicon", "/token")

DB_ERROR = re.compile(
    r"(you have an error in your sql syntax|sqlite_error|sqlite3\.\w*error|"
    r"sqlstate\[|psycopg2|pg::\w*error|unterminated quoted string|"
    r"unclosed quotation mark|\bORA-\d{5}\b|mysql_fetch|"
    r"syntax error at or near|System\.Data\.SqlClient|sequelize\w*error|"
    r"sql syntax)", re.IGNORECASE)
TRACE = re.compile(
    r"(Traceback \(most recent call last\)|\bat [\w$.]+\([\w$.]+\.java:\d+\)|"
    r"node_modules[\\/]|System\.\w+Exception|Stack trace:|Werkzeug Debugger|"
    r"File \"[^\"]+\", line \d+)", re.IGNORECASE)


def _signature(text):
    if DB_ERROR.search(text or ""):
        return "database error"
    if TRACE.search(text or ""):
        return "stack trace"
    return ""


def _text(resp):
    try:
        return resp.text or ""
    except Exception:
        return ""


def _origin(scan):
    p = urlsplit(scan.target["url"])
    return p.scheme + "://" + p.netloc


def _acct(scan):
    return "user_a" if "user_a" in scan.accounts else None


def _seen(scan):
    return scan.__dict__.setdefault("_input_seen", [])


def _reported(scan):
    return scan.__dict__.setdefault("_input_reported", set())


def _targets(scan):
    """GET endpoints to test: [(path template, query parameter name)]."""
    raw = scan.target.get("endpoints") or []
    out = []
    for ep in raw:
        if isinstance(ep, str):
            method, path, params = "GET", ep, []
        else:
            method = str(ep.get("method", "GET")).upper()
            path = str(ep.get("path", ""))
            params = ep.get("params") or []
        if method != "GET" or not path.startswith("/"):
            continue
        if any(h in path.lower() for h in PUBLIC_HINTS):
            continue
        param = params[0] if params and isinstance(params[0], str) else "id"
        if (path, param) not in out:
            out.append((path, param))
    if not raw:
        out.append((urlsplit(scan.target["url"]).path or "/", "id"))
    out.sort(key=lambda t: "{" not in t[0])  # path parameters first
    return out[:MAX_ENDPOINTS]


def _url_value(scan, tpl, param, value):
    """Put the test value in the path parameter, or in a query parameter."""
    if ID_PARAM.search(tpl):
        first = [True]

        def sub(_m):
            if first[0]:
                first[0] = False
                return quote(value, safe="")
            return BASELINE_VALUE
        return _origin(scan) + ID_PARAM.sub(sub, tpl)
    return _origin(scan) + tpl + "?" + param + "=" + quote(value, safe="")


def _url_query(scan, tpl, query):
    path = ID_PARAM.sub(BASELINE_VALUE, tpl)
    return _origin(scan) + path + "?" + query


async def _baseline(scan, tpl, param, acct):
    cache = scan.__dict__.setdefault("_input_baseline", {})
    if tpl not in cache:
        url = _url_value(scan, tpl, param, BASELINE_VALUE)
        cache[tpl] = await scan.request("GET", url, account=acct)
    return cache[tpl]


def _finding(title, tpl, url, resp, severity, confidence, status, impact, fix):
    return Finding(
        title=title,
        category="Input and injection",
        endpoint="GET " + tpl,
        severity=severity,
        confidence=confidence,
        status=status,
        impact=impact,
        fix=fix,
        evidence=make_evidence("GET", url, {}, resp.status_code, _text(resp)),
    )


class _InputCheck(BaseCheck):
    category = "Input and injection"
    values = ()          # [(label, value)]
    raw_query = False    # True: values are whole query strings
    title = ""
    impact = ""
    fix = ""
    sig_severity = Severity.MEDIUM

    async def run(self, scan):
        targets = _targets(scan)
        if not targets:
            return CheckReport(Outcome.SKIPPED, "no GET endpoints to test")
        acct = _acct(scan)
        findings, tested = [], 0
        for tpl, param in targets:
            base = await _baseline(scan, tpl, param, acct)
            if base.status_code in (401, 403, 404):
                continue
            tested += 1
            base_sig = _signature(_text(base))
            hit, weak = False, None
            for label, value in self.values:
                if self.raw_query:
                    url = _url_query(scan, tpl, value)
                else:
                    url = _url_value(scan, tpl, param, value)
                resp = await scan.request("GET", url, account=acct)
                _seen(scan).append((tpl, url, resp))
                sig = _signature(_text(resp))
                if sig and sig != base_sig:
                    findings.append(_finding(
                        self.title + " (" + sig + ", input: " + label + ")",
                        tpl, url, resp, self.sig_severity, Confidence.MEDIUM,
                        FindingStatus.SUSPECTED, self.impact, self.fix))
                    _reported(scan).add(tpl)
                    hit = True
                    break
                if resp.status_code >= 500 and base.status_code < 500 and weak is None:
                    weak = (url, resp, label)
            if not hit and weak:
                url, resp, label = weak
                findings.append(_finding(
                    "Server error on unusual input (" + label + ")",
                    tpl, url, resp, Severity.LOW, Confidence.LOW,
                    FindingStatus.MANUAL,
                    "The server failed instead of refusing the input. An odd "
                    "response alone is not proof of a weakness: review it by hand.",
                    self.fix))
        if findings:
            return CheckReport(Outcome.FINDING,
                               str(len(findings)) + " endpoint(s) need attention",
                               findings)
        if tested:
            return CheckReport(Outcome.PASSED,
                               str(tested) + " endpoint(s) handled the input safely")
        return CheckReport(
            Outcome.SKIPPED,
            "no endpoint answered the normal request (it may need a login: "
            "give the scan a user_a account)")


class SqlInjectionCheck(_InputCheck):
    id = "input_sqli"
    name = "Input 1: SQL-injection indicators"
    values = [("single quote", "'"), ("double quote", '"'),
              ("always-true test", "1' OR '1'='1")]
    title = "Database error after SQL-injection test input"
    sig_severity = Severity.HIGH
    impact = ("The input reached the database and broke the query. This is a "
              "strong sign of SQL injection but it is not proof: confirm by hand.")
    fix = ("Use parameterized queries (placeholders), never build SQL from "
           "text, and return a short generic error message.")


class WrongTypeCheck(_InputCheck):
    id = "input_wrong_types"
    name = "Input 2: wrong data types"
    values = [("text instead of a number", "abc"), ("decimal", "1.5"),
              ("null", "null")]
    title = "Wrong data type reveals an internal error"
    impact = ("The API does not validate input types, and the error shows "
              "internal details.")
    fix = ("Validate every parameter type and range, and answer 400 or 422 "
           "with a short message.")


class BoundaryCheck(_InputCheck):
    id = "input_boundary"
    name = "Input 3: boundary values"
    values = [("empty", ""), ("negative number", "-1"),
              ("huge number", "99999999999999999999"),
              ("very long text", "A" * 500)]
    title = "Boundary value reveals an internal error"
    impact = ("Extreme values cause an internal error, which can leak details "
              "or disturb the service.")
    fix = ("Set minimum and maximum values and lengths, and reject anything "
           "outside them with 400.")


class OddParamCheck(_InputCheck):
    id = "input_odd_params"
    name = "Input 4: odd parameters"
    raw_query = True
    values = [("repeated parameter", "id=1&id=2"),
              ("unknown and array parameters", "apishield_x[]=1&debug=true")]
    title = "Odd parameters reveal an internal error"
    impact = ("Unexpected parameters cause an internal error, which can leak "
              "details.")
    fix = ("Accept only the parameters the endpoint defines, and ignore or "
           "reject the rest.")


class VerboseErrorCheck(BaseCheck):
    id = "input_verbose_errors"
    name = "Input 5: error replies reveal internals"
    category = "Input and injection"

    async def run(self, scan):
        acct = _acct(scan)
        if not _seen(scan):  # C1 to C4 did not run: send one probe per endpoint
            for tpl, param in _targets(scan):
                base = await _baseline(scan, tpl, param, acct)
                if base.status_code in (401, 403, 404):
                    continue
                url = _url_value(scan, tpl, param, "'")
                resp = await scan.request("GET", url, account=acct)
                _seen(scan).append((tpl, url, resp))
        seen = _seen(scan)
        if not seen:
            return CheckReport(Outcome.SKIPPED, "no error replies to review")
        findings, done = [], set()
        base_cache = scan.__dict__.get("_input_baseline", {})
        for tpl, url, resp in seen:
            sig = _signature(_text(resp))
            base = base_cache.get(tpl)
            base_sig = _signature(_text(base)) if base is not None else ""
            if not sig or sig == base_sig or tpl in _reported(scan) or tpl in done:
                continue
            done.add(tpl)
            findings.append(_finding(
                "Error reply shows a " + sig, tpl, url, resp,
                Severity.MEDIUM, Confidence.MEDIUM, FindingStatus.SUSPECTED,
                "Error replies reveal internal details that help an attacker.",
                "Turn off debug mode and return a short generic error "
                "message. Log the details on the server only."))
        if findings:
            return CheckReport(Outcome.FINDING,
                               str(len(findings)) + " endpoint(s) show internal details",
                               findings)
        return CheckReport(
            Outcome.PASSED,
            str(len(seen)) + " reply(ies) reviewed: no new internal details")


INPUT_CHECKS = [SqlInjectionCheck(), WrongTypeCheck(), BoundaryCheck(),
                OddParamCheck(), VerboseErrorCheck()]
INPUT_CHECK_IDS = [c.id for c in INPUT_CHECKS]