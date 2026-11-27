"""Check family D: Rate limiting (Step 18).

Four checks, safe GET requests only, one at a time. Every request goes
through scan.request(), so the safety gate approves it before it is sent.
The endpoints are probed once per scan and the four checks share the result.
"""
import asyncio
from urllib.parse import urlsplit

from app.core.safety_gate import RequestBlocked
from app.schemas.findings import (
    Confidence,
    Finding,
    FindingStatus,
    Outcome,
    Severity,
    make_evidence,
)
from app.services.scan_manager import BaseCheck, CheckReport

BURST = 20          # most requests sent to one endpoint
MAX_ENDPOINTS = 2   # keeps the scan far inside the 100-request budget
MAX_WAIT = 10       # longest pause before the recovery test, in seconds
DEFAULT_WAIT = 5
SKIP_HINTS = ("/docs", "/openapi", "/static", "/favicon", "/health")
LOGIN_HINTS = ("login", "token", "auth", "signin", "register", "reset", "password")
LIMIT_HEADERS = ("x-ratelimit-limit", "ratelimit-limit", "x-rate-limit-limit",
                 "x-ratelimit-remaining", "ratelimit-remaining")
NO_ENDPOINTS = "no endpoint could be tested (needs a GET endpoint without an {id})"


async def _sleep(seconds):
    await asyncio.sleep(seconds)


def _headers(resp):
    try:
        return {str(k).lower(): str(v) for k, v in (resp.headers or {}).items()}
    except Exception:
        return {}


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


def _cancelled(scan):
    return bool(getattr(getattr(scan, "ctx", None), "cancelled", False))


def _is_login_like(path):
    return any(h in path.lower() for h in LOGIN_HINTS)


def _targets(scan):
    """GET paths to test (no {id} templates). Login-like paths first."""
    raw = scan.target.get("endpoints") or []
    found = []
    for ep in raw:
        if isinstance(ep, str):
            method, path = "GET", ep
        else:
            method = str(ep.get("method", "GET")).upper()
            path = str(ep.get("path", ""))
        if method != "GET" or not path.startswith("/") or "{" in path:
            continue
        if any(h in path.lower() for h in SKIP_HINTS):
            continue
        if path not in found:
            found.append(path)
    if not raw:
        found.append(urlsplit(scan.target["url"]).path or "/")
    found.sort(key=lambda p: not _is_login_like(p))
    return found[:MAX_ENDPOINTS]


async def _probe_endpoint(scan, path, acct):
    url = _origin(scan) + path
    info = {"path": path, "url": url, "sent": 0, "first": None, "last": None,
            "limited_at": None, "retry_after": None, "other_at": None,
            "header_limit": None, "has_headers": False, "missing": False,
            "stopped": ""}
    for i in range(1, BURST + 1):
        if _cancelled(scan):
            info["stopped"] = "scan cancelled"
            break
        try:
            resp = await scan.request("GET", url, account=acct)
        except RequestBlocked as e:
            if info["sent"] == 0:
                raise
            info["stopped"] = "safety gate: " + str(e)
            break
        info["sent"] = i
        info["last"] = resp
        code = resp.status_code
        hdr = _headers(resp)
        if info["first"] is None:
            info["first"] = code
        if i == 1 and code == 404:
            info["missing"] = True
            break
        for name in LIMIT_HEADERS:
            if name in hdr:
                info["has_headers"] = True
                if name.endswith("limit") and info["header_limit"] is None:
                    info["header_limit"] = hdr[name]
        if code == 429:
            info["limited_at"] = i
            info["retry_after"] = hdr.get("retry-after")
            break  # stop as soon as the server says "too many requests"
        first = info["first"]
        if code in (403, 503) and i > 1 and first is not None and 200 <= first < 300:
            info["other_at"] = i
            break
    return info


async def _get_probe(scan):
    probes = scan.__dict__.get("_rate_probe")
    if probes is None:
        acct = _acct(scan)
        probes = []
        for path in _targets(scan):
            info = await _probe_endpoint(scan, path, acct)
            if info["sent"] and not info["missing"]:
                probes.append(info)
        scan.__dict__["_rate_probe"] = probes
    return probes


def _reacted(p):
    return bool(p["limited_at"] or p["other_at"])


def _wait_seconds(retry_after):
    try:
        return max(1, min(MAX_WAIT, int(float(retry_after))))
    except (TypeError, ValueError):
        return DEFAULT_WAIT


def _finding(title, path, url, resp, severity, confidence, status, impact, fix):
    return Finding(
        title=title,
        category="Rate limiting",
        endpoint="GET " + path,
        severity=severity,
        confidence=confidence,
        status=status,
        impact=impact,
        fix=fix,
        evidence=make_evidence("GET", url, {}, resp.status_code, _text(resp)),
    )


class _RateCheck(BaseCheck):
    category = "Rate limiting"


class RateLimitPresentCheck(_RateCheck):
    id = "rate_present"
    name = "Rate 1: endpoint has a request limit"

    async def run(self, scan):
        probes = await _get_probe(scan)
        if not probes:
            return CheckReport(Outcome.SKIPPED, NO_ENDPOINTS)
        findings = []
        for p in probes:
            if _reacted(p) or p["has_headers"]:
                continue
            findings.append(_finding(
                "No request limit seen on " + p["path"] + " (after "
                + str(p["sent"]) + " requests)",
                p["path"], p["url"], p["last"],
                Severity.MEDIUM if _is_login_like(p["path"]) else Severity.LOW,
                Confidence.LOW, FindingStatus.SUSPECTED,
                str(p["sent"]) + " requests in a row were all accepted: no 429 "
                "and no rate-limit headers. Without a limit, attackers can "
                "guess passwords or overload the service. A limit above this "
                "safe test size may exist: confirm by hand.",
                "Add a rate limit per user and per IP address (for example a "
                "few login tries per minute) and answer 429 Too Many Requests "
                "with a Retry-After header."))
        if findings:
            return CheckReport(
                Outcome.FINDING,
                str(len(findings)) + " of " + str(len(probes))
                + " endpoint(s) showed no limit", findings)
        return CheckReport(Outcome.PASSED,
                           "all " + str(len(probes)) + " endpoint(s) show a limit")


class RateThresholdCheck(_RateCheck):
    id = "rate_threshold"
    name = "Rate 2: when the limit reacts"

    async def run(self, scan):
        probes = await _get_probe(scan)
        msgs = []
        for p in probes:
            if p["limited_at"]:
                msgs.append(p["path"] + ": 429 after " + str(p["limited_at"]) + " requests")
            elif p["other_at"]:
                msgs.append(p["path"] + ": status " + str(p["last"].status_code)
                            + " after " + str(p["other_at"]) + " requests")
            elif p["header_limit"]:
                msgs.append(p["path"] + ": declares a limit of " + p["header_limit"])
        if msgs:
            return CheckReport(Outcome.PASSED, "; ".join(msgs))
        return CheckReport(
            Outcome.SKIPPED,
            "no limit reacted within " + str(BURST) + " safe requests, so there "
            "is no threshold to measure")


class Http429Check(_RateCheck):
    id = "rate_http_429"
    name = "Rate 3: limit answers with HTTP 429"

    async def run(self, scan):
        probes = await _get_probe(scan)
        reacted = [p for p in probes if _reacted(p)]
        if not reacted:
            return CheckReport(Outcome.SKIPPED,
                               "no limit reacted, so there is no answer to check")
        findings, notes = [], []
        for p in reacted:
            if p["limited_at"]:
                notes.append(p["path"] + ": 429, Retry-After "
                             + ("present" if p["retry_after"] else "missing"))
                continue
            findings.append(_finding(
                "Limit answers with status " + str(p["last"].status_code)
                + " instead of 429",
                p["path"], p["url"], p["last"], Severity.LOW, Confidence.LOW,
                FindingStatus.SUSPECTED,
                "The server stops answering after many requests but does not "
                "use the standard 429 status, so clients and tools cannot "
                "tell a limit from a real error.",
                "Answer 429 Too Many Requests and add a Retry-After header."))
        if findings:
            return CheckReport(Outcome.FINDING,
                               "limit used a non-standard status", findings)
        return CheckReport(Outcome.PASSED, "; ".join(notes))


class RecoveryCheck(_RateCheck):
    id = "rate_recovery"
    name = "Rate 4: endpoint works again after the limit"

    async def run(self, scan):
        probes = await _get_probe(scan)
        limited = [p for p in probes if p["limited_at"]]
        if not limited:
            return CheckReport(Outcome.SKIPPED,
                               "no 429 was seen, so there is nothing to recover from")
        acct = _acct(scan)
        findings, msgs = [], []
        for p in limited:
            wait = _wait_seconds(p["retry_after"])
            resp, waited = None, 0
            for _ in range(2):  # at most 2 extra requests per endpoint
                if _cancelled(scan):
                    break
                await _sleep(wait)
                waited += wait
                resp = await scan.request("GET", p["url"], account=acct)
                if resp.status_code != 429:
                    break
            if resp is None:
                continue
            if resp.status_code != 429:
                msgs.append(p["path"] + ": works again after about "
                            + str(waited) + " s")
                continue
            findings.append(_finding(
                "Limit still active after " + str(waited) + " seconds",
                p["path"], p["url"], resp, Severity.LOW, Confidence.LOW,
                FindingStatus.MANUAL,
                "The endpoint was still blocked after waiting. This may be a "
                "long lockout (fine) or a limit that never resets (a problem "
                "for real users). Review by hand.",
                "Reset the limit after a short window and tell clients how "
                "long to wait with a Retry-After header."))
        if findings:
            return CheckReport(Outcome.FINDING,
                               "an endpoint stayed blocked", findings)
        if msgs:
            return CheckReport(Outcome.PASSED, "; ".join(msgs))
        return CheckReport(Outcome.SKIPPED, "scan cancelled before the recovery test")


RATE_CHECKS = [RateLimitPresentCheck(), RateThresholdCheck(),
               Http429Check(), RecoveryCheck()]
RATE_CHECK_IDS = [c.id for c in RATE_CHECKS]