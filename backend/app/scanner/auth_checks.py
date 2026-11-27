"""Check family A: Authentication (Step 15).

Five checks, safe GET requests only. Every request goes through
scan.request(), so the safety gate approves it before it is sent.

  1 auth_no_token         endpoint answers with no login at all
  2 auth_invalid_token    a made-up token is accepted
  3 auth_expired_token    an expired token is accepted (needs a test account
                          called "expired_token", otherwise it is Skipped)
  4 auth_malformed_token  a broken token is accepted, or crashes the server
  5 auth_consistency      login is enforced on some endpoints but not others

Endpoints come from scan.target["endpoints"] (a list of {"method", "path"}
dicts or plain path strings). If that key is missing, only the target URL
itself is tested.
"""
from urllib.parse import urlsplit

from app.schemas.findings import (
    Confidence,
    Finding,
    FindingStatus,
    Outcome,
    Severity,
    make_evidence,
)
from app.services.scan_manager import BaseCheck, CheckReport

# Paths that are normally public on purpose. They are not tested.
PUBLIC_HINTS = ("/login", "/register", "/health", "/docs", "/openapi",
                "/static", "/favicon", "/token")
MAX_ENDPOINTS = 15  # keeps the scan inside the request budget

# Fake tokens. They are not secrets.
INVALID_TOKEN = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                 "eyJzdWIiOiIxIn0.invalidsignature")
MALFORMED_TOKEN = "!!!.@@@.###"

NO_PROTECTED = ("no protected endpoints found: none answered 401 or 403 "
                "when sent with no login")


def is_open(code):
    return 200 <= code < 300


def is_rejected(code):
    return code in (401, 403)


def _path(url):
    return urlsplit(url).path or "/"


def _body(resp):
    try:
        return resp.content
    except Exception:
        return b""


def endpoint_urls(scan):
    """The list of GET endpoint URLs to test (safe, no templates, no public paths)."""
    target_url = scan.target["url"]
    raw = scan.target.get("endpoints")
    if not raw:
        return [target_url]
    parts = urlsplit(target_url)
    base = parts.scheme + "://" + parts.netloc
    urls = []
    for ep in raw:
        if isinstance(ep, str):
            method, path = "GET", ep
        else:
            method = str(ep.get("method", "GET")).upper()
            path = str(ep.get("path", ""))
        if method != "GET" or not path.startswith("/") or "{" in path:
            continue
        if any(hint in path.lower() for hint in PUBLIC_HINTS):
            continue
        url = base + path
        if url not in urls:
            urls.append(url)
    return urls[:MAX_ENDPOINTS]


def _finding(title, url, sent_headers, resp, severity, confidence, status,
             impact, fix):
    return Finding(
        title=title,
        category="Authentication",
        endpoint="GET " + _path(url),
        severity=severity,
        confidence=confidence,
        status=status,
        impact=impact,
        fix=fix,
        evidence=make_evidence("GET", url, sent_headers, resp.status_code,
                               _body(resp)),
    )


class _AuthCheck(BaseCheck):
    category = "Authentication"

    async def baseline(self, scan, url):
        """The answer to a request with no login. Sent once per URL per scan."""
        cache = scan.__dict__.setdefault("_auth_baseline", {})
        if url not in cache:
            cache[url] = await scan.request("GET", url)
        return cache[url]

    async def protected_urls(self, scan):
        """URLs that really ask for a login (they answered 401 or 403)."""
        urls = []
        for url in endpoint_urls(scan):
            resp = await self.baseline(scan, url)
            if is_rejected(resp.status_code):
                urls.append(url)
        return urls


class NoTokenCheck(_AuthCheck):
    id = "auth_no_token"
    name = "Auth 1: endpoint opens with no login"

    async def run(self, scan):
        urls = endpoint_urls(scan)
        if not urls:
            return CheckReport(Outcome.SKIPPED, "no endpoints to test")
        findings = []
        for url in urls:
            resp = await self.baseline(scan, url)
            if is_open(resp.status_code):
                findings.append(_finding(
                    "Endpoint works with no login", url, {}, resp,
                    Severity.HIGH, Confidence.MEDIUM, FindingStatus.SUSPECTED,
                    "Anyone can call this endpoint without logging in. If it "
                    "is public on purpose this is fine; otherwise its data or "
                    "function is exposed.",
                    "Require a valid login (token or API key) on this endpoint "
                    "and answer 401 when it is missing."))
        if findings:
            return CheckReport(
                Outcome.FINDING,
                str(len(findings)) + " of " + str(len(urls))
                + " endpoints answered with no login",
                findings)
        return CheckReport(
            Outcome.PASSED,
            "none of the " + str(len(urls)) + " endpoints opened without a login")


class InvalidTokenCheck(_AuthCheck):
    id = "auth_invalid_token"
    name = "Auth 2: made-up token accepted"

    async def run(self, scan):
        urls = await self.protected_urls(scan)
        if not urls:
            return CheckReport(Outcome.SKIPPED, NO_PROTECTED)
        headers = {"Authorization": "Bearer " + INVALID_TOKEN}
        findings = []
        for url in urls:
            resp = await scan.request("GET", url, headers=headers)
            if is_open(resp.status_code):
                findings.append(_finding(
                    "Made-up token is accepted", url, headers, resp,
                    Severity.CRITICAL, Confidence.HIGH, FindingStatus.CONFIRMED,
                    "The endpoint refuses requests with no login but lets in a "
                    "request carrying a token that was invented. Login can be "
                    "bypassed.",
                    "Verify the token signature and claims on every request and "
                    "answer 401 for any token that does not check out."))
        if findings:
            return CheckReport(Outcome.FINDING, "a made-up token was accepted",
                               findings)
        return CheckReport(Outcome.PASSED,
                           str(len(urls)) + " protected endpoints refused it")


class ExpiredTokenCheck(_AuthCheck):
    id = "auth_expired_token"
    name = "Auth 3: expired token accepted"
    # Without this test account the scan manager marks the check Skipped.
    requires = ("expired_token",)

    async def run(self, scan):
        urls = await self.protected_urls(scan)
        if not urls:
            return CheckReport(Outcome.SKIPPED, NO_PROTECTED)
        findings = []
        for url in urls:
            resp = await scan.request("GET", url, account="expired_token")
            if is_open(resp.status_code):
                findings.append(_finding(
                    "Expired token is accepted", url, {}, resp,
                    Severity.HIGH, Confidence.HIGH, FindingStatus.CONFIRMED,
                    "A token that should have run out still works, so a stolen "
                    "token stays useful for too long.",
                    "Check the expiry time on every request and answer 401 "
                    "once the token has expired."))
        if findings:
            return CheckReport(Outcome.FINDING, "an expired token was accepted",
                               findings)
        return CheckReport(Outcome.PASSED,
                           str(len(urls)) + " protected endpoints refused it")


class MalformedTokenCheck(_AuthCheck):
    id = "auth_malformed_token"
    name = "Auth 4: broken token accepted or crashes the server"

    async def run(self, scan):
        urls = await self.protected_urls(scan)
        if not urls:
            return CheckReport(Outcome.SKIPPED, NO_PROTECTED)
        headers = {"Authorization": "Bearer " + MALFORMED_TOKEN}
        findings = []
        for url in urls:
            resp = await scan.request("GET", url, headers=headers)
            if is_open(resp.status_code):
                findings.append(_finding(
                    "Broken token is accepted", url, headers, resp,
                    Severity.HIGH, Confidence.HIGH, FindingStatus.CONFIRMED,
                    "A token with a broken format gets through, so the login "
                    "check can be bypassed.",
                    "Reject any token that cannot be parsed and verified, "
                    "with a 401 answer."))
            elif resp.status_code >= 500:
                findings.append(_finding(
                    "Broken token causes a server error", url, headers, resp,
                    Severity.MEDIUM, Confidence.MEDIUM, FindingStatus.SUSPECTED,
                    "A broken token makes the server fail instead of refusing "
                    "it. This can leak internal details and may be a way to "
                    "disturb the service.",
                    "Catch token parsing errors and answer 401 with a short "
                    "message."))
        if findings:
            return CheckReport(Outcome.FINDING,
                               "a broken token was accepted or caused an error",
                               findings)
        return CheckReport(Outcome.PASSED,
                           str(len(urls)) + " protected endpoints refused it")


class ConsistencyCheck(_AuthCheck):
    id = "auth_consistency"
    name = "Auth 5: login enforced the same on every endpoint"

    async def run(self, scan):
        urls = endpoint_urls(scan)
        if len(urls) < 2:
            return CheckReport(Outcome.SKIPPED,
                               "needs at least 2 endpoints to compare")
        open_urls, rejected_urls = [], []
        first_open = None
        for url in urls:
            resp = await self.baseline(scan, url)
            if is_open(resp.status_code):
                open_urls.append(url)
                if first_open is None:
                    first_open = (url, resp)
            elif is_rejected(resp.status_code):
                rejected_urls.append(url)
        if open_urls and rejected_urls:
            shown = ", ".join(_path(u) for u in open_urls[:5])
            finding = _finding(
                "Login is enforced on some endpoints but not others",
                first_open[0], {}, first_open[1],
                Severity.MEDIUM, Confidence.MEDIUM, FindingStatus.MANUAL,
                "Open without login: " + shown + ". Refused without login: "
                + str(len(rejected_urls)) + " other endpoint(s). Check whether "
                "the open ones are public on purpose.",
                "Apply the same login rule to every endpoint, ideally in one "
                "shared place, and list the public endpoints on purpose.")
            return CheckReport(Outcome.FINDING,
                               "login rules differ between endpoints", [finding])
        return CheckReport(
            Outcome.PASSED,
            "login rule was the same on all " + str(len(urls)) + " endpoints")


AUTH_CHECKS = [NoTokenCheck(), InvalidTokenCheck(), ExpiredTokenCheck(),
               MalformedTokenCheck(), ConsistencyCheck()]
AUTH_CHECK_IDS = [c.id for c in AUTH_CHECKS]


def auth_registry():
    """{check_id: check} for the scan manager."""
    return {c.id: c for c in AUTH_CHECKS}
