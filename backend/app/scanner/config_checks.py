"""Check family E: Security configuration (Step 19).

Five checks, safe GET requests only. Every request goes through
scan.request(), so the safety gate approves it before it is sent.
The endpoints are probed once per scan and the five checks share the replies.
"""
import re
from urllib.parse import urlsplit

from app.scanner.input_checks import DB_ERROR, TRACE
from app.schemas.findings import (
    Confidence,
    Finding,
    FindingStatus,
    Outcome,
    Severity,
    make_evidence,
)
from app.services.auth_providers import _lab_http_allowed
from app.services.scan_manager import BaseCheck, CheckReport

MAX_ENDPOINTS = 4
BASELINE_VALUE = "1"
ID_PARAM = re.compile(r"\{[^}/]+\}")
SKIP_HINTS = ("/docs", "/openapi", "/static", "/favicon")
EVIL_ORIGIN = "https://apishield-test.example"
NOT_FOUND_PATH = "/apishield-not-found-test"
CATEGORY = "Security configuration"

SEV_RANK = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
            Severity.LOW: 1, Severity.INFO: 0}

SENSITIVE = [
    ("password or password hash", Severity.HIGH, re.compile(
        r'"(?:password_hash|hashed_password|password|passwd|pwd)"\s*:\s*"[^"]{3,}"',
        re.IGNORECASE)),
    ("secret, key or token field", Severity.HIGH, re.compile(
        r'"(?:api_?key|secret|client_secret|access_token|refresh_token|'
        r'private_key|auth_token)"\s*:\s*"[^"]{8,}"', re.IGNORECASE)),
    ("private key", Severity.HIGH, re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("AWS access key", Severity.HIGH, re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("national ID number (SSN format)", Severity.MEDIUM, re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b")),
]
CARD = re.compile(r"\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b")

INTERNAL = [
    ("stack trace", TRACE),
    ("database error", DB_ERROR),
    ("file path", re.compile(
        r"(?:[A-Za-z]:\\(?:[\w .-]+\\)+[\w .-]+\.\w+|"
        r"/(?:home|usr|opt|srv|var/www)/[\w./-]+\.\w+)")),
    ("debug page", re.compile(
        r"(Werkzeug Debugger|DEBUG\s*=\s*True|Whitelabel Error Page|"
        r"Django tried these URL patterns)", re.IGNORECASE)),
]


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


def _luhn(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _endpoints(scan):
    """[(path template, url)] for GET endpoints. {id} is filled with a plain 1."""
    raw = scan.target.get("endpoints") or []
    out = []
    for ep in raw:
        if isinstance(ep, str):
            method, path = "GET", ep
        else:
            method = str(ep.get("method", "GET")).upper()
            path = str(ep.get("path", ""))
        if method != "GET" or not path.startswith("/"):
            continue
        if any(h in path.lower() for h in SKIP_HINTS):
            continue
        url = _origin(scan) + ID_PARAM.sub(BASELINE_VALUE, path)
        if (path, url) not in out:
            out.append((path, url))
    if not raw:
        path = urlsplit(scan.target["url"]).path or "/"
        out.append((path, _origin(scan) + path))
    return out[:MAX_ENDPOINTS]


async def _get_probe(scan):
    probe = scan.__dict__.get("_cfg_probe")
    if probe is None:
        acct = _acct(scan)
        probe = []
        for tpl, url in _endpoints(scan):
            probe.append((tpl, url, await scan.request("GET", url, account=acct)))
        scan.__dict__["_cfg_probe"] = probe
    return probe


def _finding(title, tpl, url, resp, severity, confidence, status, impact, fix,
             sent=None, body=None):
    text = _text(resp) if body is None else body
    return Finding(
        title=title,
        category=CATEGORY,
        endpoint="GET " + tpl,
        severity=severity,
        confidence=confidence,
        status=status,
        impact=impact,
        fix=fix,
        evidence=make_evidence("GET", url, sent or {}, resp.status_code, text),
    )


class _ConfigCheck(BaseCheck):
    category = CATEGORY


# ---------- E1: HTTPS ----------

class HttpsCheck(_ConfigCheck):
    id = "config_https"
    name = "Config 1: HTTPS is used"

    async def run(self, scan):
        url = scan.target["url"]
        if urlsplit(url).scheme == "https":
            return CheckReport(Outcome.PASSED, "the target uses https")
        if _lab_http_allowed(url):
            return CheckReport(
                Outcome.MANUAL,
                "the lab uses plain http by design (lab exception). A real "
                "API must use https.")
        probe = await _get_probe(scan)
        tpl, purl, resp = probe[0]
        return CheckReport(Outcome.FINDING, "the target uses plain http", [_finding(
            "API is reachable over plain http", tpl, purl, resp,
            Severity.HIGH, Confidence.HIGH, FindingStatus.CONFIRMED,
            "Traffic, including logins and tokens, can be read or changed by "
            "anyone on the network path.",
            "Serve the API over https only, redirect http to https and send "
            "the Strict-Transport-Security header.")])


# ---------- E2: security headers ----------

class SecurityHeadersCheck(_ConfigCheck):
    id = "config_headers"
    name = "Config 2: security headers are present"

    async def run(self, scan):
        probe = await _get_probe(scan)
        if not probe:
            return CheckReport(Outcome.SKIPPED, "no endpoint to test")
        https = urlsplit(scan.target["url"]).scheme == "https"
        all_h = [_headers(r) for _, _, r in probe]

        def missing_everywhere(check):
            return all(not check(h) for h in all_h)

        missing = []
        if missing_everywhere(lambda h: "nosniff" in h.get("x-content-type-options", "").lower()):
            missing.append("X-Content-Type-Options: nosniff")
        if missing_everywhere(lambda h: "content-security-policy" in h):
            missing.append("Content-Security-Policy")
        if missing_everywhere(lambda h: "x-frame-options" in h
                              or "frame-ancestors" in h.get("content-security-policy", "").lower()):
            missing.append("X-Frame-Options (or CSP frame-ancestors)")
        if https and missing_everywhere(lambda h: "strict-transport-security" in h):
            missing.append("Strict-Transport-Security")
        if not missing:
            return CheckReport(Outcome.PASSED, "all expected headers were present")
        tpl, url, resp = probe[0]
        sure = Confidence.MEDIUM if len(probe) >= 2 else Confidence.LOW
        finding = _finding(
            "Security headers missing: " + ", ".join(missing), tpl, url, resp,
            Severity.LOW, sure, FindingStatus.SUSPECTED,
            "Missing headers make some browser attacks easier. A missing "
            "header alone is not proof of a weakness (some are not needed for "
            "a pure JSON API): review each one.",
            "Add the missing headers in one shared place for every response.")
        return CheckReport(Outcome.FINDING,
                           str(len(missing)) + " header(s) missing on all "
                           + str(len(probe)) + " endpoint(s) tested", [finding])


# ---------- E3: CORS ----------

class CorsCheck(_ConfigCheck):
    id = "config_cors"
    name = "Config 3: CORS is not too open"

    async def run(self, scan):
        probe = await _get_probe(scan)
        acct = _acct(scan)
        sent = {"Origin": EVIL_ORIGIN}
        hits, tested = [], 0
        for tpl, url, base in probe[:2]:
            if base.status_code == 404:
                continue
            tested += 1
            resp = await scan.request("GET", url, account=acct, headers=sent)
            h = _headers(resp)
            acao = h.get("access-control-allow-origin", "").strip()
            creds = h.get("access-control-allow-credentials", "").strip().lower() == "true"
            if acao == EVIL_ORIGIN:
                kind, rank = "reflects any origin", 3 if creds else 2
            elif acao.lower() == "null":
                kind, rank = "allows the null origin", 2
            elif acao == "*":
                kind, rank = "allows every origin (*)", 1
            else:
                continue
            hits.append((rank, kind, creds, tpl, url, resp))
        if not tested:
            return CheckReport(Outcome.SKIPPED, "no endpoint answered the normal request")
        if not hits:
            return CheckReport(Outcome.PASSED, str(tested)
                               + " endpoint(s) did not allow a foreign origin")
        rank, kind, creds, tpl, url, resp = max(hits, key=lambda x: x[0])
        if rank == 3:
            severity, conf, status = Severity.HIGH, Confidence.HIGH, FindingStatus.CONFIRMED
            impact = ("Any website can call this API with the visitor's login "
                      "and read the answer.")
        else:
            severity, conf, status = Severity.MEDIUM, Confidence.MEDIUM, FindingStatus.SUSPECTED
            impact = ("Websites from any origin can read answers from this "
                      "API. If the API is public on purpose this may be fine; "
                      "otherwise it exposes data.")
        impact += " Seen on " + str(len(hits)) + " of " + str(tested) + " endpoint(s)."
        finding = _finding(
            "CORS " + kind + (" and allows credentials" if creds else ""),
            tpl, url, resp, severity, conf, status, impact,
            "Allow only the exact origins of your own dashboard, never '*' "
            "or a copy of the request origin, and never combine with credentials.",
            sent=sent)
        return CheckReport(Outcome.FINDING, "CORS " + kind, [finding])


# ---------- E4: sensitive data in replies ----------

def _scrub(text):
    for _, _, rx in SENSITIVE:
        text = rx.sub("[REDACTED]", text)
    return CARD.sub("[REDACTED]", text)


def _sensitive_hits(text):
    hits = [(label, sev) for label, sev, rx in SENSITIVE if rx.search(text)]
    for m in CARD.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if _luhn(digits):
            hits.append(("payment card number", Severity.MEDIUM))
            break
    return hits


class SensitiveDataCheck(_ConfigCheck):
    id = "config_sensitive"
    name = "Config 4: sensitive data in replies"

    async def run(self, scan):
        probe = await _get_probe(scan)
        replies = [p for p in probe if 200 <= p[2].status_code < 300]
        if not replies:
            return CheckReport(Outcome.SKIPPED, "no endpoint answered with a 2xx reply")
        findings = []
        for tpl, url, resp in replies:
            text = _text(resp)
            hits = _sensitive_hits(text)
            if not hits:
                continue
            labels = sorted({label for label, _ in hits})
            worst = max((s for _, s in hits), key=lambda s: SEV_RANK[s])
            only_card = labels == ["payment card number"]
            findings.append(_finding(
                "Reply exposes sensitive data: " + ", ".join(labels), tpl, url, resp,
                worst, Confidence.LOW if only_card else Confidence.MEDIUM,
                FindingStatus.MANUAL if only_card else FindingStatus.SUSPECTED,
                "The reply contains data that should not leave the server. "
                "Values are masked in this report. Check by hand that it is "
                "real data and not an example.",
                "Return only the fields the client needs, never password "
                "hashes, keys or full card numbers.",
                body=_scrub(text)))
        if findings:
            return CheckReport(Outcome.FINDING, str(len(findings))
                               + " endpoint(s) expose sensitive data", findings)
        return CheckReport(Outcome.PASSED, str(len(replies))
                           + " reply(ies) reviewed: nothing sensitive found")


# ---------- E5: errors reveal internal details ----------

class ErrorDetailCheck(_ConfigCheck):
    id = "config_errors"
    name = "Config 5: errors reveal internal details"

    async def run(self, scan):
        probe = await _get_probe(scan)
        acct = _acct(scan)
        nf_url = _origin(scan) + NOT_FOUND_PATH
        nf = await scan.request("GET", nf_url, account=acct)
        everything = list(probe) + [(NOT_FOUND_PATH, nf_url, nf)]
        errors = [p for p in everything if p[2].status_code >= 400]
        findings, notes = [], []

        found = None
        for tpl, url, resp in errors:
            labels = [label for label, rx in INTERNAL if rx.search(_text(resp))]
            if labels:
                found = (tpl, url, resp, labels)
                break
        already = any(getattr(f, "category", "") == "Input and injection"
                      for f in getattr(scan, "findings", []))
        if found and already:
            notes.append("error details were already reported by the input checks")
        elif found:
            tpl, url, resp, labels = found
            findings.append(_finding(
                "Error reply reveals " + ", ".join(labels), tpl, url, resp,
                Severity.MEDIUM, Confidence.MEDIUM, FindingStatus.SUSPECTED,
                "Error pages that show internals help an attacker plan the next step.",
                "Turn off debug mode and return a short generic error. Log the "
                "details on the server only."))

        for tpl, url, resp in everything:
            h = _headers(resp)
            server, powered = h.get("server", ""), h.get("x-powered-by", "")
            shown = []
            if re.search(r"\d+\.\d+", server):
                shown.append("Server: " + server)
            if powered:
                shown.append("X-Powered-By: " + powered)
            if shown:
                findings.append(_finding(
                    "Server software and version disclosed (" + "; ".join(shown) + ")",
                    tpl, url, resp, Severity.LOW, Confidence.HIGH,
                    FindingStatus.SUSPECTED,
                    "The exact software version helps an attacker look up known "
                    "weaknesses.",
                    "Remove or shorten the Server and X-Powered-By headers."))
                break

        if findings:
            return CheckReport(Outcome.FINDING, "; ".join(notes), findings)
        return CheckReport(Outcome.PASSED, ("; ".join(notes) + ". " if notes else "")
                           + str(len(errors)) + " error reply(ies) reviewed: "
                           "no internal details found")


CONFIG_CHECKS = [HttpsCheck(), SecurityHeadersCheck(), CorsCheck(),
                 SensitiveDataCheck(), ErrorDetailCheck()]
CONFIG_CHECK_IDS = [c.id for c in CONFIG_CHECKS]