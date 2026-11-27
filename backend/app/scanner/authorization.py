"""Check B: Authorization (BOLA / IDOR, roles, write methods on other users' data)."""
import re

from app.schemas.findings import (
    Confidence, Finding, FindingStatus, Outcome, Severity, make_evidence,
)
from app.services.scan_manager import BaseCheck, CheckReport

# ======================= ADAPTER: check these lines =======================
from urllib.parse import urlsplit

from app.services.auth_providers import _lab_http_allowed

# Real object IDs that belong to User B in the lab (answer key: orders 3-4 = bob).
# "*" = use this ID for every resource. Or use {"orders": "3", "users": "2"}.
USER_B_IDS = {"orders": "3", "users": "2"}
# DISPOSABLE objects of User B. The DELETE check really deletes them.
USER_B_DELETE_IDS = {"orders": "4"}


def _base_url(scan):
    parts = urlsplit(scan.target["url"])
    return parts.scheme + "://" + parts.netloc


def _endpoints(scan):
    """Returns a list of (METHOD, '/path/{id}'). Same source as Check A."""
    out = []
    for ep in scan.target.get("endpoints") or []:
        if isinstance(ep, str):
            out.append(("GET", ep))
        else:
            out.append((str(ep.get("method", "GET")).upper(), str(ep.get("path", ""))))
    return out


def _is_lab(scan):
    """Write tests (PUT/PATCH/DELETE) run ONLY on the lab:
    ALLOW_LAB_EXCEPTION is on AND the target port is the lab port."""
    return bool(_lab_http_allowed(scan.target["url"]))
# ==========================================================================

ID_PARAM = re.compile(r"\{[^}/]+\}")
ADMIN_HINT = re.compile(r"/(admin|internal|manage|management|superuser)(/|$)", re.I)
DENY = {401, 403, 404}
MARKER = "apishield-test"

ROOT_OBJECT = "object-ownership"
ROOT_ROLE = "admin-role"
FIX_OBJECT = ("On the server, check that the logged-in user owns the requested object "
              "on every request. Never trust IDs sent by the client. Unguessable IDs "
              "help, but are not a fix on their own.")
FIX_ROLE = "Check the user's role on the server for every admin endpoint."


def _text(resp):
    """Reply body as text. Works for any reply object that has .text or .body."""
    text = getattr(resp, "text", None)
    if isinstance(text, str):
        return text
    body = getattr(resp, "body", b"") or b""
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def _eps(scan, method):
    return [p for m, p in _endpoints(scan) if m == method and p]


def _fill(template, ids):
    """Fill ONE {id} placeholder with a known ID of User B. None if impossible."""
    if len(ID_PARAM.findall(template)) != 1:
        return None
    m = re.search(r"/([^/{}]+)/\{[^}/]+\}", template)
    resource = m.group(1) if m else "*"
    obj_id = ids.get(resource) or ids.get("*")
    return ID_PARAM.sub(str(obj_id), template) if obj_id else None


class _Acc:
    """Collects results of one check. Merges findings with the same root cause."""

    def __init__(self):
        self.new, self.merged, self.manual, self.tested = [], [], [], 0

    def hit(self, scan, root, title, template, method, url, resp,
            severity, confidence, impact, fix):
        for f in list(scan.findings) + self.new:
            if (f.category == "Authorization" and f.endpoint == template
                    and f.evidence.get("root_cause") == root):
                methods = f.evidence.setdefault("affected_methods", [])
                if method not in methods:
                    methods.append(method)
                self.merged.append(f)
                return
        ev = make_evidence(method, url, {}, resp.status_code, _text(resp))
        ev["root_cause"] = root
        ev["affected_methods"] = [method]
        self.new.append(Finding(
            title=title, category="Authorization", endpoint=template,
            severity=severity, confidence=confidence, impact=impact, fix=fix,
            status=FindingStatus.CONFIRMED if confidence == Confidence.HIGH
            else FindingStatus.SUSPECTED,
            evidence=ev,
        ))

    def report(self, skip_reason):
        if self.new:
            return CheckReport(Outcome.FINDING, "", self.new)
        if self.merged:
            ids = ", ".join(sorted({f.id or "earlier finding" for f in self.merged}))
            return CheckReport(Outcome.PASSED,
                               "weakness found, merged into " + ids + " (same root cause)")
        if self.manual:
            return CheckReport(Outcome.MANUAL, "; ".join(self.manual[:3]))
        if self.tested:
            return CheckReport(Outcome.PASSED)
        return CheckReport(Outcome.SKIPPED, skip_reason)


class _AuthzCheck(BaseCheck):
    category = "Authorization"
    requires = ("user_a", "user_b")


class B1BolaRead(_AuthzCheck):
    id = "B1"
    name = "BOLA / IDOR read"

    async def run(self, scan):
        acc = _Acc()
        for tpl in _eps(scan, "GET"):
            path = _fill(tpl, USER_B_IDS)
            if not path:
                continue
            url = _base_url(scan) + path
            base = await scan.request("GET", url, account="user_b")  # baseline
            if base.status_code != 200:
                continue
            acc.tested += 1
            r = await scan.request("GET", url, account="user_a")
            if r.status_code == 200:
                same = _text(r).strip() == _text(base).strip()
                acc.hit(scan, ROOT_OBJECT,
                        "Missing object-level ownership check (BOLA / IDOR)",
                        tpl, "GET", url, r, Severity.HIGH,
                        Confidence.HIGH if same else Confidence.MEDIUM,
                        "Any logged-in user can access other users' objects by changing the ID.",
                        FIX_OBJECT)
            elif r.status_code not in DENY:
                acc.manual.append("GET %s returned %s" % (tpl, r.status_code))
        return acc.report("no GET endpoint with an ID that matches User B's known IDs")


class B2RoleCheck(_AuthzCheck):
    id = "B2"
    name = "Role check (normal user vs admin)"

    async def run(self, scan):
        acc = _Acc()
        for tpl in _eps(scan, "GET"):
            if not ADMIN_HINT.search(tpl):
                continue
            path = tpl
            if ID_PARAM.search(tpl):
                path = _fill(tpl, USER_B_IDS)
                if not path:
                    continue
            url = _base_url(scan) + path
            acc.tested += 1
            r = await scan.request("GET", url, account="user_a")  # user_a = normal user
            if r.status_code == 200:
                acc.hit(scan, ROOT_ROLE, "Normal user can reach an admin endpoint",
                        tpl, "GET", url, r, Severity.HIGH, Confidence.MEDIUM,
                        "A normal user can use admin functions or see admin data.",
                        FIX_ROLE)
            elif r.status_code not in DENY:
                acc.manual.append("GET %s returned %s" % (tpl, r.status_code))
        return acc.report("no admin-looking GET endpoint found in the spec")


class _WriteCheck(_AuthzCheck):
    method = ""
    ids = None

    async def run(self, scan):
        if not _is_lab(scan):
            return CheckReport(Outcome.SKIPPED, "write tests run on the lab only")
        acc = _Acc()
        # The lab's PATCH expects {"status": "..."}; the marker goes into that field.
        body = None if self.method == "DELETE" else {"status": MARKER}
        for tpl in _eps(scan, self.method):
            path = _fill(tpl, self.ids)
            if not path:
                continue
            url = _base_url(scan) + path
            acc.tested += 1
            r = await scan.request(self.method, url, account="user_a", json_body=body)
            if 200 <= r.status_code < 300:
                check = await scan.request("GET", url, account="user_b")  # follow-up
                if self.method == "DELETE":
                    confirmed = check.status_code == 404
                else:
                    confirmed = MARKER in _text(check)
                acc.hit(scan, ROOT_OBJECT,
                        "Missing object-level ownership check (BOLA / IDOR)",
                        tpl, self.method, url, r, Severity.HIGH,
                        Confidence.HIGH if confirmed else Confidence.MEDIUM,
                        "Any logged-in user can read, change or delete other users' objects.",
                        FIX_OBJECT)
            elif r.status_code in (400, 422):
                acc.manual.append("%s %s body rejected (%s)" % (self.method, tpl, r.status_code))
            elif r.status_code not in DENY:
                acc.manual.append("%s %s returned %s" % (self.method, tpl, r.status_code))
        return acc.report("no endpoint with an ID that matches the configured IDs")


class B3PutOther(_WriteCheck):
    id, name, method, ids = "B3", "PUT on another user's data", "PUT", USER_B_IDS


class B4PatchOther(_WriteCheck):
    id, name, method, ids = "B4", "PATCH on another user's data", "PATCH", USER_B_IDS


class B5DeleteOther(_WriteCheck):
    id, name, method, ids = "B5", "DELETE on another user's data", "DELETE", USER_B_DELETE_IDS


AUTHZ_CHECKS = [B1BolaRead(), B2RoleCheck(), B3PutOther(), B4PatchOther(), B5DeleteOther()]