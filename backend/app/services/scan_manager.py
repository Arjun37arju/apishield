import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from app.core.audit import audit
from app.core.safety_gate import (
    RequestBlocked,
    ScanContext,
    default_resolver,
    send_request,
)
from app.schemas.findings import CheckResult, Outcome, ScanState
from app.services.auth_providers import AuthError

FINAL_STATES = (ScanState.COMPLETED, ScanState.CANCELLED, ScanState.FAILED)


def _now():
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CheckReport:
    outcome: Outcome
    message: str = ""
    findings: list = field(default_factory=list)


class BaseCheck:
    id = "base"
    name = "Base check"
    category = "General"
    requires = ()  # names of test accounts this check needs, e.g. ("user_a", "user_b")

    async def run(self, scan):
        """Send requests with scan.request(...) and return a CheckReport."""
        raise NotImplementedError


@dataclass
class Scan:
    target: dict
    ctx: ScanContext
    check_ids: list
    accounts: dict = field(default_factory=dict, repr=False)
    resolver: Any = field(default=default_resolver, repr=False)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    state: ScanState = ScanState.QUEUED
    results: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    created_at: str = field(default_factory=_now)
    started_at: str = ""
    finished_at: str = ""
    error: str = ""
    task: Any = field(default=None, repr=False)

    async def request(self, method, url, account=None, variant="valid",
                      headers=None, json_body=None, content=None):
        """Every check sends requests through here, and so through the safety gate."""
        provider = None
        if account is not None:
            provider = self.accounts.get(account)
            if provider is None:
                raise AuthError("test account missing: " + account)
            prepare = getattr(provider, "prepare", None)
            if prepare:
                await prepare(self.ctx, self.resolver)
        return await send_request(
            self.ctx, method, url, headers=headers, json_body=json_body,
            content=content, resolver=self.resolver,
            auth=provider, auth_variant=variant,
        )

    def add_finding(self, finding):
        finding.id = "API-%03d" % (len(self.findings) + 1)
        self.findings.append(finding)
        return finding

    def to_dict(self):
        return {
            "id": self.id,
            "state": self.state.value,
            "scope": self.target.get("scope", ""),
            "requests_made": self.ctx.requests_made,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "results": [r.to_dict() for r in self.results],
            "findings": [f.to_dict() for f in self.findings],
        }


class ScanManager:
    def __init__(self, registry):
        self.registry = registry  # {check_id: check object}
        self.scans = {}

    def create(self, target, permission_confirmed, check_ids, accounts=None,
               resolver=default_resolver):
        if not permission_confirmed:
            raise ValueError("permission not confirmed")
        unknown = [c for c in check_ids if c not in self.registry]
        if unknown:
            raise ValueError("unknown check: " + ", ".join(unknown))
        ctx = ScanContext.from_target(target, permission_confirmed)
        scan = Scan(target=target, ctx=ctx, check_ids=list(check_ids),
                    accounts=dict(accounts or {}), resolver=resolver)
        self.scans[scan.id] = scan
        audit("scan_created", scan_id=scan.id, scope=target["scope"],
              checks=len(scan.check_ids))
        return scan

    def get(self, scan_id):
        scan = self.scans.get(scan_id)
        if scan is None:
            raise KeyError("scan not found")
        return scan

    def start(self, scan_id):
        scan = self.get(scan_id)
        if scan.state != ScanState.QUEUED:
            raise ValueError("scan cannot be started from state " + scan.state.value)
        scan.task = asyncio.create_task(self._run(scan))
        return scan

    async def wait(self, scan_id):
        scan = self.get(scan_id)
        if scan.task is not None:
            await asyncio.wait({scan.task})
        return scan

    def cancel(self, scan_id):
        scan = self.get(scan_id)
        if scan.state in FINAL_STATES:
            return scan
        scan.ctx.cancelled = True  # the gate now blocks every request
        scan.state = ScanState.CANCELLED
        scan.finished_at = _now()
        if scan.task is not None and not scan.task.done():
            scan.task.cancel()
        audit("scan_cancelled", scan_id=scan.id, requests=scan.ctx.requests_made)
        return scan

    async def _run(self, scan):
        scan.state = ScanState.RUNNING
        scan.started_at = _now()
        audit("scan_started", scan_id=scan.id)
        try:
            for check_id in scan.check_ids:
                if scan.ctx.cancelled:
                    break
                await self._run_check(scan, self.registry[check_id])
            if scan.state == ScanState.RUNNING:
                scan.state = ScanState.COMPLETED
        except asyncio.CancelledError:
            scan.state = ScanState.CANCELLED
            raise
        except Exception as e:
            scan.state = ScanState.FAILED
            scan.error = type(e).__name__
        finally:
            scan.finished_at = scan.finished_at or _now()
            audit("scan_finished", scan_id=scan.id, state=scan.state.value,
                  requests=scan.ctx.requests_made)

    async def _run_check(self, scan, check):
        started = time.monotonic()
        findings = []
        missing = [a for a in check.requires if a not in scan.accounts]
        if missing:
            outcome = Outcome.SKIPPED
            message = "test account missing: " + ", ".join(missing)
        else:
            try:
                report = await check.run(scan)
                outcome, message, findings = report.outcome, report.message, report.findings
            except RequestBlocked as e:
                outcome, message = Outcome.ERROR, "blocked by the safety gate: " + str(e)
            except AuthError as e:
                outcome, message = Outcome.ERROR, "login problem: " + str(e)
            except (httpx.HTTPError, TimeoutError) as e:
                outcome, message = Outcome.ERROR, "request failed: " + type(e).__name__
            except Exception as e:
                outcome, message = Outcome.ERROR, "internal error: " + type(e).__name__

        if findings and outcome != Outcome.FINDING:
            outcome = Outcome.FINDING
        if outcome == Outcome.FINDING and not findings:
            outcome, message = Outcome.ERROR, "check reported a finding without details"
        for finding in findings:
            scan.add_finding(finding)
        scan.results.append(CheckResult(
            check_id=check.id, name=check.name, outcome=outcome, message=message,
            duration_ms=int((time.monotonic() - started) * 1000),
            finding_count=len(findings),
        ))
