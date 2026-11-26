import asyncio

from app.schemas.findings import (
    Confidence,
    Finding,
    FindingStatus,
    Outcome,
    Severity,
    make_evidence,
)
from app.services.scan_manager import BaseCheck, CheckReport


class DummyCheck(BaseCheck):
    id = "dummy"
    name = "Dummy check"
    category = "Test"

    async def run(self, scan):
        resp = await scan.request("GET", scan.target["url"])
        return CheckReport(Outcome.PASSED,
                           "reached the target, status " + str(resp.status_code))


class SlowDummyCheck(BaseCheck):
    id = "slow_dummy"
    name = "Slow dummy check"
    category = "Test"

    async def run(self, scan):
        for _ in range(50):
            await scan.request("GET", scan.target["url"])
            await asyncio.sleep(0.05)
        return CheckReport(Outcome.PASSED, "finished all requests")


class NeedsTwoUsersCheck(BaseCheck):
    id = "needs_two_users"
    name = "Needs two users"
    category = "Test"
    requires = ("user_a", "user_b")

    async def run(self, scan):
        return CheckReport(Outcome.PASSED, "ran with two users")


class ExplodingCheck(BaseCheck):
    id = "exploding"
    name = "Exploding check"
    category = "Test"

    async def run(self, scan):
        raise RuntimeError("secret-token-xyz")


class FindingDummyCheck(BaseCheck):
    id = "finding_dummy"
    name = "Finding dummy check"
    category = "Test"

    async def run(self, scan):
        evidence = make_evidence(
            "GET", scan.target["url"],
            {"Authorization": "Bearer abcdefghijkl"}, 200,
            b'{"password": "alice-pass", "ok": true}',
        )
        finding = Finding(
            title="Dummy finding",
            category="Test",
            endpoint="GET " + scan.target["path"],
            severity=Severity.INFO,
            confidence=Confidence.LOW,
            status=FindingStatus.SUSPECTED,
            impact="Test only.",
            fix="Nothing to fix.",
            evidence=evidence,
        )
        return CheckReport(Outcome.FINDING, "dummy finding created", [finding])
