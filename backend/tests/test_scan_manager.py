import asyncio

import httpx
import pytest
import respx

from app.core.url_validation import clean_target_url
from app.scanner.dummy_checks import (
    DummyCheck,
    ExplodingCheck,
    FindingDummyCheck,
    NeedsTwoUsersCheck,
    SlowDummyCheck,
)
from app.schemas.findings import Outcome, ScanState, make_evidence, redact_text
from app.services.auth_providers import ApiKeyProvider
from app.services.scan_manager import BaseCheck, ScanManager

PUBLIC_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
def temp_audit(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.audit.AUDIT_LOG", tmp_path / "audit.log")


def fixed_resolver(host, port):
    return [PUBLIC_IP]


def make_target():
    return clean_target_url("http://api.example.com/v1")


def make_registry():
    checks = [DummyCheck(), SlowDummyCheck(), NeedsTwoUsersCheck(),
              ExplodingCheck(), FindingDummyCheck()]
    return {c.id: c for c in checks}


def mocked_target():
    mock = respx.mock(assert_all_called=False)
    route = mock.route(host=PUBLIC_IP).mock(
        return_value=httpx.Response(200, json={"ok": True}))
    return mock, route


def test_scan_runs_dummy_check_and_completes():
    mock, route = mocked_target()

    async def scenario():
        mgr = ScanManager(make_registry())
        scan = mgr.create(make_target(), True, ["dummy"], resolver=fixed_resolver)
        assert scan.state == ScanState.QUEUED
        mgr.start(scan.id)
        await mgr.wait(scan.id)
        return scan

    with mock:
        scan = asyncio.run(scenario())
    assert scan.state == ScanState.COMPLETED
    assert scan.results[0].outcome == Outcome.PASSED
    assert scan.ctx.requests_made == 1
    assert route.call_count == 1
    assert scan.to_dict()["state"] == "Completed"


def test_missing_account_is_skipped_with_reason_and_sends_nothing():
    mock, route = mocked_target()

    async def scenario():
        mgr = ScanManager(make_registry())
        scan = mgr.create(make_target(), True, ["needs_two_users"],
                          accounts={"user_a": ApiKeyProvider("test-key-123456")},
                          resolver=fixed_resolver)
        mgr.start(scan.id)
        await mgr.wait(scan.id)
        return scan

    with mock:
        scan = asyncio.run(scenario())
    assert scan.results[0].outcome == Outcome.SKIPPED
    assert "user_b" in scan.results[0].message
    assert route.call_count == 0


def test_error_is_recorded_without_leaking_and_scan_continues():
    mock, route = mocked_target()

    async def scenario():
        mgr = ScanManager(make_registry())
        scan = mgr.create(make_target(), True, ["exploding", "dummy"],
                          resolver=fixed_resolver)
        mgr.start(scan.id)
        await mgr.wait(scan.id)
        return scan

    with mock:
        scan = asyncio.run(scenario())
    assert scan.state == ScanState.COMPLETED
    assert scan.results[0].outcome == Outcome.ERROR
    assert "RuntimeError" in scan.results[0].message
    assert "secret-token-xyz" not in scan.results[0].message
    assert scan.results[1].outcome == Outcome.PASSED


def test_finding_gets_id_and_masked_evidence():
    mock, route = mocked_target()

    async def scenario():
        mgr = ScanManager(make_registry())
        scan = mgr.create(make_target(), True, ["finding_dummy", "finding_dummy"],
                          resolver=fixed_resolver)
        mgr.start(scan.id)
        await mgr.wait(scan.id)
        return scan

    with mock:
        scan = asyncio.run(scenario())
    assert [f.id for f in scan.findings] == ["API-001", "API-002"]
    assert scan.results[0].outcome == Outcome.FINDING
    assert scan.results[0].finding_count == 1
    text = str(scan.to_dict())
    assert "alice-pass" not in text
    assert "abcdefghijkl" not in text


def test_cancel_stops_all_requests():
    mock, route = mocked_target()

    async def scenario():
        mgr = ScanManager(make_registry())
        scan = mgr.create(make_target(), True, ["slow_dummy", "dummy"],
                          resolver=fixed_resolver)
        mgr.start(scan.id)
        await asyncio.sleep(0.3)
        mgr.cancel(scan.id)
        count_at_cancel = route.call_count
        await mgr.wait(scan.id)
        await asyncio.sleep(0.3)
        return scan, count_at_cancel

    with mock:
        scan, count_at_cancel = asyncio.run(scenario())
    assert count_at_cancel > 0
    assert scan.state == ScanState.CANCELLED
    assert route.call_count == count_at_cancel
    assert scan.results == []
    assert scan.finished_at != ""


def test_cancel_before_start():
    mock, route = mocked_target()

    async def scenario():
        mgr = ScanManager(make_registry())
        scan = mgr.create(make_target(), True, ["dummy"], resolver=fixed_resolver)
        mgr.cancel(scan.id)
        with pytest.raises(ValueError):
            mgr.start(scan.id)
        return scan

    with mock:
        scan = asyncio.run(scenario())
    assert scan.state == ScanState.CANCELLED
    assert route.call_count == 0


def test_cannot_start_twice():
    mock, route = mocked_target()

    async def scenario():
        mgr = ScanManager(make_registry())
        scan = mgr.create(make_target(), True, ["dummy"], resolver=fixed_resolver)
        mgr.start(scan.id)
        with pytest.raises(ValueError):
            mgr.start(scan.id)
        await mgr.wait(scan.id)

    with mock:
        asyncio.run(scenario())


def test_create_needs_permission_and_known_checks():
    mgr = ScanManager(make_registry())
    with pytest.raises(ValueError):
        mgr.create(make_target(), False, ["dummy"])
    with pytest.raises(ValueError):
        mgr.create(make_target(), True, ["no_such_check"])
    with pytest.raises(KeyError):
        mgr.get("missing")


def test_request_budget_is_enforced_per_scan():
    mock, route = mocked_target()

    async def scenario():
        mgr = ScanManager({"dummy": DummyCheck()})
        scan = mgr.create(make_target(), True, ["dummy", "dummy"],
                          resolver=fixed_resolver)
        scan.ctx.max_requests = 1
        mgr.start(scan.id)
        await mgr.wait(scan.id)
        return scan

    with mock:
        scan = asyncio.run(scenario())
    assert scan.results[0].outcome == Outcome.PASSED
    assert scan.results[1].outcome == Outcome.ERROR
    assert "budget" in scan.results[1].message
    assert route.call_count == 1


class BrokenCheck(BaseCheck):
    id = "broken"
    name = "Broken check"
    requires = None  # makes the runner itself fail


def test_runner_crash_gives_failed_state():
    async def scenario():
        mgr = ScanManager({"broken": BrokenCheck()})
        scan = mgr.create(make_target(), True, ["broken"], resolver=fixed_resolver)
        mgr.start(scan.id)
        await mgr.wait(scan.id)
        return scan

    scan = asyncio.run(scenario())
    assert scan.state == ScanState.FAILED
    assert scan.error == "TypeError"


def test_evidence_masks_secrets_and_truncates():
    ev = make_evidence(
        "get", "http://x.test/a",
        {"Authorization": "Bearer abcdefghijkl", "X-API-Key": "supersecretkey",
         "Accept": "application/json"},
        200,
        b'{"password": "alice-pass", "token": "abc123", "note": "' + b"x" * 2000 + b'"}',
    )
    text = str(ev)
    assert "alice-pass" not in text
    assert "abc123" not in text
    assert "abcdefghijkl" not in text
    assert "supersecretkey" not in text
    assert ev["request"]["headers"]["Accept"] == "application/json"
    assert len(ev["response"]["body"]) <= 500


def test_redact_text_handles_bearer_in_body_and_bad_bytes():
    assert "abc123def456" not in redact_text("Authorization: Bearer abc123def456")
    ev = make_evidence("GET", "http://x.test", {}, 200, b"\xff\xfe binary")
    assert ev["response"]["status"] == 200
