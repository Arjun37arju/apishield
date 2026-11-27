"""Run Check A (authentication) against your own local lab.

Start the lab first (127.0.0.1:5000), then from the backend folder:

    $env:ALLOW_LAB_EXCEPTION = "true"
    python -m tools.lab_auth_scan

Switch the lab exception off again when you are done.
Evidence is not printed here, so no token can show on screen.
"""
import asyncio

from app.core.url_validation import clean_target_url
from app.scanner.auth_checks import AUTH_CHECK_IDS, auth_registry
from app.services.scan_manager import ScanManager

LAB = "http://127.0.0.1:5000"
# Lab endpoints from docs/lab-answer-key.md (GET only, no templates).
ENDPOINTS = [
    "/api/internal/stats",
    "/api/orders/1",
    "/api/admin/users",
    "/api/users/me",
]


async def main():
    target = clean_target_url(LAB + "/api")
    target["endpoints"] = ENDPOINTS
    mgr = ScanManager(auth_registry())
    scan = mgr.create(target, True, AUTH_CHECK_IDS)
    mgr.start(scan.id)
    await mgr.wait(scan.id)

    print("state:", scan.state.value, "| requests:", scan.ctx.requests_made)
    if scan.error:
        print("error:", scan.error)
    print()
    for r in scan.results:
        print("%-24s %-18s %s" % (r.check_id, r.outcome.value, r.message))
    print()
    if not scan.findings:
        print("no findings")
    for f in scan.findings:
        print("%s  %-8s %-6s  %s  [%s]" % (
            f.id, f.severity.value, f.confidence.value, f.endpoint, f.title))


if __name__ == "__main__":
    asyncio.run(main())
