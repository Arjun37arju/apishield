# Step 24 test record

Date: 2026-11-27

## Gates
- Backend tests: 193 passed (independent of the .env file)
- pip-audit: no known vulnerabilities
- npm audit: 0 vulnerabilities
- Versions locked: backend/requirements.lock.txt

## Lab scan vs answer key (docs/lab-answer-key.md)
- Found: 9 of 10 (W1 to W9)
- W10 (HTTP only): flagged "Needs manual check" by design (lab exception)
- Missed: 0
- False positives: 0 after the fix below
- Final scan: 102 requests, 13 findings (High 8, Medium 3, Low 2)

## Bug found and fixed
The expired-token account sent the valid token (api/scans.py), which gave 2 false
positives. Fixed, and 4 tests now cover it (tests/test_expired_token_account.py).

## Known issue
The report shows "Passed" for PATCH and DELETE even when a weakness is found
(the details column says "weakness found, merged into API-004").

# Limitations
- Results are evidence for review, not proof that an API is secure.
- Findings marked suspected or manual review need a person to confirm them.
- Tested only against the local lab, not real APIs.
- The lab exception allows plain http on the local lab only. The HTTPS check needs a manual review there.
- PUT check skipped: the lab has no PUT endpoint with an ID.
- Rate-limit checks 2 to 4 skipped: the lab has no limit, so there was nothing to measure.
- The rate-limit test uses a safe size of 20 requests. Higher limits may exist.
- A missing security header is not always a weakness for a pure JSON API.
- Logins entered on the Auth screen are kept in memory only and are cleared on page refresh.
- The expired-token check needs a Bearer login with an expired token supplied.
