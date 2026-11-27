# APIShield

APIShield is a security scanner for web APIs. You give it the address of an API you own
(and optionally an OpenAPI file). It runs a limited set of non-destructive checks, shows
the findings in a dashboard, keeps the history in a local SQLite database, and exports a
redacted PDF report.

## Authorized use only

Only scan systems you own or have written permission to test. The report lists weaknesses,
so share it carefully. Results are evidence for review, not proof that an API is secure.

## What it checks

- Authentication: no login, made-up token, expired token, broken token, inconsistent login rules
- Authorization: object-level access (BOLA / IDOR), role check, PUT / PATCH / DELETE on another user's data
- Input and injection: SQL-injection indicators, wrong data types, boundary values, odd parameters, error replies
- Rate limiting: request limit, 429 answer, recovery
- Security configuration: HTTPS, security headers, CORS, sensitive data, error details

Logins: Bearer / JWT token, Basic, API key and OAuth 2.0 client credentials.

## Safety design

- The backend listens on 127.0.0.1 only.
- CORS allows only the exact dashboard address.
- Limits are enforced in code: 100 requests per scan, 2 parallel, 10 s timeout, 1 MB response.
- Uploads: 2 MB maximum, JSON or YAML only, safe YAML loading, remote references off.
- URLs: http or https only, no password inside the URL; private, loopback and metadata
  addresses are blocked. The one exception is the built-in lab (see below).
- Logins entered in the dashboard are kept in memory only and are cleared on page refresh.
- Reports and the database store masked evidence only. Report text is escaped.

## Requirements

- Python 3.14
- Node.js 22 or newer
- Windows PowerShell (the commands below use it)

## Setup

```
git clone https://github.com/Arjun37arju/apishield.git
cd apishield
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
copy backend\.env.example backend\.env
cd frontend
npm install
```

## Run the tests

```
cd backend
..\.venv\Scripts\python.exe -m pytest -q
```

## Run the demo with the practice lab

The `lab` folder contains an intentionally vulnerable API with fake data. It is never to be
exposed to a network. The lab answer key is in `docs\lab-answer-key.md`.

1. In `backend\.env` set `ALLOW_LAB_EXCEPTION=true`. This allows plain http for the local lab only.
   Set it back to `false` when you are not scanning the lab.
2. Start the lab, the backend and the dashboard in three terminals:

```
cd lab
..\.venv\Scripts\python.exe -m uvicorn lab_api:app --host 127.0.0.1 --port 5000
```
```
cd backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
```
cd frontend
npm run dev
```

3. Reset the lab before each scan:

```
Invoke-RestMethod -Method Post http://127.0.0.1:5000/lab/reset
```

4. Open http://localhost:5173. On the Auth screen set User A to Bearer with `lab-token-user-a`
   (expired token `lab-token-expired`) and User B to Bearer with `lab-token-user-b`.
5. On Target Setup enter `http://127.0.0.1:5000`, paste the endpoints, tick the permission box
   and start the scan.

The scan should find 9 of the 10 planted weaknesses. The tenth (no HTTPS) is flagged for manual
review because the lab exception allows plain http.

## Known limits

- Tested against the local lab only, not against real APIs.
- Findings marked suspected or manual review need a person to confirm them.
- The PUT check is skipped when the API has no PUT endpoint with an ID.
- Rate-limit checks use a safe size of 20 requests. Higher limits may exist.
- A missing security header is not always a weakness for a pure JSON API.
- The report shows "Passed" for PATCH and DELETE rows even when a weakness is found; the
  details column says "weakness found, merged into ...".
- Test results are in `docs\step24-test-record.md` and `docs\step25-self-check.md`.