# Step 25 self-security check

Date: 2026-11-27

| Test | Result |
|---|---|
| Backend listens on 127.0.0.1 only | PASS |
| No .env, .db, reports or PDFs tracked by Git | PASS |
| CORS allowed for the dashboard origin | PASS |
| CORS refused for another origin, including preflight | PASS |
| 3 MB upload rejected (HTTP 400) | PASS |
| Malicious YAML rejected (HTTP 400) | PASS |
| Valid spec accepted (HTTP 200) | PASS |
| No tokens in the database, reports or log files | PASS |
| Tests pass with the lab exception on and off | PASS |

Backend terminal window searched for lab-token: nothing found (PASS).
