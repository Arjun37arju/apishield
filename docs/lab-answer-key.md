# API-Gapwolf lab answer key

The lab (lab/lab_api.py) is intentionally vulnerable. Fake data only. Run on 127.0.0.1:5000.

Test users: User A = alice (id 1), User B = bob (id 2), admin (id 3).
Orders 1-2 belong to User A. Orders 3-4 belong to User B.
Test tokens are fake and are defined in lab/lab_api.py.

| ID | Planted weakness | Where | Check family |
|----|------------------|-------|--------------|
| W1 | Missing authentication | GET /api/internal/stats | A Authentication |
| W2 | BOLA / IDOR: user A reads user B's order | GET /api/orders/{id} | B Authorization |
| W3 | Weak role check: normal user lists all users | GET /api/admin/users | B Authorization |
| W4 | No owner check on write methods | PATCH, DELETE /api/orders/{id} | B Authorization |
| W5 | Verbose database error message | GET /api/search?q=' | C Input and injection |
| W6 | No rate limit on login | POST /api/login | D Rate limiting |
| W7 | CORS allows any origin | all endpoints | E Security config |
| W8 | No security headers | all endpoints | E Security config |
| W9 | Sensitive data exposed (password, hash) | GET /api/users/me | E Security config |
| W10 | HTTP only, no HTTPS | whole lab | E Security config |

A good scan finds all 10. Record found, missed and false positives in Step 24.
