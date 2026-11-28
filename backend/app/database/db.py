"""SQLite storage (Step 21).

Saves scans, check results, findings and masked evidence, and reads them
back for the history screen. Every value goes in with '?' placeholders.
"""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from app.core.settings import settings
from app.schemas.findings import redact_text

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '',
    requests_made INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS check_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id TEXT NOT NULL,
    name TEXT NOT NULL,
    outcome TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    duration_ms INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    status TEXT NOT NULL,
    impact TEXT NOT NULL DEFAULT '',
    fix TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    method TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    request_headers TEXT NOT NULL DEFAULT '{}',
    status_code INTEGER NOT NULL DEFAULT 0,
    response_body TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL DEFAULT '',
    extra TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_results_scan ON check_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_reports_scan ON reports(scan_id);
"""


def _db_path(path=None):
    return Path(path or getattr(settings, "database_path", "data/api-gapwolf.db"))


@contextmanager
def connect(path=None):
    p = _db_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(path=None):
    """Create the database file and the 5 tables if they do not exist."""
    with connect(path):
        pass


def _clean(value, limit=2000):
    """Masks secrets once more before anything is written to disk."""
    return redact_text(str(value if value is not None else ""))[:limit]


def _now():
    return datetime.now(timezone.utc).isoformat()


def save_scan(scan, path=None):
    """Save a finished scan with its check results, findings and evidence.
    Saving the same scan again replaces the old copy."""
    data = scan.to_dict()
    with connect(path) as conn:
        conn.execute("DELETE FROM scans WHERE id = ?", (data["id"],))
        conn.execute(
            "INSERT INTO scans (id, state, scope, requests_made, created_at, "
            "started_at, finished_at, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (data["id"], data["state"], _clean(data.get("scope"), 300),
             int(data.get("requests_made", 0)), data.get("created_at", ""),
             data.get("started_at", ""), data.get("finished_at", ""),
             _clean(data.get("error"), 200)))
        for r in data.get("results", []):
            conn.execute(
                "INSERT INTO check_results (scan_id, check_id, name, outcome, "
                "message, duration_ms, finding_count) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (data["id"], r["check_id"], _clean(r["name"], 200), r["outcome"],
                 _clean(r.get("message"), 500), int(r.get("duration_ms", 0)),
                 int(r.get("finding_count", 0))))
        for f in data.get("findings", []):
            cur = conn.execute(
                "INSERT INTO findings (scan_id, code, title, category, endpoint, "
                "severity, confidence, status, impact, fix) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (data["id"], f["id"], _clean(f["title"], 300), f["category"],
                 _clean(f["endpoint"], 300), f["severity"], f["confidence"],
                 f["status"], _clean(f.get("impact"), 1000), _clean(f.get("fix"), 1000)))
            ev = f.get("evidence") or {}
            req, resp = ev.get("request") or {}, ev.get("response") or {}
            extra = {k: v for k, v in ev.items()
                     if k not in ("request", "response", "observed_at")}
            conn.execute(
                "INSERT INTO evidence (finding_id, method, url, request_headers, "
                "status_code, response_body, observed_at, extra) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (cur.lastrowid, _clean(req.get("method"), 10),
                 _clean(req.get("url"), 300),
                 _clean(json.dumps(req.get("headers") or {}), 2000),
                 int(resp.get("status", 0)), _clean(resp.get("body"), 500),
                 ev.get("observed_at", ""), _clean(json.dumps(extra), 2000)))
    return data["id"]


def list_scans(limit=50, path=None):
    """Screen-ready history: one row per scan with finding counts by severity."""
    limit = max(1, min(int(limit), 500))
    sql = """
        SELECT s.id, s.state, s.scope, s.requests_made, s.created_at, s.finished_at,
          (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id) AS finding_count,
          (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.severity = 'Critical') AS critical,
          (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.severity = 'High') AS high,
          (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.severity = 'Medium') AS medium,
          (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.severity = 'Low') AS low,
          (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id AND f.severity = 'Info') AS info
        FROM scans s
        ORDER BY s.created_at DESC, s.rowid DESC
        LIMIT ?
    """
    with connect(path) as conn:
        return [dict(r) for r in conn.execute(sql, (limit,))]


def get_scan(scan_id, path=None):
    """Reopen one scan. Same shape as Scan.to_dict(), plus a 'reports' list."""
    with connect(path) as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            raise KeyError("scan not found")
        results = [dict(r) for r in conn.execute(
            "SELECT check_id, name, outcome, message, duration_ms, finding_count "
            "FROM check_results WHERE scan_id = ? ORDER BY id", (scan_id,))]
        findings = []
        for f in conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY id", (scan_id,)):
            e = conn.execute("SELECT * FROM evidence WHERE finding_id = ?",
                             (f["id"],)).fetchone()
            evidence = {}
            if e is not None:
                evidence = {
                    "request": {"method": e["method"], "url": e["url"],
                                "headers": json.loads(e["request_headers"] or "{}")},
                    "response": {"status": e["status_code"], "body": e["response_body"]},
                    "observed_at": e["observed_at"],
                }
                evidence.update(json.loads(e["extra"] or "{}"))
            findings.append({
                "id": f["code"], "title": f["title"], "category": f["category"],
                "endpoint": f["endpoint"], "severity": f["severity"],
                "confidence": f["confidence"], "status": f["status"],
                "evidence": evidence, "impact": f["impact"], "fix": f["fix"],
            })
        reports = [dict(r) for r in conn.execute(
            "SELECT file_name, created_at FROM reports WHERE scan_id = ? ORDER BY id",
            (scan_id,))]
        return {
            "id": row["id"], "state": row["state"], "scope": row["scope"],
            "requests_made": row["requests_made"], "created_at": row["created_at"],
            "started_at": row["started_at"], "finished_at": row["finished_at"],
            "error": row["error"], "results": results, "findings": findings,
            "reports": reports,
        }


def add_report(scan_id, file_name, path=None):
    """Remember a generated PDF (used in Step 23). Stores the bare file name only."""
    name = Path(str(file_name).replace("\\", "/")).name
    with connect(path) as conn:
        conn.execute(
            "INSERT INTO reports (scan_id, file_name, created_at) VALUES (?, ?, ?)",
            (scan_id, name, _now()))