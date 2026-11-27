import sqlite3

import pytest

from app.database.db import add_report, get_scan, init_db, list_scans, save_scan
from app.schemas.findings import (
    CheckResult, Confidence, Finding, FindingStatus, Outcome, Severity, make_evidence,
)


class FakeScan:
    def __init__(self, scan_id="scan0001", findings=(), created_at="2026-11-26T10:00:00+00:00"):
        self.id, self.findings, self.created_at = scan_id, list(findings), created_at

    def to_dict(self):
        results = [CheckResult("B1", "BOLA / IDOR read", Outcome.FINDING,
                               "1 endpoint(s) need attention", 120, len(self.findings))]
        return {
            "id": self.id, "state": "Completed", "scope": "127.0.0.1:5000",
            "requests_made": 12, "created_at": self.created_at,
            "started_at": self.created_at, "finished_at": self.created_at, "error": "",
            "results": [r.to_dict() for r in results],
            "findings": [f.to_dict() for f in self.findings],
        }


def make_finding(title="Missing ownership check", severity=Severity.HIGH,
                 body='{"id": 2, "owner": "b"}', code="API-001"):
    f = Finding(
        title=title, category="Authorization", endpoint="GET /orders/{id}",
        severity=severity, confidence=Confidence.HIGH, impact="Data is exposed.",
        fix="Check ownership.", status=FindingStatus.CONFIRMED,
        evidence=make_evidence("GET", "http://127.0.0.1:5000/orders/2",
                               {"Authorization": "Bearer supersecret123"}, 200, body))
    f.evidence["root_cause"] = "object-ownership"
    f.evidence["affected_methods"] = ["GET", "PUT"]
    f.id = code
    return f


@pytest.fixture
def db(tmp_path):
    p = tmp_path / "test.db"
    init_db(p)
    return p


def dump(path):
    conn = sqlite3.connect(str(path))
    text = "\n".join(conn.iterdump())
    conn.close()
    return text


def test_scan_is_saved_and_can_be_reopened(db):
    save_scan(FakeScan(findings=[make_finding()]), db)
    s = get_scan("scan0001", db)
    assert s["state"] == "Completed"
    assert s["requests_made"] == 12
    assert s["results"][0]["check_id"] == "B1"
    f = s["findings"][0]
    assert f["id"] == "API-001"
    assert f["severity"] == "High"
    assert f["evidence"]["root_cause"] == "object-ownership"
    assert f["evidence"]["affected_methods"] == ["GET", "PUT"]
    assert f["evidence"]["request"]["url"] == "http://127.0.0.1:5000/orders/2"
    assert f["evidence"]["response"]["status"] == 200


def test_no_raw_secrets_in_database(db):
    body = '{"token": "abc123secret", "password": "hunter2pass", "ok": true}'
    save_scan(FakeScan(findings=[make_finding(body=body)]), db)
    text = dump(db)
    for secret in ("abc123secret", "hunter2pass", "supersecret123"):
        assert secret not in text


def test_sql_text_is_stored_not_executed(db):
    evil = "x'); DROP TABLE scans;--"
    save_scan(FakeScan(findings=[make_finding(title=evil)]), db)
    assert len(list_scans(path=db)) == 1
    assert get_scan("scan0001", db)["findings"][0]["title"] == evil


def test_history_is_newest_first_with_severity_counts(db):
    save_scan(FakeScan("old00001", [make_finding()], "2026-11-25T10:00:00+00:00"), db)
    save_scan(FakeScan("new00001", [make_finding(severity=Severity.CRITICAL),
                                    make_finding(severity=Severity.LOW, code="API-002")],
                       "2026-11-26T10:00:00+00:00"), db)
    rows = list_scans(path=db)
    assert [r["id"] for r in rows] == ["new00001", "old00001"]
    assert rows[0]["finding_count"] == 2
    assert rows[0]["critical"] == 1 and rows[0]["low"] == 1 and rows[0]["high"] == 0
    assert rows[1]["high"] == 1


def test_saving_the_same_scan_twice_does_not_duplicate(db):
    scan = FakeScan(findings=[make_finding()])
    save_scan(scan, db)
    save_scan(scan, db)
    assert len(list_scans(path=db)) == 1
    assert len(get_scan("scan0001", db)["findings"]) == 1


def test_unknown_scan_raises(db):
    with pytest.raises(KeyError):
        get_scan("nope", db)


def test_report_record_keeps_only_the_file_name(db):
    save_scan(FakeScan(findings=[make_finding()]), db)
    add_report("scan0001", "../../evil.pdf", db)
    assert get_scan("scan0001", db)["reports"][0]["file_name"] == "evil.pdf"
    with pytest.raises(sqlite3.IntegrityError):
        add_report("no-such-scan", "x.pdf", db)


def test_all_five_tables_exist(db):
    conn = sqlite3.connect(str(db))
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    conn.close()
    assert {"scans", "check_results", "findings", "evidence", "reports"} <= names