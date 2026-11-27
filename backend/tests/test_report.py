from app.reports.pdf_report import build_report


def test_report_is_a_pdf(tmp_path):
    scan = {
        "id": "abc123",
        "state": "Completed",
        "scope": "127.0.0.1:5000",
        "requests_made": 5,
        "results": [{"check_id": "x", "name": "Check X", "outcome": "Passed", "message": ""}],
        "findings": [{
            "id": "API-001", "title": "Test <finding> & more", "category": "Auth",
            "endpoint": "GET /x", "severity": "High", "confidence": "Medium",
            "status": "suspected", "impact": "Impact", "fix": "Fix",
            "evidence": {"request": {"method": "GET", "url": "http://x"},
                         "response": {"status": 200, "body": "{}"}},
        }],
    }
    path = build_report(scan, tmp_path)
    assert path.read_bytes().startswith(b"%PDF")


def test_report_without_findings(tmp_path):
    path = build_report({"id": "empty", "findings": [], "results": []}, tmp_path)
    assert path.exists()