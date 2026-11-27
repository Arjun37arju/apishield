from fastapi.testclient import TestClient

from app.main import app


def test_checks_list():
    with TestClient(app) as client:
        res = client.get("/checks")
        assert res.status_code == 200
        assert isinstance(res.json(), list)


def test_scan_requires_permission():
    with TestClient(app) as client:
        res = client.post(
            "/scans",
            json={"url": "http://127.0.0.1:9000", "permission_confirmed": False},
        )
        assert res.status_code == 400


def test_scan_rejects_bad_url():
    with TestClient(app) as client:
        res = client.post(
            "/scans", json={"url": "not-a-url", "permission_confirmed": True}
        )
        assert res.status_code == 400


def test_scan_rejects_unknown_check():
    with TestClient(app) as client:
        res = client.post(
            "/scans",
            json={
                "url": "http://127.0.0.1:9000",
                "permission_confirmed": True,
                "check_ids": ["does-not-exist"],
            },
        )
        assert res.status_code == 400


def test_unknown_scan_is_404():
    with TestClient(app) as client:
        assert client.get("/scans/nope").status_code == 404
        assert client.get("/scans/nope/findings").status_code == 404
        assert client.post("/scans/nope/cancel").status_code == 404