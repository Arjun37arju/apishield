import json

import pytest
from fastapi.testclient import TestClient

from app.core.settings import settings
from app.main import app

client = TestClient(app)

GOOD = {
    "openapi": "3.0.0",
    "info": {"title": "Demo", "version": "1.0"},
    "paths": {"/users": {"get": {}}},
}


@pytest.fixture(autouse=True)
def temp_audit(tmp_path, monkeypatch):
    path = tmp_path / "audit.log"
    monkeypatch.setattr("app.core.audit.AUDIT_LOG", path)
    return path


def test_permission_required(temp_audit):
    r = client.post("/targets/validate", json={"url": "https://example.com"})
    assert r.status_code == 400
    assert "permission" in temp_audit.read_text()


def test_good_url_with_permission(temp_audit):
    r = client.post(
        "/targets/validate",
        json={"url": "https://example.com/api", "permission_confirmed": True},
    )
    assert r.status_code == 200
    assert r.json()["requests_sent"] == 0
    assert "permission_confirmed" in temp_audit.read_text()


def test_bad_url_rejected_and_secret_not_logged(temp_audit):
    r = client.post(
        "/targets/validate",
        json={"url": "https://user:topsecret@example.com", "permission_confirmed": True},
    )
    assert r.status_code == 400
    assert "topsecret" not in temp_audit.read_text()


def test_upload_good_spec(temp_audit):
    data = json.dumps(GOOD).encode()
    r = client.post("/targets/openapi", files={"file": ("spec.json", data, "application/json")})
    assert r.status_code == 200
    assert r.json()["endpoint_count"] == 1
    assert r.json()["requests_sent"] == 0


def test_upload_wrong_type_rejected(temp_audit):
    r = client.post("/targets/openapi", files={"file": ("spec.txt", b"hello", "text/plain")})
    assert r.status_code == 400


def test_upload_huge_file_rejected(temp_audit):
    big = b"a" * (settings.max_upload_bytes + 1)
    r = client.post("/targets/openapi", files={"file": ("spec.json", big, "application/json")})
    assert r.status_code == 400


def test_upload_malicious_yaml_rejected(temp_audit):
    evil = b'openapi: 3.0.0\nx: !!python/object/apply:os.system ["echo hacked"]\n'
    r = client.post("/targets/openapi", files={"file": ("spec.yaml", evil, "application/x-yaml")})
    assert r.status_code == 400
