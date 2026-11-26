import json

import pytest

from app.core.settings import settings
from app.services.openapi_import import OpenAPIError, parse_openapi

GOOD = {
    "openapi": "3.0.0",
    "info": {"title": "Demo", "version": "1.0"},
    "paths": {
        "/users": {"get": {"summary": "List users"}, "post": {}},
        "/users/{id}": {"get": {}, "delete": {}},
    },
}

GOOD_YAML = """openapi: 3.0.0
info:
  title: Demo
  version: "1.0"
paths:
  /items:
    get:
      summary: List items
"""


def test_good_json_becomes_endpoint_list():
    r = parse_openapi("spec.json", json.dumps(GOOD).encode())
    assert r["endpoint_count"] == 4
    assert {"method": "GET", "path": "/users", "summary": "List users"} in r["endpoints"]


def test_good_yaml():
    r = parse_openapi("spec.yaml", GOOD_YAML.encode())
    assert r["endpoint_count"] == 1


def test_broken_json_rejected():
    with pytest.raises(OpenAPIError):
        parse_openapi("spec.json", b'{"openapi": "3.0.0", ')


def test_huge_file_rejected_before_parsing():
    big = b"a" * (settings.max_upload_bytes + 1)
    with pytest.raises(OpenAPIError, match="too large"):
        parse_openapi("spec.json", big)


def test_malicious_yaml_object_rejected():
    evil = b'openapi: 3.0.0\nx: !!python/object/apply:os.system ["echo hacked"]\n'
    with pytest.raises(OpenAPIError):
        parse_openapi("spec.yaml", evil)


def test_yaml_alias_rejected():
    bomb = b"openapi: 3.0.0\na: &a [1, 2]\nb: *a\n"
    with pytest.raises(OpenAPIError, match="alias"):
        parse_openapi("spec.yaml", bomb)


@pytest.mark.parametrize("name", ["spec.txt", "spec.exe", "spec", "spec.json.exe", ""])
def test_wrong_extension_rejected(name):
    with pytest.raises(OpenAPIError):
        parse_openapi(name, json.dumps(GOOD).encode())


def test_not_openapi_rejected():
    with pytest.raises(OpenAPIError):
        parse_openapi("spec.json", b'{"hello": "world"}')


def test_no_paths_rejected():
    with pytest.raises(OpenAPIError):
        parse_openapi("spec.json", b'{"openapi": "3.0.0", "paths": {}}')


def test_invalid_utf8_rejected():
    with pytest.raises(OpenAPIError):
        parse_openapi("spec.json", b"\xff\xfe\x00")
