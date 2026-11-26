import json

import yaml

from app.core.settings import settings


class OpenAPIError(ValueError):
    """Raised when an uploaded API description is not acceptable."""


ALLOWED_EXTENSIONS = (".json", ".yaml", ".yml")
HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
MAX_ENDPOINTS = 1000


def _check_and_decode(filename, content):
    name = (filename or "").lower()
    if not name.endswith(ALLOWED_EXTENSIONS):
        raise OpenAPIError("Only .json, .yaml and .yml files are allowed")
    if len(content) > settings.max_upload_bytes:
        raise OpenAPIError("File is too large")
    try:
        return name, content.decode("utf-8")
    except UnicodeDecodeError:
        raise OpenAPIError("File is not valid UTF-8 text")


def _parse_json(text):
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        raise OpenAPIError("File is not valid JSON")


def _parse_yaml(text):
    try:
        for token in yaml.scan(text, Loader=yaml.SafeLoader):
            if isinstance(token, yaml.AliasToken):
                raise OpenAPIError("YAML aliases are not allowed")
        return yaml.safe_load(text)
    except OpenAPIError:
        raise
    except (yaml.YAMLError, RecursionError):
        raise OpenAPIError("File is not valid or safe YAML")


def parse_openapi(filename, content):
    name, text = _check_and_decode(filename, content)
    doc = _parse_json(text) if name.endswith(".json") else _parse_yaml(text)

    if not isinstance(doc, dict) or not ("openapi" in doc or "swagger" in doc):
        raise OpenAPIError("File is not an OpenAPI / Swagger document")
    paths = doc.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise OpenAPIError("No paths found in the document")

    endpoints = []
    for path, item in paths.items():
        if not isinstance(path, str) or not path.startswith("/"):
            raise OpenAPIError("A path in the document is invalid")
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            op = item.get(method)
            if isinstance(op, dict):
                endpoints.append({
                    "method": method.upper(),
                    "path": path[:300],
                    "summary": str(op.get("summary", ""))[:200],
                })
                if len(endpoints) > MAX_ENDPOINTS:
                    raise OpenAPIError("Too many endpoints")
    if not endpoints:
        raise OpenAPIError("No endpoints found in the document")

    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    return {
        "title": str(info.get("title", ""))[:200],
        "version": str(info.get("version", ""))[:50],
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
    }
