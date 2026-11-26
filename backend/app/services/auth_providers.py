import base64
import re
from urllib.parse import urlsplit

from app.core.settings import settings

HEADER_NAME = re.compile(r"[A-Za-z0-9-]{1,64}")
VARIANTS = ("valid", "none", "wrong")


class AuthError(ValueError):
    """Raised when credentials cannot be used safely."""


def _clean(value, label):
    text = str(value or "")
    if not text or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise AuthError(label + " is empty or has control characters")
    return text


def _lab_http_allowed(url):
    parts = urlsplit(url)
    return (
        settings.allow_lab_exception
        and parts.port == settings.lab_port
        and parts.hostname in ("127.0.0.1", "localhost", "::1")
    )


class AuthProvider:
    """One interface for every login method. Checks never contain login code."""

    name = "base"

    def apply(self, headers, url, variant="valid"):
        raise NotImplementedError

    def __repr__(self):
        return "<" + self.__class__.__name__ + " credentials hidden>"


class BasicAuthProvider(AuthProvider):
    name = "basic"

    def __init__(self, username, password):
        self._username = _clean(username, "username")
        if ":" in self._username:
            raise AuthError("username must not contain a colon")
        self._password = _clean(password, "password")

    def apply(self, headers, url, variant="valid"):
        if variant not in VARIANTS:
            raise AuthError("unknown variant")
        out = dict(headers or {})
        if variant == "none":
            return out
        if urlsplit(url).scheme != "https" and not _lab_http_allowed(url):
            raise AuthError("Basic Auth is only allowed over HTTPS")
        password = self._password if variant == "valid" else "invalid-password"
        raw = (self._username + ":" + password).encode("utf-8")
        out["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        return out


class ApiKeyProvider(AuthProvider):
    name = "api_key"

    def __init__(self, key, header_name="X-API-Key"):
        if not HEADER_NAME.fullmatch(str(header_name or "")):
            raise AuthError("invalid header name")
        self._header = header_name
        self._key = _clean(key, "API key")

    def apply(self, headers, url, variant="valid"):
        if variant not in VARIANTS:
            raise AuthError("unknown variant")
        out = dict(headers or {})
        if variant == "none":
            return out
        out[self._header] = self._key if variant == "valid" else "invalid-key"
        return out
