from urllib.parse import urlsplit

from app.core.settings import settings


class TargetError(ValueError):
    """Raised when a target URL is not acceptable."""


DEFAULT_PORTS = {"http": 80, "https": 443}


def allowed_ports() -> set:
    return {80, 443, settings.lab_port}


def clean_target_url(raw: str) -> dict:
    raw = (raw or "").strip()
    if not raw or len(raw) > 2048:
        raise TargetError("URL is empty or too long")
    if any(ord(c) <= 32 or ord(c) == 127 for c in raw):
        raise TargetError("URL contains spaces or control characters")

    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise TargetError("Only http and https are allowed")
    if parts.username or parts.password or "@" in parts.netloc:
        raise TargetError("URLs with a username or password inside are not allowed")

    host = parts.hostname
    if not host:
        raise TargetError("URL has no host")
    try:
        port = parts.port or DEFAULT_PORTS[scheme]
    except ValueError:
        raise TargetError("Invalid port")
    if port not in allowed_ports():
        raise TargetError("Port " + str(port) + " is not allowed")

    shown_host = "[" + host + "]" if ":" in host else host
    path = parts.path or "/"
    return {
        "url": scheme + "://" + shown_host + ":" + str(port) + path,
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "scope": shown_host + ":" + str(port),
    }
