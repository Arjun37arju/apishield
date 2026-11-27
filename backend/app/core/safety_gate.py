import asyncio
import ipaddress
import socket
import threading
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit

import httpx

from app.core.audit import audit
from app.core.settings import settings
from app.core.url_validation import TargetError, clean_target_url

ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
MAX_REDIRECT_HOPS = 3


class RequestBlocked(Exception):
    """The safety gate refused a request. No network call was made."""


@dataclass
class ScanContext:
    scope_host: str
    scope_port: int
    scope_path: str = "/"
    permission_confirmed: bool = False
    max_requests: int = field(default_factory=lambda: settings.max_requests_per_scan)
    requests_made: int = 0
    cancelled: bool = False
    lock: Any = field(default_factory=threading.Lock, repr=False)
    semaphore: Any = field(
        default_factory=lambda: asyncio.Semaphore(settings.max_concurrency),
        repr=False,
    )

    @classmethod
    def from_target(cls, target, permission_confirmed):
        return cls(
            scope_host=target["host"],
            scope_port=target["port"],
            scope_path=target["path"],
            permission_confirmed=permission_confirmed,
        )

    def budget(self):
        return min(self.max_requests, settings.max_requests_per_scan)


@dataclass
class GateResult:
    allowed: bool
    reason: str = ""
    ip: str = ""
    host: str = ""
    port: int = 0
    scheme: str = ""
    path: str = "/"
    query: str = ""


@dataclass
class GateResponse:
    status_code: int
    headers: dict
    body: bytes
    truncated: bool

    @property
    def text(self):
        return self.body.decode("utf-8", errors="replace")


def ip_block_reason(ip_text):
    try:
        ip = ipaddress.ip_address(ip_text.split("%")[0])
    except ValueError:
        return "invalid IP address"
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local or cloud metadata address"
    if ip.is_private:
        return "private address"
    if not ip.is_global:
        return "non-public address"
    return None


def default_resolver(host, port):
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _path_in_scope(path, scope_path):
    segments = unquote(path).split("/")
    if ".." in segments:
        return False
    base = scope_path.rstrip("/")
    return base == "" or path == base or path.startswith(base + "/")


def _block(reason, method="", host="", port=0, path=""):
    audit("request_blocked", reason=reason, method=method, host=host,
          port=port, path=path[:200])
    return GateResult(False, reason=reason)


def evaluate(ctx, method, url, resolver=default_resolver):
    method = (method or "").upper()

    # check 1: permission and scope confirmed
    if not ctx.permission_confirmed or not ctx.scope_host:
        return _block("permission or scope not confirmed", method)
    # check 7: scan not cancelled
    if ctx.cancelled:
        return _block("scan was cancelled", method)
    if method not in ALLOWED_METHODS:
        return _block("HTTP method not allowed", method)

    # check 2: URL valid, http/https, allowed port
    try:
        target = clean_target_url(url)
    except TargetError as e:
        return _block(str(e), method)
    host, port, path = target["host"], target["port"], target["path"]
    parts = urlsplit(url.strip())

    # check 4: host, port and path inside the approved scope
    if host.lower() != ctx.scope_host.lower():
        return _block("host is outside the approved scope", method, host, port, path)
    if port != ctx.scope_port:
        return _block("port is outside the approved scope", method, host, port, path)
    if not _path_in_scope(path, ctx.scope_path):
        return _block("path is outside the approved scope", method, host, port, path)

    # check 6: request budget
    if ctx.requests_made >= ctx.budget():
        return _block("request budget used up", method, host, port, path)

    # check 3: DNS result must be an allowed address
    try:
        ips = [host] if _is_ip(host) else resolver(host, port)
    except OSError:
        return _block("host name could not be resolved", method, host, port, path)
    if not ips:
        return _block("host name could not be resolved", method, host, port, path)
    for ip in ips:
        why = ip_block_reason(ip)
        lab_ok = (
            why == "loopback address"
            and settings.allow_lab_exception
            and port == settings.lab_port
        )
        if why and not lab_ok:
            return _block(why + " is not allowed", method, host, port, path)

    with ctx.lock:
        if ctx.requests_made >= ctx.budget():
            return _block("request budget used up", method, host, port, path)
        ctx.requests_made += 1

    return GateResult(True, ip=ips[0], host=host, port=port,
                      scheme=target["scheme"], path=path, query=parts.query)


async def _fetch(ctx, gate, method, headers, json_body, content):
    ip_host = "[" + gate.ip + "]" if ":" in gate.ip else gate.ip
    name = "[" + gate.host + "]" if ":" in gate.host else gate.host
    target = gate.scheme + "://" + ip_host + ":" + str(gate.port) + gate.path
    if gate.query:
        target += "?" + gate.query

    hdrs = {k: v for k, v in (headers or {}).items() if k.lower() != "host"}
    default_port = 443 if gate.scheme == "https" else 80
    hdrs["Host"] = name if gate.port == default_port else name + ":" + str(gate.port)
    extensions = {"sni_hostname": gate.host} if gate.scheme == "https" else {}

    async with ctx.semaphore:
        if ctx.cancelled:
            raise RequestBlocked("scan was cancelled")
        async with asyncio.timeout(settings.request_timeout_seconds):
            async with httpx.AsyncClient(
                timeout=settings.request_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(
                    method, target, headers=hdrs, json=json_body,
                    content=content, extensions=extensions,
                ) as resp:
                    body = bytearray()
                    truncated = False
                    async for chunk in resp.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > settings.max_response_bytes:
                            truncated = True
                            del body[settings.max_response_bytes:]
                            break
                    return GateResponse(resp.status_code, dict(resp.headers),
                                        bytes(body), truncated)


async def send_request(ctx, method, url, headers=None, json_body=None,
                       content=None, resolver=default_resolver,
                       auth=None, auth_variant="valid"):
    """The ONLY function that sends requests to a target."""
    current = url
    hops = 0
    while True:
        gate = await asyncio.to_thread(evaluate, ctx, method, current, resolver)
        if not gate.allowed:
            raise RequestBlocked(gate.reason)
        send_headers = auth.apply(headers, current, auth_variant) if auth else headers
        resp = await _fetch(ctx, gate, method, send_headers, json_body, content)
        location = resp.headers.get("location")
        if settings.follow_redirects and 300 <= resp.status_code < 400 and location:
            hops += 1
            if hops > MAX_REDIRECT_HOPS:
                raise RequestBlocked("too many redirects")
            current = urljoin(current, location)  # check 5: re-checked by the gate
            if resp.status_code in (301, 302, 303):
                method, json_body, content = "GET", None, None
            continue
        return resp
