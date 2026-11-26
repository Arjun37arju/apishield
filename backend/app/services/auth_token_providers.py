import json
import time
from urllib.parse import urlencode, urlsplit

from app.core.safety_gate import default_resolver, send_request
from app.services.auth_providers import (
    AuthError,
    AuthProvider,
    _clean,
    _lab_http_allowed,
)

BEARER_VARIANTS = ("valid", "none", "wrong", "expired", "malformed")
SKEW_SECONDS = 10


def _tamper(token):
    """Make a well-formed but invalid token (bad signature for a JWT)."""
    if token.count(".") == 2:
        head, sig = token.rsplit(".", 1)
        if sig:
            last = "A" if sig[-1] != "A" else "B"
            return head + "." + sig[:-1] + last
    return "invalid-token"


class _BearerBase(AuthProvider):
    def __init__(self, expired_token=None):
        self._expired = _clean(expired_token, "expired token") if expired_token else None

    def _current_token(self):
        raise NotImplementedError

    def apply(self, headers, url, variant="valid"):
        if variant not in BEARER_VARIANTS:
            raise AuthError("unknown variant")
        out = dict(headers or {})
        if variant == "none":
            return out
        if urlsplit(url).scheme != "https" and not _lab_http_allowed(url):
            raise AuthError("Tokens are only sent over HTTPS")
        if variant == "expired":
            if not self._expired:
                raise AuthError("no expired token was supplied")
            token = self._expired
        elif variant == "malformed":
            token = "!!malformed!!"
        else:
            real = self._current_token()
            token = real if variant == "valid" else _tamper(real)
        out["Authorization"] = "Bearer " + token
        return out


class BearerTokenProvider(_BearerBase):
    name = "bearer"

    def __init__(self, token, expired_token=None):
        super().__init__(expired_token)
        self._token = _clean(token, "token")

    def _current_token(self):
        return self._token


class OAuthClientCredentialsProvider(_BearerBase):
    """OAuth 2.0 client credentials flow only. Use a least-privilege test client."""

    name = "oauth2_client_credentials"

    def __init__(self, token_url, client_id, client_secret, scope="",
                 expired_token=None):
        super().__init__(expired_token)
        self._token_url = _clean(token_url, "token URL")
        self._client_id = _clean(client_id, "client id")
        self._client_secret = _clean(client_secret, "client secret")
        self._scope = str(scope or "").strip()
        if any(ord(c) < 32 or ord(c) == 127 for c in self._scope):
            raise AuthError("scope has control characters")
        self._access_token = None
        self._expires_at = 0.0
        self.granted_scope = ""

    def _current_token(self):
        if not self._access_token:
            raise AuthError("no access token yet: call prepare() first")
        return self._access_token

    def needs_token(self):
        return (not self._access_token
                or time.monotonic() >= self._expires_at - SKEW_SECONDS)

    async def prepare(self, ctx, resolver=default_resolver):
        """Get (or renew) the access token. The request goes through the gate."""
        if not self.needs_token():
            return
        if urlsplit(self._token_url).scheme != "https" and not _lab_http_allowed(self._token_url):
            raise AuthError("The token endpoint must use HTTPS")
        form = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if self._scope:
            form["scope"] = self._scope
        resp = await send_request(
            ctx, "POST", self._token_url,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"},
            content=urlencode(form),
            resolver=resolver,
        )
        if resp.status_code != 200:
            raise AuthError("token request failed with status " + str(resp.status_code))
        if resp.truncated:
            raise AuthError("token response is too large")
        try:
            data = json.loads(resp.body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise AuthError("token response is not valid JSON")
        if not isinstance(data, dict) or not isinstance(data.get("access_token"), str):
            raise AuthError("token response has no access_token")
        token = _clean(data["access_token"], "access token")
        if str(data.get("token_type", "")).lower() != "bearer":
            raise AuthError("unsupported token type")
        try:
            expires_in = int(data.get("expires_in", 300))
        except (TypeError, ValueError):
            expires_in = 300
        expires_in = max(1, min(expires_in, 86400))
        self._access_token = token
        self._expires_at = time.monotonic() + expires_in
        self.granted_scope = str(data.get("scope", ""))[:200]
