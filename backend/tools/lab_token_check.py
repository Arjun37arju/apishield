import asyncio

from app.core.safety_gate import RequestBlocked, ScanContext, send_request
from app.core.settings import settings
from app.services.auth_providers import AuthError
from app.services.auth_token_providers import (
    BearerTokenProvider,
    OAuthClientCredentialsProvider,
)

BASE = "http://127.0.0.1:" + str(settings.lab_port)


async def check(ctx, label, provider, variant):
    try:
        r = await send_request(ctx, "GET", BASE + "/api/orders",
                               auth=provider, auth_variant=variant)
        print(label.ljust(22), r.status_code)
    except (RequestBlocked, AuthError) as e:
        print(label.ljust(22), "ERROR:", e)


async def main():
    ctx = ScanContext(scope_host="127.0.0.1", scope_port=settings.lab_port,
                      scope_path="/", permission_confirmed=True)

    bearer = BearerTokenProvider("lab-token-user-a", expired_token="lab-token-expired")
    for v in ("none", "wrong", "expired", "malformed", "valid"):
        await check(ctx, "bearer / " + v, bearer, v)

    oauth = OAuthClientCredentialsProvider(
        BASE + "/api/oauth/token", "lab-client", "lab-client-secret",
        scope="read", expired_token="lab-token-expired")
    await oauth.prepare(ctx)
    print("oauth granted scope:".ljust(22), oauth.granted_scope)
    for v in ("none", "wrong", "expired", "valid"):
        await check(ctx, "oauth / " + v, oauth, v)

    bad = OAuthClientCredentialsProvider(
        BASE + "/api/oauth/token", "lab-client", "wrong-secret")
    try:
        await bad.prepare(ctx)
    except AuthError as e:
        print("oauth wrong secret:".ljust(22), e)


asyncio.run(main())
