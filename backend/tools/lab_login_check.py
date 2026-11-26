import asyncio

from app.core.safety_gate import RequestBlocked, ScanContext, send_request
from app.core.settings import settings
from app.services.auth_providers import ApiKeyProvider, BasicAuthProvider

BASE = "http://127.0.0.1:" + str(settings.lab_port)


async def check(ctx, label, path, provider, variant):
    try:
        r = await send_request(ctx, "GET", BASE + path, auth=provider,
                               auth_variant=variant)
        print(label.ljust(20), r.status_code)
    except RequestBlocked as e:
        print(label.ljust(20), "BLOCKED:", e)


async def main():
    ctx = ScanContext(scope_host="127.0.0.1", scope_port=settings.lab_port,
                      scope_path="/", permission_confirmed=True)
    basic = BasicAuthProvider("alice", "alice-pass")
    key = ApiKeyProvider("lab-key-user-a")
    for variant in ("none", "wrong", "valid"):
        await check(ctx, "basic / " + variant, "/api/basic/me", basic, variant)
    for variant in ("none", "wrong", "valid"):
        await check(ctx, "api key / " + variant, "/api/key/me", key, variant)


asyncio.run(main())
