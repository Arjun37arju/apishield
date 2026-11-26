from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# INTENTIONALLY VULNERABLE. Fake data only. Run on 127.0.0.1 only.
app = FastAPI(title="APIShield Lab (intentionally vulnerable)", version="1.0")

# Planted weakness W7: CORS allows any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

USERS = {
    1: {"id": 1, "username": "alice", "role": "user", "password": "alice-pass",
        "password_hash": "fakehash-alice", "email": "alice@example.test"},
    2: {"id": 2, "username": "bob", "role": "user", "password": "bob-pass",
        "password_hash": "fakehash-bob", "email": "bob@example.test"},
    3: {"id": 3, "username": "admin", "role": "admin", "password": "admin-pass",
        "password_hash": "fakehash-admin", "email": "admin@example.test"},
}
TOKENS = {"lab-token-user-a": 1, "lab-token-user-b": 2, "lab-token-admin": 3}
LOGIN_TOKENS = {"alice": "lab-token-user-a", "bob": "lab-token-user-b",
                "admin": "lab-token-admin"}


def seed_orders():
    return {
        1: {"id": 1, "owner_id": 1, "item": "Laptop stand", "status": "paid", "total": 49.9},
        2: {"id": 2, "owner_id": 1, "item": "USB cable", "status": "shipped", "total": 9.5},
        3: {"id": 3, "owner_id": 2, "item": "Headphones", "status": "paid", "total": 89.0},
        4: {"id": 4, "owner_id": 2, "item": "Notebook", "status": "pending", "total": 4.2},
    }


ORDERS = seed_orders()


class Login(BaseModel):
    username: str
    password: str


class OrderPatch(BaseModel):
    status: str


def current_user(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed token")
    token = authorization[7:]
    if token == "lab-token-expired":
        raise HTTPException(status_code=401, detail="Token expired")
    uid = TOKENS.get(token)
    if uid is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    return USERS[uid]


# W6: no rate limit on login
@app.post("/api/login")
def login(body: Login):
    user = next((u for u in USERS.values() if u["username"] == body.username), None)
    if not user or user["password"] != body.password:
        raise HTTPException(status_code=401, detail="Wrong username or password")
    return {"token": LOGIN_TOKENS[user["username"]]}


# W9: returns password hash and plain password (sensitive data exposure)
@app.get("/api/users/me")
def me(authorization: str = Header(default=None)):
    return current_user(authorization)


@app.get("/api/orders")
def my_orders(authorization: str = Header(default=None)):
    user = current_user(authorization)
    return [o for o in ORDERS.values() if o["owner_id"] == user["id"]]


# W2: BOLA / IDOR - any logged-in user can read any order
@app.get("/api/orders/{order_id}")
def get_order(order_id: int, authorization: str = Header(default=None)):
    current_user(authorization)
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    return order


# W4: no owner check on write methods
@app.patch("/api/orders/{order_id}")
def patch_order(order_id: int, body: OrderPatch, authorization: str = Header(default=None)):
    current_user(authorization)
    order = ORDERS.get(order_id)
    if not order:
        raise HTTPException(status_code=404, detail="Order not found")
    order["status"] = body.status
    return order


@app.delete("/api/orders/{order_id}")
def delete_order(order_id: int, authorization: str = Header(default=None)):
    current_user(authorization)
    if order_id not in ORDERS:
        raise HTTPException(status_code=404, detail="Order not found")
    del ORDERS[order_id]
    return {"deleted": order_id}


# W3: weak role check - a normal user can list all users
@app.get("/api/admin/users")
def admin_users(authorization: str = Header(default=None)):
    current_user(authorization)
    return list(USERS.values())


# W1: missing authentication
@app.get("/api/internal/stats")
def internal_stats():
    return {"total_users": len(USERS), "total_orders": len(ORDERS), "revenue": 152.6}


# W5: verbose error with database details
@app.get("/api/search")
def search(q: str = ""):
    if "'" in q:
        raise HTTPException(
            status_code=500,
            detail="sqlite3.OperationalError: near \"'\": syntax error. Query: "
                   "SELECT * FROM products WHERE name LIKE '%" + q + "%' "
                   "(file /srv/lab/app/db.py, line 42)",
        )
    return {"query": q, "results": []}


@app.post("/lab/reset", include_in_schema=False)
def reset():
    ORDERS.clear()
    ORDERS.update(seed_orders())
    return {"reset": True}


import base64 as _b64

API_KEYS = {"lab-key-user-a": 1, "lab-key-user-b": 2}


@app.get("/api/basic/me")
def basic_me(authorization: str = Header(default=None)):
    if not authorization or not authorization.startswith("Basic "):
        raise HTTPException(status_code=401, detail="Missing Basic credentials")
    try:
        text = _b64.b64decode(authorization[6:]).decode()
        username, password = text.split(":", 1)
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed Basic credentials")
    user = next((u for u in USERS.values() if u["username"] == username), None)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Wrong username or password")
    return {"id": user["id"], "username": user["username"]}


@app.get("/api/key/me")
def key_me(x_api_key: str = Header(default=None)):
    uid = API_KEYS.get(x_api_key or "")
    if uid is None:
        raise HTTPException(status_code=401, detail="Missing or invalid API key")
    return {"id": uid, "username": USERS[uid]["username"]}


from fastapi import Form


@app.post("/api/oauth/token")
def oauth_token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    scope: str = Form(default="read"),
):
    if grant_type != "client_credentials":
        raise HTTPException(status_code=400, detail="unsupported_grant_type")
    if client_id != "lab-client" or client_secret != "lab-client-secret":
        raise HTTPException(status_code=401, detail="invalid_client")
    TOKENS["lab-oauth-read"] = 1
    return {"access_token": "lab-oauth-read", "token_type": "Bearer",
            "expires_in": 60, "scope": "read"}
