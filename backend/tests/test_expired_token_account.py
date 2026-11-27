from app.api.scans import _user_accounts

URL = "https://example.test/api/users/me"


def _accounts():
    return _user_accounts({
        "user_a": {"type": "bearer", "token": "token-user-a-123",
                   "expired_token": "token-expired-123"},
        "user_b": {"type": "bearer", "token": "token-user-b-123"},
    })


def test_expired_account_sends_the_expired_token():
    headers = _accounts()["expired_token"].apply({}, URL)
    assert headers["Authorization"] == "Bearer token-expired-123"


def test_expired_account_never_sends_the_valid_token():
    headers = _accounts()["expired_token"].apply({}, URL)
    assert "token-user-a-123" not in headers["Authorization"]


def test_user_a_still_sends_the_valid_token():
    headers = _accounts()["user_a"].apply({}, URL)
    assert headers["Authorization"] == "Bearer token-user-a-123"


def test_no_expired_account_without_an_expired_token():
    accounts = _user_accounts({
        "user_a": {"type": "bearer", "token": "token-user-a-123"},
    })
    assert "expired_token" not in accounts
