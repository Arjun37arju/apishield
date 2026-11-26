import pytest

from app.core.url_validation import TargetError, clean_target_url


def test_good_https_url():
    r = clean_target_url("https://api.example.com/v1")
    assert r["host"] == "api.example.com"
    assert r["port"] == 443
    assert r["scope"] == "api.example.com:443"


def test_lab_port_allowed():
    r = clean_target_url("http://127.0.0.1:5000/api")
    assert r["port"] == 5000


@pytest.mark.parametrize("bad", [
    "",
    "   ",
    "ftp://example.com",
    "javascript:alert(1)",
    "file:///etc/passwd",
    "https://user:pass@example.com",
    "https://user@example.com",
    "https://example.com:6379",
    "https://example.com:99999",
    "https://exa mple.com",
    "https://",
])
def test_bad_urls_rejected(bad):
    with pytest.raises(TargetError):
        clean_target_url(bad)
