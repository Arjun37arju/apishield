import pytest

from app.core.settings import settings


@pytest.fixture(autouse=True)
def lab_exception_off_by_default(monkeypatch):
    """Tests never depend on the developer's .env file.
    A test that needs the lab exception turns it on itself."""
    monkeypatch.setattr(settings, "allow_lab_exception", False)
