from app.scanner.auth_checks import auth_registry
from app.scanner.authorization import AUTHZ_CHECKS
from app.scanner.config_checks import CONFIG_CHECKS
from app.scanner.input_checks import INPUT_CHECKS
from app.scanner.rate_checks import RATE_CHECKS


def full_registry():
    """All 24 real checks: A (authentication), B (authorization), C (input),
    D (rate limit), E (security configuration)."""
    registry = dict(auth_registry())
    for check in [*AUTHZ_CHECKS, *INPUT_CHECKS, *RATE_CHECKS, *CONFIG_CHECKS]:
        registry[check.id] = check
    return registry