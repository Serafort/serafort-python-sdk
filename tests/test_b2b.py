import base64
import json
import time

import pytest

from serafort.b2b import B2BModule
from serafort.errors import AuthenticationError
from serafort.types import SerafortConfig


def create_mock_jwt(header: dict, payload: dict) -> str:
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig_b64 = base64.urlsafe_b64encode(b"valid_mock_signature_bytes").decode().rstrip("=")
    return f"{h_b64}.{p_b64}.{sig_b64}"

def test_validate_token_claims_and_rbac():
    config = SerafortConfig(endpoint="https://auth.acme.com")
    b2b = B2BModule(config)

    now = time.time()
    token = create_mock_jwt(
        {"alg": "RS256", "kid": "k1"},
        {
            "sub": "usr_python_123",
            "tenant_id": "ten_enterprise",
            "email": "py_dev@acme.com",
            "roles": ["admin", "engineer"],
            "permissions": ["org:read", "org:write", "analytics:*"],
            "iss": "https://auth.acme.com",
            "exp": now + 3600,
        }
    )

    user = b2b.validate_token(token, skip_signature_check=True)
    assert user.user_id == "usr_python_123"
    assert user.tenant_id == "ten_enterprise"
    assert user.email == "py_dev@acme.com"
    assert "admin" in user.roles

    # RBAC permissions
    assert b2b.has_permission(user, "org:read") is True
    assert b2b.has_permission(user, "analytics:view") is True # wildcard
    assert b2b.has_permission(user, "billing:delete") is False

    # Roles
    assert b2b.has_role(user, "engineer") is True
    assert b2b.has_role(user, "billing_admin") is False

def test_validate_token_expired():
    config = SerafortConfig(endpoint="https://auth.acme.com")
    b2b = B2BModule(config)

    now = time.time()
    expired_token = create_mock_jwt(
        {"alg": "RS256"},
        {
            "sub": "usr_expired",
            "exp": now - 300,
        }
    )

    with pytest.raises(AuthenticationError) as exc_info:
        b2b.validate_token(expired_token, clock_tolerance_seconds=10, skip_signature_check=True)
    assert "expired" in str(exc_info.value).lower()
