import base64
import json
import time
from typing import List, Optional
from urllib.parse import urlencode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .errors import AuthenticationError
from .jwks import JwksClient
from .types import SerafortConfig, UserContext


def base64url_decode(val: str) -> bytes:
    padded = val + "=" * ((4 - len(val) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))

class B2BModule:
    def __init__(self, config: SerafortConfig, jwks_client: Optional[JwksClient] = None):
        self.config = config
        self.jwks_client = jwks_client or JwksClient(config)
        self.base_url = config.endpoint.rstrip("/")

    def validate_token(
        self,
        token: str,
        expected_issuer: Optional[str] = None,
        expected_audience: Optional[str] = None,
        clock_tolerance_seconds: int = 60,
        skip_signature_check: bool = False,
    ) -> UserContext:
        """Synchronously validates a JWT token locally, verifying signature against cached JWKS."""
        header, payload, sig_bytes, signing_input = self._parse_jwt(token)
        self._verify_claims(payload, expected_issuer, expected_audience, clock_tolerance_seconds)

        if not skip_signature_check:
            pub_key = self.jwks_client.get_public_key(header.get("kid"))
            self._verify_signature(pub_key, signing_input, sig_bytes)

        return self._map_to_user_context(payload)

    async def avalidate_token(
        self,
        token: str,
        expected_issuer: Optional[str] = None,
        expected_audience: Optional[str] = None,
        clock_tolerance_seconds: int = 60,
        skip_signature_check: bool = False,
    ) -> UserContext:
        """Asynchronously validates a JWT token locally, verifying signature against cached JWKS."""
        header, payload, sig_bytes, signing_input = self._parse_jwt(token)
        self._verify_claims(payload, expected_issuer, expected_audience, clock_tolerance_seconds)

        if not skip_signature_check:
            pub_key = await self.jwks_client.aget_public_key(header.get("kid"))
            self._verify_signature(pub_key, signing_input, sig_bytes)

        return self._map_to_user_context(payload)

    def has_permission(self, user: UserContext, required_permission: str) -> bool:
        """Checks if the user possesses a specific permission, supporting wildcard patterns (e.g. 'org:*')."""
        if not user or not user.permissions:
            return False

        for perm in user.permissions:
            if perm == "*" or perm == required_permission:
                return True
            if perm.endswith(":*"):
                prefix = perm[:-2]
                if required_permission.startswith(prefix):
                    return True
        return False

    def has_role(self, user: UserContext, role: str) -> bool:
        """Checks if the user has a specific role assigned."""
        return bool(user and role in user.roles)

    def get_login_url(self, tenant_id: str, redirect_uri: str, state: Optional[str] = None) -> str:
        """Constructs the Enterprise SSO Login URL."""
        params = {
            "tenant_id": tenant_id,
            "redirect_uri": redirect_uri,
        }
        if state:
            params["state"] = state
        return f"{self.base_url}/api/auth/sso/login?{urlencode(params)}"

    def _parse_jwt(self, token: str):
        parts = token.split(".")
        if len(parts) != 3:
            raise AuthenticationError("Invalid JWT: token must contain exactly 3 dot-separated parts")

        try:
            header_json = base64url_decode(parts[0]).decode("utf-8")
            header = json.loads(header_json)

            payload_json = base64url_decode(parts[1]).decode("utf-8")
            payload = json.loads(payload_json)

            sig_bytes = base64url_decode(parts[2])
            signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")

            return header, payload, sig_bytes, signing_input
        except Exception as e:
            raise AuthenticationError(f"Failed to parse JWT: {str(e)}")

    def _verify_claims(self, payload: dict, expected_issuer: Optional[str], expected_audience: Optional[str], clock_tolerance: int):
        now = time.time()

        if "exp" in payload:
            exp = float(payload["exp"])
            if now > exp + clock_tolerance:
                raise AuthenticationError("Token has expired")

        if "nbf" in payload:
            nbf = float(payload["nbf"])
            if now < nbf - clock_tolerance:
                raise AuthenticationError("Token not yet valid")

        iss = expected_issuer or self.base_url
        if iss and "iss" in payload and payload["iss"] != iss:
            raise AuthenticationError(f"Invalid token issuer: expected '{iss}', got '{payload['iss']}'")

        if expected_audience and "aud" in payload:
            auds = payload["aud"] if isinstance(payload["aud"], list) else [payload["aud"]]
            if expected_audience not in auds:
                raise AuthenticationError(f"Invalid token audience: expected '{expected_audience}'")

    def _verify_signature(self, pub_key, signing_input: bytes, sig_bytes: bytes):
        try:
            pub_key.verify(sig_bytes, signing_input, padding.PKCS1v15(), hashes.SHA256())
        except Exception as e:
            raise AuthenticationError(f"JWT signature verification failed: {str(e)}")

    def _map_to_user_context(self, claims: dict) -> UserContext:
        user_id = str(claims.get("sub") or claims.get("id") or claims.get("user_id") or "")
        tenant_id = str(
            claims.get("tenant_id")
            or claims.get("org_id")
            or claims.get("tid")
            or claims.get("app_metadata", {}).get("tenant_id", "")
        )
        email = claims.get("email")

        roles: List[str] = []
        if isinstance(claims.get("roles"), list):
            roles = [str(r) for r in claims["roles"]]
        elif isinstance(claims.get("role"), str):
            roles = [claims["role"]]

        permissions: List[str] = []
        if isinstance(claims.get("permissions"), list):
            permissions = [str(p) for p in claims["permissions"]]
        elif isinstance(claims.get("scope"), str):
            permissions = claims["scope"].split()

        return UserContext(
            user_id=user_id,
            tenant_id=tenant_id,
            email=email,
            roles=roles,
            permissions=permissions,
            claims=claims,
        )
