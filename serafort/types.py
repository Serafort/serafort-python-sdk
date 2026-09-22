from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class RetryConfig(BaseModel):
    max_retries: int = Field(default=3, description="Maximum retry attempts")
    initial_delay_ms: int = Field(default=500, description="Initial retry delay in milliseconds")
    max_delay_ms: int = Field(default=5000, description="Maximum retry delay in milliseconds")

class SerafortConfig(BaseModel):
    endpoint: str = Field(description="Base URL of Serafort IAM backend")
    client_id: Optional[str] = Field(default=None, description="Client ID for M2M authentication")
    client_secret: Optional[str] = Field(default=None, description="Client secret for M2M authentication")
    publishable_key: Optional[str] = Field(default=None, description="Publishable key for public B2B flows")
    timeout_seconds: float = Field(default=10.0, description="HTTP request timeout")
    retry_policy: RetryConfig = Field(default_factory=RetryConfig)

class UserContext(BaseModel):
    user_id: str
    tenant_id: str
    email: Optional[str] = None
    roles: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    claims: Dict[str, Any] = Field(default_factory=dict)

class OAuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    scope: Optional[str] = None

class JWK(BaseModel):
    kty: str
    kid: Optional[str] = None
    use: Optional[str] = None
    alg: Optional[str] = None
    n: Optional[str] = None
    e: Optional[str] = None

class JWKS(BaseModel):
    keys: List[JWK]
