from typing import List, Optional, Union

from .b2b import B2BModule
from .m2m import M2MModule
from .types import SerafortConfig, UserContext


class SerafortClient:
    """Unified Serafort Python Client."""
    def __init__(self, config: Union[SerafortConfig, dict]):
        if isinstance(config, dict):
            self.config = SerafortConfig(**config)
        else:
            self.config = config

        self.m2m = M2MModule(self.config)
        self.b2b = B2BModule(self.config)

    def get_access_token(self, scopes: Optional[List[str]] = None) -> str:
        """Retrieves an M2M access token synchronously from cache or fetches a new one."""
        return self.m2m.get_access_token(scopes)

    async def aget_access_token(self, scopes: Optional[List[str]] = None) -> str:
        """Retrieves an M2M access token asynchronously from cache or fetches a new one."""
        return await self.m2m.aget_access_token(scopes)

    def validate_token(self, token: str, **kwargs) -> UserContext:
        """Synchronously validates a JWT token locally and decodes its UserContext."""
        return self.b2b.validate_token(token, **kwargs)

    async def avalidate_token(self, token: str, **kwargs) -> UserContext:
        """Asynchronously validates a JWT token locally and decodes its UserContext."""
        return await self.b2b.avalidate_token(token, **kwargs)

    def has_permission(self, user: UserContext, required: str) -> bool:
        """Evaluates whether the user context possesses the specified permission (with wildcards)."""
        return self.b2b.has_permission(user, required)

    def has_role(self, user: UserContext, role: str) -> bool:
        """Evaluates whether the user context has the specified role."""
        return self.b2b.has_role(user, role)

    def get_login_url(self, tenant_id: str, redirect_uri: str, state: Optional[str] = None) -> str:
        """Constructs the Enterprise SSO Login URL."""
        return self.b2b.get_login_url(tenant_id, redirect_uri, state=state)
