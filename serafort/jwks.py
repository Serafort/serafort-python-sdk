import base64
import time
from threading import Lock
from typing import Any, Dict, Optional

import httpx
from cryptography.hazmat.primitives.asymmetric import rsa

from .errors import AuthenticationError, NetworkError
from .types import JWKS, SerafortConfig


def base64url_to_int(val: str) -> int:
    padded = val + "=" * ((4 - len(val) % 4) % 4)
    data = base64.urlsafe_b64decode(padded.encode("ascii"))
    return int.from_bytes(data, byteorder="big")

class JwksClient:
    def __init__(self, config: SerafortConfig, cache_ttl_seconds: int = 3600):
        self.config = config
        self.jwks_url = f"{config.endpoint.rstrip('/')}/.well-known/jwks.json"
        self._keys: Dict[str, Any] = {}
        self._fetched_at: float = 0.0
        self._ttl = cache_ttl_seconds
        self._lock = Lock()
        self._sync_client = httpx.Client(timeout=config.timeout_seconds)
        self._async_client: Optional[httpx.AsyncClient] = None

    def get_public_key(self, kid: Optional[str] = None) -> Any:
        with self._lock:
            if self._keys and time.time() - self._fetched_at < self._ttl:
                if kid and kid in self._keys:
                    return self._keys[kid]
                if not kid and len(self._keys) == 1:
                    return next(iter(self._keys.values()))

        self._refresh_sync()

        with self._lock:
            if kid and kid in self._keys:
                return self._keys[kid]
            if not kid and self._keys:
                return next(iter(self._keys.values()))

        raise AuthenticationError(f"Public key for kid '{kid or 'default'}' not found in JWKS")

    async def aget_public_key(self, kid: Optional[str] = None) -> Any:
        with self._lock:
            if self._keys and time.time() - self._fetched_at < self._ttl:
                if kid and kid in self._keys:
                    return self._keys[kid]
                if not kid and len(self._keys) == 1:
                    return next(iter(self._keys.values()))

        await self._refresh_async()

        with self._lock:
            if kid and kid in self._keys:
                return self._keys[kid]
            if not kid and self._keys:
                return next(iter(self._keys.values()))

        raise AuthenticationError(f"Public key for kid '{kid or 'default'}' not found in JWKS")

    def _refresh_sync(self):
        try:
            resp = self._sync_client.get(self.jwks_url, headers={"Accept": "application/json"})
        except Exception as e:
            raise NetworkError(f"Failed to fetch JWKS from {self.jwks_url}", cause=e)

        if resp.status_code != 200:
            raise AuthenticationError(f"JWKS endpoint returned status {resp.status_code}")

        self._process_jwks(resp.json())

    async def _refresh_async(self):
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(timeout=self.config.timeout_seconds)

        try:
            resp = await self._async_client.get(self.jwks_url, headers={"Accept": "application/json"})
        except Exception as e:
            raise NetworkError(f"Failed to fetch JWKS from {self.jwks_url}", cause=e)

        if resp.status_code != 200:
            raise AuthenticationError(f"JWKS endpoint returned status {resp.status_code}")

        self._process_jwks(resp.json())

    def _process_jwks(self, data: dict):
        jwks = JWKS(**data)
        new_keys: Dict[str, Any] = {}

        for key in jwks.keys:
            if key.kty == "RSA" and key.n and key.e and key.kid:
                try:
                    n = base64url_to_int(key.n)
                    e = base64url_to_int(key.e)
                    pub_key = rsa.RSAPublicNumbers(e, n).public_key()
                    new_keys[key.kid] = pub_key
                except Exception:
                    pass

        with self._lock:
            self._keys = new_keys
            self._fetched_at = time.time()
