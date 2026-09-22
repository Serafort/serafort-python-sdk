import asyncio
import math
import random
import time
from threading import Lock
from typing import Dict, List, Optional

import httpx

from .errors import AuthenticationError, NetworkError, RateLimitError, SerafortError
from .types import OAuthTokenResponse, SerafortConfig


class CachedToken:
    def __init__(self, access_token: str, expires_at: float, scope: Optional[str] = None):
        self.access_token = access_token
        self.expires_at = expires_at
        self.scope = scope

class TokenCache:
    def __init__(self, buffer_seconds: int = 300):
        self._lock = Lock()
        self._tokens: Dict[str, CachedToken] = {}
        self.buffer_seconds = buffer_seconds

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            item = self._tokens.get(key)
            if not item:
                return None
            if time.time() + self.buffer_seconds > item.expires_at:
                return None
            return item.access_token

    def set(self, key: str, token: str, expires_in_seconds: int, scope: Optional[str] = None):
        with self._lock:
            expires_at = time.time() + expires_in_seconds
            self._tokens[key] = CachedToken(token, expires_at, scope)

    def invalidate(self, key: Optional[str] = None):
        with self._lock:
            if key:
                self._tokens.pop(key, None)
            else:
                self._tokens.clear()

class M2MModule:
    def __init__(self, config: SerafortConfig, cache: Optional[TokenCache] = None):
        self.config = config
        self.cache = cache or TokenCache()
        self.base_url = config.endpoint.rstrip("/")
        self._sync_client = httpx.Client(timeout=config.timeout_seconds)
        self._async_client: Optional[httpx.AsyncClient] = None
        self._flight_lock = Lock()
        self._in_flight: Dict[str, str] = {}

    def get_access_token(self, scopes: Optional[List[str]] = None) -> str:
        """Retrieves an M2M access token synchronously from cache or fetches a new one."""
        return self._get_token_sync(scopes=scopes, force=False)

    def force_refresh_token(self, scopes: Optional[List[str]] = None) -> str:
        """Forces a synchronous refresh of the access token, bypassing the cache."""
        return self._get_token_sync(scopes=scopes, force=True)

    async def aget_access_token(self, scopes: Optional[List[str]] = None) -> str:
        """Retrieves an M2M access token asynchronously from cache or fetches a new one."""
        return await self._get_token_async(scopes=scopes, force=False)

    async def aforce_refresh_token(self, scopes: Optional[List[str]] = None) -> str:
        """Forces an asynchronous refresh of the access token, bypassing the cache."""
        return await self._get_token_async(scopes=scopes, force=True)

    def _get_cache_key(self, scopes: Optional[List[str]]) -> str:
        sorted_scopes = " ".join(sorted(scopes)) if scopes else ""
        return f"{self.config.client_id or 'default'}:{sorted_scopes}"

    def _get_token_sync(self, scopes: Optional[List[str]], force: bool) -> str:
        cache_key = self._get_cache_key(scopes)
        if not force:
            token = self.cache.get(cache_key)
            if token:
                return token

        scope_str = " ".join(sorted(scopes)) if scopes else None
        return self._fetch_token_sync_with_retry(cache_key, scope_str)

    async def _get_token_async(self, scopes: Optional[List[str]], force: bool) -> str:
        cache_key = self._get_cache_key(scopes)
        if not force:
            token = self.cache.get(cache_key)
            if token:
                return token

        scope_str = " ".join(sorted(scopes)) if scopes else None
        return await self._fetch_token_async_with_retry(cache_key, scope_str)

    def _fetch_token_sync_with_retry(self, cache_key: str, scope: Optional[str]) -> str:
        retry_cfg = self.config.retry_policy
        token_url = f"{self.base_url}/oauth/token"

        data = {
            "grant_type": "client_credentials",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        if scope:
            data["scope"] = scope

        for attempt in range(retry_cfg.max_retries + 1):
            if attempt > 0:
                delay = (retry_cfg.initial_delay_ms / 1000.0) * math.pow(2, attempt - 1)
                jitter = delay * (0.8 + random.random() * 0.4)
                capped_delay = min(jitter, retry_cfg.max_delay_ms / 1000.0)
                time.sleep(capped_delay)

            try:
                resp = self._sync_client.post(
                    token_url,
                    data=data,
                    headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
                )
            except Exception as e:
                if attempt == retry_cfg.max_retries:
                    raise NetworkError(f"Network error connecting to {token_url}", cause=e)
                continue

            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt == retry_cfg.max_retries:
                    raise RateLimitError("Rate limit exceeded") if resp.status_code == 429 else SerafortError(f"Server error {resp.status_code}", status=resp.status_code)
                continue

            if resp.status_code != 200:
                raise AuthenticationError(f"OAuth request failed with status {resp.status_code}: {resp.text}", status=resp.status_code)

            payload = OAuthTokenResponse(**resp.json())
            self.cache.set(cache_key, payload.access_token, payload.expires_in, scope)
            return payload.access_token

        raise SerafortError("Failed to fetch access token after retries")

    async def _fetch_token_async_with_retry(self, cache_key: str, scope: Optional[str]) -> str:
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(timeout=self.config.timeout_seconds)

        retry_cfg = self.config.retry_policy
        token_url = f"{self.base_url}/oauth/token"

        data = {
            "grant_type": "client_credentials",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        if scope:
            data["scope"] = scope

        for attempt in range(retry_cfg.max_retries + 1):
            if attempt > 0:
                delay = (retry_cfg.initial_delay_ms / 1000.0) * math.pow(2, attempt - 1)
                jitter = delay * (0.8 + random.random() * 0.4)
                capped_delay = min(jitter, retry_cfg.max_delay_ms / 1000.0)
                await asyncio.sleep(capped_delay)

            try:
                resp = await self._async_client.post(
                    token_url,
                    data=data,
                    headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
                )
            except Exception as e:
                if attempt == retry_cfg.max_retries:
                    raise NetworkError(f"Network error connecting to {token_url}", cause=e)
                continue

            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt == retry_cfg.max_retries:
                    raise RateLimitError("Rate limit exceeded") if resp.status_code == 429 else SerafortError(f"Server error {resp.status_code}", status=resp.status_code)
                continue

            if resp.status_code != 200:
                raise AuthenticationError(f"OAuth request failed with status {resp.status_code}: {resp.text}", status=resp.status_code)

            payload = OAuthTokenResponse(**resp.json())
            self.cache.set(cache_key, payload.access_token, payload.expires_in, scope)
            return payload.access_token

        raise SerafortError("Failed to fetch access token after retries")
