from serafort.m2m import M2MModule, TokenCache
from serafort.types import SerafortConfig


def test_token_cache_valid_and_proactive():
    cache = TokenCache(buffer_seconds=300) # 5 min buffer

    # Valid token expiring in 10 minutes -> Cache hit
    cache.set("key_1", "tok_valid", expires_in_seconds=600)
    assert cache.get("key_1") == "tok_valid"

    # Token expiring in 2 minutes (< 5 min buffer) -> Cache miss (needs proactive refresh)
    cache.set("key_2", "tok_nearing_exp", expires_in_seconds=120)
    assert cache.get("key_2") is None

def test_m2m_get_access_token_with_cache(monkeypatch):
    config = SerafortConfig(
        endpoint="https://auth.acme.com",
        client_id="test_client",
        client_secret="test_secret",
    )
    mod = M2MModule(config)

    calls = 0
    def mock_fetch(cache_key, scope):
        nonlocal calls
        calls += 1
        mod.cache.set(cache_key, "fetched_token_xyz", 3600)
        return "fetched_token_xyz"

    monkeypatch.setattr(mod, "_fetch_token_sync_with_retry", mock_fetch)

    # First call: hits fetcher
    tok1 = mod.get_access_token(["read:users"])
    assert tok1 == "fetched_token_xyz"
    assert calls == 1

    # Second call: hits cache
    tok2 = mod.get_access_token(["read:users"])
    assert tok2 == "fetched_token_xyz"
    assert calls == 1

    # Force refresh: bypasses cache
    tok3 = mod.force_refresh_token(["read:users"])
    assert tok3 == "fetched_token_xyz"
    assert calls == 2
