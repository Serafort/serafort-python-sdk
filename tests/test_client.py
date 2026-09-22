from serafort import SerafortClient


def test_serafort_client_init():
    client = SerafortClient({
        "endpoint": "https://auth.acme.com",
        "client_id": "test_id",
        "client_secret": "test_secret",
    })

    assert client.config.endpoint == "https://auth.acme.com"
    assert client.config.client_id == "test_id"
    assert client.m2m is not None
    assert client.b2b is not None

def test_login_url_generation():
    client = SerafortClient({
        "endpoint": "https://auth.acme.com",
    })

    url = client.get_login_url("ten_123", "https://app.acme.com/callback", state="csrf_state")
    assert "https://auth.acme.com/api/auth/sso/login?" in url
    assert "tenant_id=ten_123" in url
    assert "redirect_uri=https%3A%2F%2Fapp.acme.com%2Fcallback" in url
    assert "state=csrf_state" in url
