# Serafort Python SDK (`serafort-sdk`)

Official Python client library for the Serafort identity platform. High-performance, concurrency-safe Machine Identity (M2M) caching and local B2B JWT validation supporting both synchronous and asynchronous operations.

## Installation

```bash
pip install serafort-sdk
```

## Quickstart

### Synchronous Usage

```python
from serafort import SerafortClient

client = SerafortClient({
    "endpoint": "https://auth.acme.com",
    "client_id": "my-client-id",
    "client_secret": "my-client-secret",
})

# 1. Retrieve M2M access token (cached, proactive 5-min refresh)
token = client.get_access_token(["read:users"])

# 2. Local JWT token validation & RBAC (zero network hops)
user = client.validate_token(token)
print(f"Authenticated user: {user.user_id} in tenant {user.tenant_id}")

if client.has_permission(user, "org:write"):
    print("Permission granted!")
```

### Asynchronous Usage (`async`/`await`)

```python
import asyncio
from serafort import SerafortClient

async def main():
    client = SerafortClient({
        "endpoint": "https://auth.acme.com",
        "client_id": "my-client-id",
        "client_secret": "my-client-secret",
    })

    token = await client.aget_access_token(["read:users"])
    user = await client.avalidate_token(token)
    print(user)

asyncio.run(main())
```

## Contributing

### Setup

This project uses [Poetry](https://python-poetry.org/) for dependency management.

```bash
pip install poetry
poetry install --with dev
```

### Running checks

```bash
poetry run ruff check .      # Lint
poetry run mypy serafort/    # Type check
poetry run pytest            # Tests
```

### Git hooks

Enable the repo's git hooks once per clone:

```bash
git config core.hooksPath .githooks
```

This runs `ruff`, `mypy`, and `pytest` before each commit (see
`.githooks/pre-commit`). There's no `.husky/` directory here — Husky is an
npm package for JavaScript/TypeScript repos, and this is a pure-Python
package with no Node.js toolchain. `.githooks/` + `git config
core.hooksPath` is the native git mechanism for hooks and needs nothing
beyond git itself plus the Python tooling above.

The same three checks run in CI on every push and pull request against
`main` (see `.github/workflows/ci.yml`), across Python 3.10 and 3.12.
