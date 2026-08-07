"""Test harness: isolated temp DB + signing key, ASGI client with lifespan replicated.

Env is set BEFORE importing the app so the settings singleton and the engine pick
up the temp paths.
"""
import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="mxtng-auth-test-")
os.environ["ENVIRONMENT"] = "test"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_TMP}/auth.db"
os.environ["PRIVATE_KEY_PATH"] = f"{_TMP}/signing_key.pem"
os.environ["REFRESH_COOKIE_SECURE"] = "false"
os.environ["ISSUER"] = "http://localhost:8100"
os.environ["DEFAULT_AUDIENCE"] = "ats"
os.environ["MAX_FAILED_LOGINS"] = "3"

import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402


@pytest_asyncio.fixture
async def client():
    # Import after env is set.
    from mxtng_auth import models  # noqa: F401  (register tables)
    from mxtng_auth.db import Base, engine
    from mxtng_auth.main import app
    from mxtng_auth.signer import get_signer

    get_signer()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
