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

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Per-IP ceilings are process-global, so one test's traffic must not spend
    another's budget (see mxtng_auth.ratelimit)."""
    from mxtng_auth.ratelimit import limiter

    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture
def outbox(monkeypatch):
    """Capture what would be mailed.

    Shared because sign-in now *always* goes through the emailed Sign-in Code
    (SECURITY_AUDIT C-2) — there is no single-step login left to test against.
    """
    from mxtng_auth import mail

    sent = []

    async def _fake_send(*, to_email, message, purpose, mode):
        sent.append(
            {
                "to": to_email,
                "subject": message.subject,
                "text": message.text_body,
                "purpose": purpose,
                "mode": mode,
            }
        )
        return "relay"

    monkeypatch.setattr(mail, "send", _fake_send)
    return sent


def code_from(entry) -> str:
    """Pull the Sign-in Code out of a captured message body."""
    from mxtng_auth.settings import settings

    for token in entry["text"].split():
        stripped = token.strip(".,")
        if stripped.isdigit() and len(stripped) == settings.OTP_CODE_LENGTH:
            return stripped
    raise AssertionError(f"No code in mail body: {entry['text']!r}")


async def sign_in(client, outbox, *, email: str, password: str):
    """Complete a full two-step sign-in and return the /login/verify response."""
    before = len(outbox)
    challenge = await client.post(
        "/v1/login/challenge", json={"email": email, "password": password}
    )
    assert challenge.status_code == 202, challenge.text
    response = await client.post(
        "/v1/login/verify",
        json={
            "challenge_id": challenge.json()["challenge_id"],
            "code": code_from(outbox[before]),
        },
    )
    assert response.status_code == 200, response.text
    return response


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
