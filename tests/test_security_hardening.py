"""Regression tests for the SECURITY_AUDIT remediations.

Each test names the finding it pins down. They exist because every one of these
holes was invisible from the outside — the service answered 200 either way — so
the only thing standing between a fix and its quiet reversal is a test that
fails loudly.
"""
import pytest
from pydantic import SecretStr, ValidationError

from mxtng_auth import services
from mxtng_auth.ratelimit import limiter
from mxtng_auth.settings import Settings, settings

EMAIL = "hardening@example.com"
PASSWORD = "correct horse battery"


async def _signup(client, email=EMAIL, password=PASSWORD):
    return await client.post("/v1/credentials", json={"email": email, "password": password})


# --- H-3: OAuth state is issued, stored and burned --------------------------
async def test_callback_without_state_is_refused(client, monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "client-id")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", SecretStr("client-secret"))
    monkeypatch.setattr(settings, "GOOGLE_REDIRECT_URI", "http://localhost:8100/cb")

    response = await client.get("/v1/google/callback", params={"code": "whatever"})

    assert response.status_code == 400
    assert response.json()["code"] == "invalid_oauth_state"


async def test_callback_rejects_a_state_this_service_never_issued(client, monkeypatch):
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "client-id")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", SecretStr("client-secret"))
    monkeypatch.setattr(settings, "GOOGLE_REDIRECT_URI", "http://localhost:8100/cb")

    response = await client.get(
        "/v1/google/callback", params={"code": "whatever", "state": "forged-state"}
    )

    assert response.status_code == 400
    assert response.json()["code"] == "invalid_oauth_state"


async def test_state_is_single_use(client):
    """The second callback carrying the same state is an injection attempt."""
    from mxtng_auth.db import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        state = await services.issue_oauth_state(db)
        await services.consume_oauth_state(db, state=state)

        with pytest.raises(services.InvalidOAuthState):
            await services.consume_oauth_state(db, state=state)


async def test_expired_state_is_rejected(client, monkeypatch):
    from mxtng_auth.db import AsyncSessionLocal

    monkeypatch.setattr(settings, "OAUTH_STATE_TTL_SECONDS", -1)
    async with AsyncSessionLocal() as db:
        state = await services.issue_oauth_state(db)
        with pytest.raises(services.InvalidOAuthState):
            await services.consume_oauth_state(db, state=state)


# --- M-1: per-IP ceilings on the unauthenticated surface --------------------
async def test_password_reset_requests_are_rate_limited(client, monkeypatch):
    """Unlimited, this endpoint mails anyone anything on demand."""
    monkeypatch.setattr(settings, "RATE_LIMIT_RESET_PER_MINUTE", 2)
    limiter.reset()

    for _ in range(2):
        allowed = await client.post(
            "/v1/password-reset/request", json={"email": EMAIL}
        )
        assert allowed.status_code == 200

    throttled = await client.post("/v1/password-reset/request", json={"email": EMAIL})
    assert throttled.status_code == 429
    assert throttled.headers["retry-after"]


async def test_signup_is_rate_limited(client, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_SIGNUP_PER_MINUTE", 1)
    limiter.reset()

    assert (await _signup(client, email="one@example.com")).status_code == 201
    assert (await _signup(client, email="two@example.com")).status_code == 429


async def test_login_attempts_are_rate_limited_per_source(client, outbox, monkeypatch):
    """The per-credential lockout cannot see one source spraying many accounts."""
    monkeypatch.setattr(settings, "RATE_LIMIT_LOGIN_PER_MINUTE", 3)
    limiter.reset()

    for index in range(3):
        await client.post(
            "/v1/login/challenge",
            json={"email": f"spray{index}@example.com", "password": "guess"},
        )

    blocked = await client.post(
        "/v1/login/challenge", json={"email": "spray9@example.com", "password": "guess"}
    )
    assert blocked.status_code == 429


# --- M-2: introspection is one query, and still correct ---------------------
async def test_introspect_answers_a_batch_in_order(client, outbox):
    await _signup(client)
    token = (
        await client.post(
            "/v1/login/verify",
            json={
                "challenge_id": (
                    await client.post(
                        "/v1/login/challenge",
                        json={"email": EMAIL, "password": PASSWORD},
                    )
                ).json()["challenge_id"],
                "code": _code(outbox[0]),
            },
        )
    ).json()["access_token"]

    from jose import jwt

    live = jwt.get_unverified_claims(token)["sid"]
    response = await client.post(
        "/v1/sessions/introspect",
        json={"session_ids": ["not-a-session", live, "also-not-a-session", live]},
    )

    assert response.status_code == 200
    assert response.json()["active"] == [live]


def _code(entry) -> str:
    for token in entry["text"].split():
        stripped = token.strip(".,")
        if stripped.isdigit() and len(stripped) == settings.OTP_CODE_LENGTH:
            return stripped
    raise AssertionError(f"No code in {entry['text']!r}")


# --- H-1: the admin surface closes when unconfigured ------------------------
async def test_admin_endpoint_is_closed_when_no_key_is_configured(client, monkeypatch):
    """"No key set" must mean "no access", never "no check"."""
    monkeypatch.setattr(settings, "ADMIN_API_KEY", None)

    response = await client.post(
        "/v1/admin/credentials/whatever/disable", headers={"X-Admin-Key": "anything"}
    )

    assert response.status_code == 503


async def test_admin_endpoint_rejects_a_wrong_key(client, monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_API_KEY", SecretStr("the-real-key"))

    response = await client.post(
        "/v1/admin/credentials/whatever/disable", headers={"X-Admin-Key": "guess"}
    )

    assert response.status_code == 403


# --- H-1: production refuses to boot on placeholders ------------------------
def _production_settings(**overrides):
    base = dict(
        ENVIRONMENT="production",
        ADMIN_API_KEY="a-real-admin-key",
        TRUSTED_HOSTS=["auth.example.com"],
        REFRESH_COOKIE_SECURE=True,
        _env_file=None,
    )
    base.update(overrides)
    return Settings(**base)


def test_production_boots_with_real_secrets():
    assert _production_settings().is_production


def test_production_refuses_a_missing_admin_key():
    with pytest.raises(ValidationError, match="ADMIN_API_KEY"):
        _production_settings(ADMIN_API_KEY=None)


def test_production_refuses_a_published_placeholder():
    with pytest.raises(ValidationError, match="placeholder"):
        _production_settings(ADMIN_API_KEY="change-me-admin-key")


def test_production_refuses_wildcard_trusted_hosts():
    with pytest.raises(ValidationError, match="TRUSTED_HOSTS"):
        _production_settings(TRUSTED_HOSTS=["*"])


def test_production_refuses_to_echo_reset_tokens():
    with pytest.raises(ValidationError, match="DEBUG_ECHO_RESET_TOKENS"):
        _production_settings(DEBUG_ECHO_RESET_TOKENS=True)


def test_production_refuses_an_insecure_refresh_cookie():
    with pytest.raises(ValidationError, match="REFRESH_COOKIE_SECURE"):
        _production_settings(REFRESH_COOKIE_SECURE=False)


def test_an_unknown_environment_is_a_startup_error():
    """A typo'd "prod" must not silently unlock development behaviour."""
    with pytest.raises(ValidationError):
        Settings(ENVIRONMENT="prod", _env_file=None)


# --- M-5: no ephemeral signing keys outside development ---------------------
def test_signer_refuses_to_invent_a_key_in_production(monkeypatch, tmp_path):
    from mxtng_auth.signer import LocalRSASigner, MissingSigningKey

    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "PRIVATE_KEY_PEM", None)
    monkeypatch.setattr(settings, "PRIVATE_KEY_PATH", str(tmp_path / "absent.pem"))

    with pytest.raises(MissingSigningKey, match="ephemeral"):
        LocalRSASigner.from_settings()


# --- H-2: an unverified Google address cannot claim an account --------------
@pytest.mark.parametrize(
    "email_verified, expect_accepted",
    [(True, True), ("true", True), (False, False), (None, False), ("", False)],
)
def test_google_identity_requires_a_verified_address(email_verified, expect_accepted):
    """The claim that decides whether a Google login may take over an existing
    password account. Exercised directly against the check rather than through a
    mocked token exchange, so it stays readable and cannot pass by accident."""
    from mxtng_auth.google import UnverifiedGoogleEmail, _require_verified_email

    claims = {"email": "victim@example.com", "sub": "123"}
    if email_verified is not None:
        claims["email_verified"] = email_verified

    if expect_accepted:
        _require_verified_email(claims)
    else:
        with pytest.raises(UnverifiedGoogleEmail):
            _require_verified_email(claims)
