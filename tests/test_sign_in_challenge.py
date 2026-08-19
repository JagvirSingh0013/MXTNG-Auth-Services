"""Sign-in challenge flow (ADR-0011).

Mail is intercepted rather than mocked away wholesale: these tests assert on the
message that would actually be sent, including that the fallback SMTP path is
reached when the relay is down — that path is what unbricks a fresh environment,
so it needs exercising, not just existing.
"""
import pytest

from jose import jwt

from mxtng_auth import mail, services
from mxtng_auth.settings import settings

EMAIL = "rec@example.com"
PASSWORD = "correct horse battery"


@pytest.fixture
def outbox(monkeypatch):
    """Capture what would be mailed, standing in for the relay."""
    sent = []

    async def _fake_send(*, to_email, message, purpose, mode):
        sent.append(
            {"to": to_email, "subject": message.subject, "text": message.text_body,
             "purpose": purpose, "mode": mode}
        )
        return "relay"

    monkeypatch.setattr(mail, "send", _fake_send)
    return sent


def _code_from(entry):
    for token in entry["text"].split():
        stripped = token.strip(".,")
        if stripped.isdigit() and len(stripped) == settings.OTP_CODE_LENGTH:
            return stripped
    raise AssertionError(f"No code in mail body: {entry['text']!r}")


async def _signup(client, email=EMAIL, password=PASSWORD):
    return await client.post("/v1/credentials", json={"email": email, "password": password})


async def _challenge(client, email=EMAIL, password=PASSWORD):
    return await client.post("/v1/login/challenge", json={"email": email, "password": password})


# --- The happy path ---------------------------------------------------------
async def test_password_alone_yields_no_tokens(client, outbox):
    await _signup(client)
    response = await _challenge(client)

    assert response.status_code == 202
    body = response.json()
    assert "access_token" not in body
    assert body["expires_in"] == settings.OTP_TTL_SECONDS
    # The address is hinted, never echoed back in full.
    assert body["email_hint"].endswith("@example.com")
    assert EMAIL.split("@")[0] not in body["email_hint"]
    assert len(outbox) == 1
    assert outbox[0]["mode"] == mail.MODE_INLINE


async def test_correct_code_completes_sign_in(client, outbox):
    await _signup(client)
    challenge = (await _challenge(client)).json()

    verify = await client.post(
        "/v1/login/verify",
        json={"challenge_id": challenge["challenge_id"], "code": _code_from(outbox[0])},
    )
    assert verify.status_code == 200

    jwks = (await client.get("/.well-known/jwks.json")).json()
    claims = jwt.decode(
        verify.json()["access_token"], jwks, algorithms=["RS256"],
        audience="ats", issuer="http://localhost:8100",
    )
    assert claims["email"] == EMAIL


async def test_code_is_single_use(client, outbox):
    await _signup(client)
    challenge = (await _challenge(client)).json()
    code = _code_from(outbox[0])
    payload = {"challenge_id": challenge["challenge_id"], "code": code}

    assert (await client.post("/v1/login/verify", json=payload)).status_code == 200
    assert (await client.post("/v1/login/verify", json=payload)).status_code == 401


# --- Failure and abuse ------------------------------------------------------
async def test_wrong_codes_trip_the_credential_lockout(client, outbox):
    """MAX_FAILED_LOGINS is 3 in the test harness. Wrong codes feed the same
    counter a wrong password does, so guessing cannot be reset by re-challenging."""
    await _signup(client)
    challenge = (await _challenge(client)).json()
    real = _code_from(outbox[0])
    wrong = "000000" if real != "000000" else "111111"

    for _ in range(settings.MAX_FAILED_LOGINS):
        response = await client.post(
            "/v1/login/verify",
            json={"challenge_id": challenge["challenge_id"], "code": wrong},
        )
        assert response.status_code == 401

    # The credential itself is now locked — a fresh password attempt is refused.
    locked = await _challenge(client)
    assert locked.status_code == 429
    assert locked.json()["code"] == "account_locked"


async def test_a_new_challenge_supersedes_the_previous_one(client, outbox):
    await _signup(client)
    first = (await _challenge(client)).json()
    first_code = _code_from(outbox[0])

    second = (await _challenge(client)).json()
    assert second["challenge_id"] != first["challenge_id"]

    stale = await client.post(
        "/v1/login/verify", json={"challenge_id": first["challenge_id"], "code": first_code}
    )
    assert stale.status_code == 401

    fresh = await client.post(
        "/v1/login/verify",
        json={"challenge_id": second["challenge_id"], "code": _code_from(outbox[1])},
    )
    assert fresh.status_code == 200


async def test_resend_invalidates_the_previous_code(client, outbox, monkeypatch):
    monkeypatch.setattr(settings, "OTP_RESEND_COOLDOWN_SECONDS", 0)
    await _signup(client)
    challenge = (await _challenge(client)).json()
    original = _code_from(outbox[0])

    resend = await client.post(
        "/v1/login/resend", json={"challenge_id": challenge["challenge_id"]}
    )
    assert resend.status_code == 202
    assert resend.json()["challenge_id"] == challenge["challenge_id"]

    replacement = _code_from(outbox[1])
    assert replacement != original or len(outbox) == 2

    stale = await client.post(
        "/v1/login/verify", json={"challenge_id": challenge["challenge_id"], "code": original}
    )
    assert stale.status_code == 401


async def test_resend_is_rate_limited(client, outbox):
    await _signup(client)
    challenge = (await _challenge(client)).json()

    too_soon = await client.post(
        "/v1/login/resend", json={"challenge_id": challenge["challenge_id"]}
    )
    assert too_soon.status_code == 429
    assert len(outbox) == 1


async def test_unknown_challenge_is_rejected(client, outbox):
    response = await client.post(
        "/v1/login/verify", json={"challenge_id": "not-a-challenge", "code": "123456"}
    )
    assert response.status_code == 401


# --- Rollout switch ---------------------------------------------------------
async def test_legacy_login_still_issues_tokens_until_the_switch_flips(client, outbox):
    await _signup(client)
    legacy = await client.post("/v1/login", json={"email": EMAIL, "password": PASSWORD})
    assert legacy.status_code == 200
    assert "access_token" in legacy.json()
    assert outbox == []  # no challenge, no mail


async def test_flipping_require_otp_retires_legacy_login(client, outbox, monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_OTP", True)
    await _signup(client)
    legacy = await client.post("/v1/login", json={"email": EMAIL, "password": PASSWORD})
    assert legacy.status_code == 403
    assert legacy.json()["code"] == "otp_required"


# --- Mail delivery ----------------------------------------------------------
async def test_undeliverable_code_fails_the_sign_in_loudly(client, monkeypatch):
    """A challenge nobody can answer must not look like a successful first step."""
    async def _boom(**_kwargs):
        raise mail.MailUndeliverable("relay down, no fallback configured")

    monkeypatch.setattr(mail, "send", _boom)
    await _signup(client)
    response = await _challenge(client)
    assert response.status_code == 502
    assert response.json()["code"] == "mail_delivery_failed"


async def test_fallback_smtp_takes_over_when_the_relay_is_down(monkeypatch):
    """The break-glass path is what makes bootstrap possible, so prove it sends
    rather than merely existing."""
    delivered = {}

    def _fake_smtp(*, to_email, message):
        delivered["to"] = to_email
        delivered["subject"] = message.subject

    monkeypatch.setattr(settings, "MAIL_RELAY_URL", "http://relay.invalid/internal/mail")
    monkeypatch.setattr(settings, "FALLBACK_SMTP_HOST", "smtp.example.test")
    monkeypatch.setattr(mail, "_send_smtp_blocking", _fake_smtp)

    message = mail.render_sign_in_code(
        code="123456", ttl_seconds=300, requested_at=services._now()
    )
    path = await mail.send(
        to_email=EMAIL, message=message,
        purpose=mail.PURPOSE_SIGN_IN_CODE, mode=mail.MODE_INLINE,
    )
    assert path == "fallback"
    assert delivered["to"] == EMAIL


async def test_password_reset_is_actually_emailed_now(client, outbox):
    await _signup(client)
    response = await client.post("/v1/password-reset/request", json={"email": EMAIL})
    assert response.status_code == 200
    assert len(outbox) == 1
    assert outbox[0]["purpose"] == mail.PURPOSE_PASSWORD_RESET
    # A 30-minute token tolerates the outbox; a 5-minute code does not.
    assert outbox[0]["mode"] == mail.MODE_QUEUED


async def test_a_delivery_failure_reports_both_causes(monkeypatch):
    """The fallback's own complaint is the least useful half. Without the relay
    error beside it, an operator cannot tell a misconfigured URL from a bad secret
    from an SMTP rejection."""
    monkeypatch.setattr(settings, "MAIL_RELAY_URL", None)
    monkeypatch.setattr(settings, "FALLBACK_SMTP_HOST", None)

    message = mail.render_sign_in_code(code="123456", ttl_seconds=300, requested_at=services._now())
    with pytest.raises(mail.MailUndeliverable) as caught:
        await mail.send(
            to_email=EMAIL, message=message,
            purpose=mail.PURPOSE_SIGN_IN_CODE, mode=mail.MODE_INLINE,
        )

    reported = str(caught.value)
    assert "relay failed" in reported
    assert "fallback failed" in reported


# --- Startup configuration check --------------------------------------------
def test_startup_refuses_when_otp_is_required_but_nothing_can_send(monkeypatch):
    """Starting up is worse than not starting: every sign-in would 502, far from
    the cause."""
    from mxtng_auth.main import MailNotConfigured, check_mail_configuration

    monkeypatch.setattr(settings, "REQUIRE_OTP", True)
    monkeypatch.setattr(settings, "MAIL_RELAY_URL", None)
    monkeypatch.setattr(settings, "FALLBACK_SMTP_HOST", None)

    with pytest.raises(MailNotConfigured, match="No mail path configured"):
        check_mail_configuration()


def test_startup_only_complains_while_legacy_login_still_works(monkeypatch, caplog):
    from mxtng_auth.main import check_mail_configuration

    monkeypatch.setattr(settings, "REQUIRE_OTP", False)
    monkeypatch.setattr(settings, "MAIL_RELAY_URL", None)
    monkeypatch.setattr(settings, "FALLBACK_SMTP_HOST", None)

    with caplog.at_level("ERROR"):
        check_mail_configuration()  # must not raise
    assert "No mail path configured" in caplog.text


def test_startup_warns_when_only_the_relay_is_configured(monkeypatch, caplog):
    """A relay without a fallback is the unrecoverable case: if it breaks, nobody
    can sign in to fix it."""
    from mxtng_auth.main import check_mail_configuration

    monkeypatch.setattr(settings, "MAIL_RELAY_URL", "http://ats.test/api/v1/internal/mail")
    monkeypatch.setattr(settings, "MAIL_RELAY_SECRET", "a-real-secret")
    monkeypatch.setattr(settings, "FALLBACK_SMTP_HOST", None)

    with caplog.at_level("WARNING"):
        check_mail_configuration()
    assert "FALLBACK_SMTP_HOST" in caplog.text


def test_startup_flags_a_default_relay_secret(monkeypatch, caplog):
    from mxtng_auth.main import check_mail_configuration

    monkeypatch.setattr(settings, "MAIL_RELAY_URL", "http://ats.test/api/v1/internal/mail")
    monkeypatch.setattr(settings, "MAIL_RELAY_SECRET", "change-me-mail-relay-secret")
    monkeypatch.setattr(settings, "FALLBACK_SMTP_HOST", "smtp.example.test")

    with caplog.at_level("ERROR"):
        check_mail_configuration()
    assert "MAIL_RELAY_SECRET" in caplog.text
