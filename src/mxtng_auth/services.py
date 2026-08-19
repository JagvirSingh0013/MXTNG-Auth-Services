"""Auth service logic: signup, login (hardened), refresh rotation, reset, Google, admin.

Everything here is identity-only. No agencies, roles, or referrals ever appear —
that is each product's job (ADR-0005/0007).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mxtng_auth import events, mail
from mxtng_auth.models import (
    AuthAuditLog,
    Credential,
    PasswordResetToken,
    RefreshToken,
    SignInChallenge,
)
from mxtng_auth.security import (
    hash_opaque_token,
    hash_password,
    hash_sign_in_code,
    new_opaque_token,
    new_sign_in_code,
    verify_password,
    verify_sign_in_code,
)
from mxtng_auth.settings import settings
from mxtng_auth.tokens import mint_access_token, resolve_audience


# --- Error taxonomy ---------------------------------------------------------
class AuthError(Exception):
    status_code = 400
    code = "auth_error"

    def __init__(self, message: str, *, code: str | None = None, status_code: int | None = None):
        super().__init__(message)
        if code:
            self.code = code
        if status_code:
            self.status_code = status_code


class EmailAlreadyRegistered(AuthError):
    status_code = 409
    code = "email_taken"


class InvalidCredentials(AuthError):
    status_code = 401
    code = "invalid_credentials"


class AccountLocked(AuthError):
    status_code = 429
    code = "account_locked"


class AccountDisabled(AuthError):
    status_code = 403
    code = "account_disabled"


class InvalidRefresh(AuthError):
    status_code = 401
    code = "invalid_refresh"


class InvalidResetToken(AuthError):
    status_code = 400
    code = "invalid_reset_token"


class InvalidChallenge(AuthError):
    status_code = 401
    code = "invalid_challenge"


class ResendTooSoon(AuthError):
    status_code = 429
    code = "resend_too_soon"


class MailDeliveryFailed(AuthError):
    status_code = 502
    code = "mail_delivery_failed"


class OtpRequired(AuthError):
    status_code = 403
    code = "otp_required"


# --- Helpers ----------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; treat them as UTC for safe comparison."""
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _normalize_email(email: str) -> str:
    return email.strip().lower()


async def _audit(
    db: AsyncSession,
    event: str,
    *,
    credential_id: int | None = None,
    email: str | None = None,
    ip: str | None = None,
    detail: str | None = None,
) -> None:
    db.add(
        AuthAuditLog(
            credential_id=credential_id, event=event, email=email, ip=ip, detail=detail
        )
    )


async def _get_by_email(db: AsyncSession, email: str) -> Credential | None:
    result = await db.execute(select(Credential).where(Credential.email == email))
    return result.scalar_one_or_none()


async def get_credential(db: AsyncSession, credential_id: int) -> Credential | None:
    return await db.get(Credential, credential_id)


async def get_by_auth_user_id(db: AsyncSession, auth_user_id: str) -> Credential | None:
    result = await db.execute(
        select(Credential).where(Credential.auth_user_id == auth_user_id)
    )
    return result.scalar_one_or_none()


# --- Signup (idempotent) ----------------------------------------------------
async def create_credential(
    db: AsyncSession,
    *,
    email: str,
    password: str,
    idempotency_key: str | None = None,
    ip: str | None = None,
) -> Credential:
    """Create a password credential. Idempotent on a client-supplied key (ADR-0007):
    a retry with the same key returns the same row; a new key against an existing
    email is a conflict."""
    email = _normalize_email(email)

    if idempotency_key:
        result = await db.execute(
            select(Credential).where(Credential.idempotency_key == idempotency_key)
        )
        existing = result.scalar_one_or_none()
        if existing is not None:
            return existing  # replayed request -> same UUID

    if await _get_by_email(db, email) is not None:
        raise EmailAlreadyRegistered("That email is already registered")

    credential = Credential(
        email=email,
        password_hash=hash_password(password),
        idempotency_key=idempotency_key,
    )
    db.add(credential)
    await _audit(db, "signup", email=email, ip=ip)
    await db.commit()
    await db.refresh(credential)
    return credential


# --- Login ------------------------------------------------------------------
async def authenticate(
    db: AsyncSession, *, email: str, password: str, ip: str | None = None
) -> Credential:
    email = _normalize_email(email)
    credential = await _get_by_email(db, email)

    if credential is None:
        await _audit(db, "login_failed", email=email, ip=ip, detail="no_such_credential")
        await db.commit()
        raise InvalidCredentials("Invalid email or password")

    locked_until = _aware(credential.locked_until)
    if locked_until and locked_until > _now():
        await _audit(db, "login_blocked_locked", credential_id=credential.id, email=email, ip=ip)
        await db.commit()
        raise AccountLocked("Too many failed attempts. Try again later.")

    if credential.disabled:
        await _audit(db, "login_blocked_disabled", credential_id=credential.id, email=email, ip=ip)
        await db.commit()
        raise AccountDisabled("This account has been disabled")

    if not verify_password(password, credential.password_hash):
        credential.failed_attempts += 1
        if credential.failed_attempts >= settings.MAX_FAILED_LOGINS:
            credential.locked_until = _now() + timedelta(seconds=settings.LOGIN_LOCKOUT_SECONDS)
            credential.failed_attempts = 0
        await _audit(db, "login_failed", credential_id=credential.id, email=email, ip=ip)
        await db.commit()
        raise InvalidCredentials("Invalid email or password")

    credential.failed_attempts = 0
    credential.locked_until = None
    await _audit(db, "login_succeeded", credential_id=credential.id, email=email, ip=ip)
    await db.commit()
    return credential


# --- Sign-in challenge (ADR-0011) -------------------------------------------
async def _supersede_challenges(db: AsyncSession, *, credential_id: int) -> None:
    """At most one challenge is live per credential, so a fresh sign-in always
    invalidates whatever an earlier attempt left behind."""
    result = await db.execute(
        select(SignInChallenge).where(
            SignInChallenge.credential_id == credential_id,
            SignInChallenge.consumed.is_(False),
        )
    )
    for challenge in result.scalars().all():
        challenge.consumed = True


async def _mail_sign_in_code(credential: Credential, code: str) -> None:
    message = mail.render_sign_in_code(
        code=code, ttl_seconds=settings.OTP_TTL_SECONDS, requested_at=_now()
    )
    await mail.send(
        to_email=credential.email,
        message=message,
        purpose=mail.PURPOSE_SIGN_IN_CODE,
        mode=mail.MODE_INLINE,
    )


async def start_challenge(
    db: AsyncSession, *, credential: Credential, audience: str, ip: str | None = None
) -> SignInChallenge:
    """Withhold tokens behind an emailed Sign-in Code. The caller has already
    proved the first factor (password, or a verified Google identity)."""
    audience = resolve_audience(audience)
    await _supersede_challenges(db, credential_id=credential.id)

    code = new_sign_in_code(settings.OTP_CODE_LENGTH)
    challenge = SignInChallenge(
        credential_id=credential.id,
        code_hash=hash_sign_in_code(code),
        audience=audience,
        expires_at=_now() + timedelta(seconds=settings.OTP_TTL_SECONDS),
    )
    db.add(challenge)
    await db.commit()
    await db.refresh(challenge)

    try:
        await _mail_sign_in_code(credential, code)
    except mail.MailUndeliverable as exc:
        # A challenge nobody can answer is worse than no challenge: retire it so a
        # retry is not blocked by a dead row, and fail the sign-in visibly.
        challenge.consumed = True
        await _audit(db, "otp_send_failed", credential_id=credential.id,
                     email=credential.email, ip=ip, detail=str(exc)[:400])
        await db.commit()
        raise MailDeliveryFailed("Could not send your sign-in code. Try again shortly.") from exc

    await _audit(db, "otp_challenged", credential_id=credential.id, email=credential.email, ip=ip)
    await db.commit()
    return challenge


async def _load_live_challenge(db: AsyncSession, challenge_id: str) -> SignInChallenge:
    result = await db.execute(
        select(SignInChallenge).where(SignInChallenge.challenge_id == challenge_id)
    )
    challenge = result.scalar_one_or_none()
    if challenge is None or challenge.consumed or _aware(challenge.expires_at) < _now():
        raise InvalidChallenge("Invalid or expired sign-in code")
    return challenge


async def resend_challenge(
    db: AsyncSession, *, challenge_id: str, ip: str | None = None
) -> SignInChallenge:
    """Mint a fresh code and restart the window. The previous code stops working —
    which is why the email carries the time it was requested."""
    challenge = await _load_live_challenge(db, challenge_id)

    since_last = (_now() - _aware(challenge.last_sent_at)).total_seconds()
    if since_last < settings.OTP_RESEND_COOLDOWN_SECONDS:
        raise ResendTooSoon("Wait a moment before requesting another code.")
    if challenge.sends >= settings.OTP_MAX_SENDS_PER_CHALLENGE:
        raise ResendTooSoon("Too many codes requested. Start signing in again.")

    credential = await db.get(Credential, challenge.credential_id)
    if credential is None or credential.disabled:
        raise AccountDisabled("This account has been disabled")

    code = new_sign_in_code(settings.OTP_CODE_LENGTH)
    challenge.code_hash = hash_sign_in_code(code)
    challenge.expires_at = _now() + timedelta(seconds=settings.OTP_TTL_SECONDS)
    challenge.attempts = 0
    challenge.sends += 1
    challenge.last_sent_at = _now()
    await db.commit()

    try:
        await _mail_sign_in_code(credential, code)
    except mail.MailUndeliverable as exc:
        await _audit(db, "otp_send_failed", credential_id=credential.id,
                     email=credential.email, ip=ip, detail=str(exc)[:400])
        await db.commit()
        raise MailDeliveryFailed("Could not send your sign-in code. Try again shortly.") from exc

    await _audit(db, "otp_resent", credential_id=credential.id, email=credential.email, ip=ip)
    await db.commit()
    return challenge


async def verify_challenge(
    db: AsyncSession, *, challenge_id: str, code: str, ip: str | None = None
) -> tuple[str, int, str]:
    """Trade a correct Sign-in Code for tokens. Wrong codes count against the same
    lockout a wrong password does, so possession of the password buys a fixed
    number of guesses in total rather than five per challenge, forever."""
    challenge = await _load_live_challenge(db, challenge_id)

    credential = await db.get(Credential, challenge.credential_id)
    if credential is None:
        raise InvalidChallenge("Invalid or expired sign-in code")
    if credential.disabled:
        raise AccountDisabled("This account has been disabled")

    locked_until = _aware(credential.locked_until)
    if locked_until and locked_until > _now():
        raise AccountLocked("Too many failed attempts. Try again later.")

    if not verify_sign_in_code(code, challenge.code_hash):
        challenge.attempts += 1
        credential.failed_attempts += 1
        if (
            credential.failed_attempts >= settings.MAX_FAILED_LOGINS
            or challenge.attempts >= settings.OTP_MAX_ATTEMPTS
        ):
            challenge.consumed = True
        if credential.failed_attempts >= settings.MAX_FAILED_LOGINS:
            credential.locked_until = _now() + timedelta(seconds=settings.LOGIN_LOCKOUT_SECONDS)
            credential.failed_attempts = 0
        await _audit(db, "otp_failed", credential_id=credential.id,
                     email=credential.email, ip=ip)
        await db.commit()
        raise InvalidChallenge("Invalid or expired sign-in code")

    challenge.consumed = True
    credential.failed_attempts = 0
    credential.locked_until = None
    await _audit(db, "otp_verified", credential_id=credential.id, email=credential.email, ip=ip)
    await db.commit()
    return await issue_tokens(db, credential=credential, audience=challenge.audience)


# --- Refresh-token issuance & rotation --------------------------------------
async def issue_tokens(
    db: AsyncSession, *, credential: Credential, audience: str, family_id: str | None = None
) -> tuple[str, int, str]:
    """Return (access_token, expires_in, refresh_raw). Starts a new family unless
    continuing an existing one during rotation.

    A `family_id`-less call means a brand-new session (fresh login, not a
    refresh). Concurrent sessions are allowed: a user may be logged in on as
    many devices as they like, each with its own independent token family."""
    audience = resolve_audience(audience)
    access_token, expires_in = mint_access_token(
        auth_user_id=credential.auth_user_id, email=credential.email, audience=audience
    )
    raw = new_opaque_token()
    refresh = RefreshToken(
        credential_id=credential.id,
        token_hash=hash_opaque_token(raw),
        audience=audience,
        expires_at=_now() + timedelta(seconds=settings.REFRESH_TOKEN_TTL_SECONDS),
    )
    if family_id:
        refresh.family_id = family_id
    db.add(refresh)
    await db.commit()
    return access_token, expires_in, raw


async def rotate_refresh(db: AsyncSession, *, raw: str, ip: str | None = None) -> tuple[str, int, str]:
    """Consume a refresh token and issue its successor. Replay of a rotated/revoked
    token is treated as theft and revokes the whole family (ADR-0006)."""
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == hash_opaque_token(raw))
    )
    token = result.scalar_one_or_none()

    if token is None:
        raise InvalidRefresh("Invalid refresh token")

    if token.revoked or token.rotated:
        # Reuse of an already-consumed/revoked token => compromise. Burn the family.
        await _revoke_family(db, family_id=token.family_id)
        await _audit(
            db, "refresh_reuse_detected", credential_id=token.credential_id,
            ip=ip, detail=f"family={token.family_id}",
        )
        await db.commit()
        raise InvalidRefresh("Refresh token reuse detected")

    if _aware(token.expires_at) < _now():
        raise InvalidRefresh("Refresh token expired")

    credential = await db.get(Credential, token.credential_id)
    if credential is None or credential.disabled:
        raise AccountDisabled("This account has been disabled")

    token.rotated = True
    await db.commit()
    access_token, expires_in, new_raw = await issue_tokens(
        db, credential=credential, audience=token.audience, family_id=token.family_id
    )
    await _audit(db, "refresh_rotated", credential_id=credential.id, ip=ip)
    await db.commit()
    return access_token, expires_in, new_raw


async def _revoke_family(db: AsyncSession, *, family_id: str) -> None:
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.family_id == family_id)
    )
    for token in result.scalars().all():
        token.revoked = True


async def revoke_by_raw(db: AsyncSession, *, raw: str) -> None:
    """Logout: revoke the family of the presented refresh token (best-effort)."""
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == hash_opaque_token(raw))
    )
    token = result.scalar_one_or_none()
    if token is not None:
        await _revoke_family(db, family_id=token.family_id)
        await _audit(db, "logout", credential_id=token.credential_id)
        await db.commit()


async def revoke_all_by_raw(db: AsyncSession, *, raw: str) -> None:
    """Force-logout using the presented refresh token to identify the credential."""
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == hash_opaque_token(raw))
    )
    token = result.scalar_one_or_none()
    if token is None:
        return
    credential = await db.get(Credential, token.credential_id)
    if credential is not None:
        await revoke_all_for_credential(db, credential=credential)


async def revoke_all_for_credential(db: AsyncSession, *, credential: Credential) -> None:
    """Force-logout / password change: revoke every refresh family for the user."""
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.credential_id == credential.id)
    )
    for token in result.scalars().all():
        token.revoked = True
    await _audit(db, "logout_all", credential_id=credential.id)
    await db.commit()


# --- Password reset ---------------------------------------------------------
async def request_password_reset(db: AsyncSession, *, email: str, ip: str | None = None) -> str | None:
    """Create a single-use reset token and email it. Returns the raw token for the
    non-production convenience echo; None if the email is unknown (no enumeration).

    Unlike a Sign-in Code this goes through the relay's durable outbox: a 30-minute
    token comfortably tolerates a worker poll, and a queued reset is better than a
    lost one.
    """
    email = _normalize_email(email)
    credential = await _get_by_email(db, email)
    await _audit(db, "password_reset_requested", email=email, ip=ip,
                 credential_id=credential.id if credential else None)
    await db.commit()
    if credential is None:
        return None
    raw = new_opaque_token()
    db.add(
        PasswordResetToken(
            credential_id=credential.id,
            token_hash=hash_opaque_token(raw),
            expires_at=_now() + timedelta(seconds=settings.RESET_TOKEN_TTL_SECONDS),
        )
    )
    await db.commit()

    message = mail.render_password_reset(
        token=raw,
        ttl_seconds=settings.RESET_TOKEN_TTL_SECONDS,
        reset_url=settings.PASSWORD_RESET_URL,
    )
    try:
        await mail.send(
            to_email=credential.email,
            message=message,
            purpose=mail.PURPOSE_PASSWORD_RESET,
            mode=mail.MODE_QUEUED,
        )
    except mail.MailUndeliverable as exc:
        # The token is already valid, so surface the failure in the audit log rather
        # than telling an anonymous caller that this address exists but mail broke.
        await _audit(db, "password_reset_send_failed", credential_id=credential.id,
                     email=email, ip=ip, detail=str(exc)[:400])
        await db.commit()
    return raw


async def confirm_password_reset(
    db: AsyncSession, *, raw: str, new_password: str, ip: str | None = None
) -> None:
    result = await db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_opaque_token(raw))
    )
    token = result.scalar_one_or_none()
    if token is None or token.used or _aware(token.expires_at) < _now():
        raise InvalidResetToken("Invalid or expired reset token")

    credential = await db.get(Credential, token.credential_id)
    if credential is None:
        raise InvalidResetToken("Invalid or expired reset token")

    credential.password_hash = hash_password(new_password)
    credential.failed_attempts = 0
    credential.locked_until = None
    token.used = True
    await _audit(db, "password_reset_confirmed", credential_id=credential.id, ip=ip)
    await db.commit()
    # A password change revokes renewal everywhere.
    await revoke_all_for_credential(db, credential=credential)


# --- Google Sign-in ---------------------------------------------------------
async def upsert_google_credential(
    db: AsyncSession, *, google_sub: str, email: str, ip: str | None = None
) -> Credential:
    """Find-or-create the credential for a verified Google identity. Follows the
    same path as password sign-up — provisioning/gating is the product's job."""
    email = _normalize_email(email)
    result = await db.execute(select(Credential).where(Credential.google_sub == google_sub))
    credential = result.scalar_one_or_none()
    if credential is not None:
        return credential

    credential = await _get_by_email(db, email)
    if credential is not None:
        credential.google_sub = google_sub  # link Google to an existing password credential
        await _audit(db, "google_linked", credential_id=credential.id, email=email, ip=ip)
        await db.commit()
        return credential

    credential = Credential(email=email, google_sub=google_sub)
    db.add(credential)
    await _audit(db, "google_signup", email=email, ip=ip)
    await db.commit()
    await db.refresh(credential)
    return credential


# --- Admin identity mutations (emit IdentityEvents) -------------------------
async def change_email(db: AsyncSession, *, credential: Credential, new_email: str) -> None:
    new_email = _normalize_email(new_email)
    if await _get_by_email(db, new_email) is not None:
        raise EmailAlreadyRegistered("That email is already registered")
    credential.email = new_email
    await _audit(db, "email_changed", credential_id=credential.id, email=new_email)
    await db.commit()
    await events.emit(events.EMAIL_CHANGED, auth_user_id=credential.auth_user_id,
                      data={"email": new_email})


async def disable_credential(db: AsyncSession, *, credential: Credential) -> None:
    credential.disabled = True
    await _audit(db, "account_disabled", credential_id=credential.id)
    await db.commit()
    await revoke_all_for_credential(db, credential=credential)
    await events.emit(events.ACCOUNT_DISABLED, auth_user_id=credential.auth_user_id, data={})
