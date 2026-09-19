"""HTTP surface. Identity-only responses; refresh lives in an httpOnly cookie."""
from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from mxtng_auth import services
from mxtng_auth.db import get_db
from mxtng_auth.schemas import (
    ChallengeResendRequest,
    ChallengeResponse,
    ChallengeVerifyRequest,
    CredentialCreate,
    CredentialRead,
    EmailChange,
    GoogleAuthStart,
    LoginRequest,
    MessageResponse,
    PasswordResetConfirm,
    PasswordResetRequest,
    SessionIntrospectRequest,
    SessionIntrospectResponse,
    TokenResponse,
)
from mxtng_auth.ratelimit import client_ip, rate_limit
from mxtng_auth.settings import reveal, settings
from mxtng_auth.signer import get_signer

DbDep = Annotated[AsyncSession, Depends(get_db)]

public_router = APIRouter(tags=["public"])
v1 = APIRouter(prefix="/v1", tags=["auth"])
admin = APIRouter(prefix="/v1/admin", tags=["admin"])


def _client_ip(request: Request) -> str | None:
    """Delegates to the shared helper so the audit trail and the rate limiter
    always agree on who the caller is (SECURITY_AUDIT L-6)."""
    return client_ip(request)


def _user_agent(request: Request) -> str | None:
    """Labels the session in the audit trail; never used as a security signal."""
    return request.headers.get("user-agent")


def _set_refresh_cookie(response: Response, raw: str) -> None:
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=raw,
        max_age=settings.REFRESH_TOKEN_TTL_SECONDS,
        httponly=True,
        secure=settings.REFRESH_COOKIE_SECURE,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
        path=settings.REFRESH_COOKIE_PATH,
        domain=settings.REFRESH_COOKIE_DOMAIN,
    )


def _email_hint(email: str) -> str:
    """Enough for 'we sent a code to a…@example.com' without printing the address
    back to whoever is holding the challenge."""
    local, _, domain = email.partition("@")
    masked = local[0] + "•" * max(len(local) - 1, 1) if local else "•"
    return f"{masked}@{domain}" if domain else masked


def _challenge_response(challenge, email: str) -> ChallengeResponse:
    return ChallengeResponse(
        challenge_id=challenge.challenge_id,
        expires_in=settings.OTP_TTL_SECONDS,
        email_hint=_email_hint(email),
    )


def _clear_refresh_cookie(response: Response) -> None:
    # The attributes must match the cookie that was set, or the browser keeps it.
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path=settings.REFRESH_COOKIE_PATH,
        domain=settings.REFRESH_COOKIE_DOMAIN,
        httponly=True,
        secure=settings.REFRESH_COOKIE_SECURE,
        samesite=settings.REFRESH_COOKIE_SAMESITE,
    )


# --- Public: health + JWKS --------------------------------------------------
@public_router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@public_router.get("/.well-known/jwks.json")
async def jwks() -> dict:
    return get_signer().jwks()


# --- Signup (idempotent) ----------------------------------------------------
@v1.post(
    "/credentials",
    response_model=CredentialRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit("signup", "RATE_LIMIT_SIGNUP_PER_MINUTE"))],
)
async def create_credential(
    payload: CredentialCreate,
    request: Request,
    db: DbDep,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> CredentialRead:
    credential = await services.create_credential(
        db,
        email=payload.email,
        password=payload.password,
        idempotency_key=idempotency_key,
        ip=_client_ip(request),
    )
    return CredentialRead(auth_user_id=credential.auth_user_id, email=credential.email)


# --- Login / refresh / logout ----------------------------------------------
# The legacy single-step `POST /v1/login` was removed (SECURITY_AUDIT C-2).
# It issued tokens on a password alone, so nothing in the sign-in path ever
# proved the person controlled the mailbox — and the ATS turns an email domain
# into agency membership. It lived behind a `REQUIRE_OTP` flag that defaulted to
# off; a flag that can re-enable a critical hole is not a mitigation, so both the
# route and the flag are gone. Every product now signs in through
# /v1/login/challenge + /v1/login/verify.


# --- Sign-in challenge (ADR-0011) -------------------------------------------
@v1.post(
    "/login/challenge",
    response_model=ChallengeResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limit("login", "RATE_LIMIT_LOGIN_PER_MINUTE"))],
)
async def login_challenge(
    payload: LoginRequest, request: Request, db: DbDep
) -> ChallengeResponse:
    """Verify the password, then withhold tokens until the emailed code comes back."""
    credential = await services.authenticate(
        db, email=payload.email, password=payload.password, ip=_client_ip(request)
    )
    challenge = await services.start_challenge(
        db, credential=credential, audience=payload.audience or "", ip=_client_ip(request)
    )
    return _challenge_response(challenge, credential.email)


@v1.post(
    "/login/verify",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit("login", "RATE_LIMIT_LOGIN_PER_MINUTE"))],
)
async def login_verify(
    payload: ChallengeVerifyRequest, request: Request, response: Response, db: DbDep
) -> TokenResponse:
    access_token, expires_in, refresh_raw = await services.verify_challenge(
        db,
        challenge_id=payload.challenge_id,
        code=payload.code,
        ip=_client_ip(request),
        user_agent=_user_agent(request),
    )
    _set_refresh_cookie(response, refresh_raw)
    return TokenResponse(access_token=access_token, expires_in=expires_in)


@v1.post(
    "/login/resend",
    response_model=ChallengeResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limit("login", "RATE_LIMIT_LOGIN_PER_MINUTE"))],
)
async def login_resend(
    payload: ChallengeResendRequest, request: Request, db: DbDep
) -> ChallengeResponse:
    """Mint a replacement code. The previous one stops working immediately."""
    challenge = await services.resend_challenge(
        db, challenge_id=payload.challenge_id, ip=_client_ip(request)
    )
    credential = await services.get_credential(db, challenge.credential_id)
    return _challenge_response(challenge, credential.email if credential else "")


@v1.post("/token/refresh", response_model=TokenResponse)
async def refresh(request: Request, response: Response, db: DbDep) -> TokenResponse:
    raw = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if not raw:
        raise HTTPException(status_code=401, detail="Missing refresh token")
    access_token, expires_in, new_raw = await services.rotate_refresh(
        db, raw=raw, ip=_client_ip(request)
    )
    _set_refresh_cookie(response, new_raw)
    return TokenResponse(access_token=access_token, expires_in=expires_in)


@v1.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response, db: DbDep) -> Response:
    raw = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if raw:
        await services.revoke_by_raw(db, raw=raw)
    _clear_refresh_cookie(response)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@v1.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(request: Request, response: Response, db: DbDep) -> Response:
    raw = request.cookies.get(settings.REFRESH_COOKIE_NAME)
    if raw:
        await services.revoke_all_by_raw(db, raw=raw)
    _clear_refresh_cookie(response)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Sessions ---------------------------------------------------------------
@v1.post(
    "/sessions/introspect",
    response_model=SessionIntrospectResponse,
    dependencies=[Depends(rate_limit("introspect", "RATE_LIMIT_INTROSPECT_PER_MINUTE"))],
)
async def sessions_introspect(
    payload: SessionIntrospectRequest, db: DbDep
) -> SessionIntrospectResponse:
    """Tell a product which of these sessions are still live.

    This is what makes a revocation visible to a verifier that checks signatures
    offline (ADR-0006): the token stays valid until `exp`, but its `sid` stops
    being live the moment another device signs in.

    Unauthenticated on purpose. A `sid` is a random UUID that can only be read
    out of a token you already hold, the answer is a bare boolean, and there is
    nothing here to enumerate — so a shared secret would add key distribution
    without adding secrecy. It is a POST rather than a GET so session ids stay
    out of access logs and proxy caches.

    Answered with a single `IN` query and rate-limited per IP: the previous
    per-id loop turned one cheap anonymous request into up to a hundred
    sequential round trips (SECURITY_AUDIT M-2).
    """
    active = await services.live_session_ids(db, payload.session_ids)
    return SessionIntrospectResponse(active=active)


# --- Password reset ---------------------------------------------------------
@v1.post(
    "/password-reset/request",
    response_model=MessageResponse,
    dependencies=[Depends(rate_limit("password_reset", "RATE_LIMIT_RESET_PER_MINUTE"))],
)
async def password_reset_request(
    payload: PasswordResetRequest, request: Request, db: DbDep
) -> MessageResponse:
    raw = await services.request_password_reset(
        db, email=payload.email, ip=_client_ip(request)
    )
    # Never reveal whether the email exists. The developer convenience of getting
    # the token back is opt-in and development-only (SECURITY_AUDIT M-10): the
    # old `!= "production"` test handed live reset tokens to anonymous callers on
    # staging, on any typo'd ENVIRONMENT, and whenever the variable was unset.
    if raw and settings.DEBUG_ECHO_RESET_TOKENS and settings.is_development:
        return MessageResponse(message=f"reset_token={raw}")
    return MessageResponse(message="If that email exists, a reset link has been sent.")


@v1.post(
    "/password-reset/confirm",
    response_model=MessageResponse,
    dependencies=[Depends(rate_limit("password_reset", "RATE_LIMIT_RESET_PER_MINUTE"))],
)
async def password_reset_confirm(
    payload: PasswordResetConfirm, request: Request, db: DbDep
) -> MessageResponse:
    await services.confirm_password_reset(
        db, raw=payload.token, new_password=payload.new_password, ip=_client_ip(request)
    )
    return MessageResponse(message="Password updated. Please sign in again.")


# --- Sign-in-with-Google ----------------------------------------------------
def _require_google() -> None:
    if not settings.google_enabled:
        raise HTTPException(status_code=501, detail="Google sign-in is not configured")


@v1.get(
    "/google/start",
    response_model=GoogleAuthStart,
    dependencies=[Depends(rate_limit("login", "RATE_LIMIT_LOGIN_PER_MINUTE"))],
)
async def google_start(db: DbDep) -> GoogleAuthStart:
    _require_google()
    from mxtng_auth.google import build_authorization_url

    # Persisted, single-use and short-lived — see services.issue_oauth_state.
    state = await services.issue_oauth_state(db)
    return GoogleAuthStart(authorization_url=build_authorization_url(state))


@v1.get(
    "/google/callback",
    dependencies=[Depends(rate_limit("login", "RATE_LIMIT_LOGIN_PER_MINUTE"))],
)
async def google_callback(code: str, request: Request, db: DbDep, state: str | None = None):
    _require_google()
    from mxtng_auth.google import UnverifiedGoogleEmail, exchange_code

    # Burn the nonce before spending an authorization code (SECURITY_AUDIT H-3).
    # Without this the callback accepted any code from anyone, which is login
    # CSRF in one direction and authorization-code injection in the other.
    await services.consume_oauth_state(db, state=state, ip=_client_ip(request))

    try:
        google_sub, email = await exchange_code(code)
    except UnverifiedGoogleEmail as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    credential = await services.upsert_google_credential(
        db, google_sub=google_sub, email=email, ip=_client_ip(request)
    )
    # Google proves the first factor; the Sign-in Code is still owed (ADR-0011).
    # The challenge id doubles as the browser hand-off the old exchange code used
    # to be — it is inert without the emailed code, so a redirect URL is safe.
    challenge = await services.start_challenge(
        db, credential=credential, audience=settings.DEFAULT_AUDIENCE, ip=_client_ip(request)
    )
    if settings.GOOGLE_POST_LOGIN_REDIRECT:
        sep = "&" if "?" in settings.GOOGLE_POST_LOGIN_REDIRECT else "?"
        return RedirectResponse(
            f"{settings.GOOGLE_POST_LOGIN_REDIRECT}{sep}challenge={challenge.challenge_id}"
        )
    return _challenge_response(challenge, credential.email)


# --- Admin (service-to-service identity mutations) --------------------------
async def _require_admin(x_admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None) -> None:
    """Gate the service-to-service identity mutations.

    An unset key closes the surface rather than opening it: these endpoints
    reassign a credential's email address, so "no key configured" must never
    mean "no key required" (SECURITY_AUDIT H-1).
    """
    expected = reveal(settings.ADMIN_API_KEY)
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin API is not configured.",
        )
    if not x_admin_key or not secrets.compare_digest(x_admin_key, expected):
        raise HTTPException(status_code=403, detail="Forbidden")


@admin.post("/credentials/{auth_user_id}/email", response_model=MessageResponse)
async def admin_change_email(
    auth_user_id: str,
    payload: EmailChange,
    db: DbDep,
    _: Annotated[None, Depends(_require_admin)],
) -> MessageResponse:
    credential = await services.get_by_auth_user_id(db, auth_user_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Not found")
    await services.change_email(db, credential=credential, new_email=payload.email)
    return MessageResponse(message="email changed")


@admin.post("/credentials/{auth_user_id}/disable", response_model=MessageResponse)
async def admin_disable(
    auth_user_id: str,
    db: DbDep,
    _: Annotated[None, Depends(_require_admin)],
) -> MessageResponse:
    credential = await services.get_by_auth_user_id(db, auth_user_id)
    if credential is None:
        raise HTTPException(status_code=404, detail="Not found")
    await services.disable_credential(db, credential=credential)
    return MessageResponse(message="account disabled")
