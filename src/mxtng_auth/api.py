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
    CredentialCreate,
    CredentialRead,
    EmailChange,
    GoogleAuthStart,
    GoogleExchangeRequest,
    LoginRequest,
    MessageResponse,
    PasswordResetConfirm,
    PasswordResetRequest,
    TokenResponse,
)
from mxtng_auth.settings import settings
from mxtng_auth.signer import get_signer

DbDep = Annotated[AsyncSession, Depends(get_db)]

public_router = APIRouter(tags=["public"])
v1 = APIRouter(prefix="/v1", tags=["auth"])
admin = APIRouter(prefix="/v1/admin", tags=["admin"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _set_refresh_cookie(response: Response, raw: str) -> None:
    response.set_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        value=raw,
        max_age=settings.REFRESH_TOKEN_TTL_SECONDS,
        httponly=True,
        secure=settings.REFRESH_COOKIE_SECURE,
        samesite="lax",
        path=settings.REFRESH_COOKIE_PATH,
        domain=settings.REFRESH_COOKIE_DOMAIN,
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.REFRESH_COOKIE_NAME,
        path=settings.REFRESH_COOKIE_PATH,
        domain=settings.REFRESH_COOKIE_DOMAIN,
    )


# --- Public: health + JWKS --------------------------------------------------
@public_router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@public_router.get("/.well-known/jwks.json")
async def jwks() -> dict:
    return get_signer().jwks()


# --- Signup (idempotent) ----------------------------------------------------
@v1.post("/credentials", response_model=CredentialRead, status_code=status.HTTP_201_CREATED)
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
@v1.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, request: Request, response: Response, db: DbDep) -> TokenResponse:
    credential = await services.authenticate(
        db, email=payload.email, password=payload.password, ip=_client_ip(request)
    )
    access_token, expires_in, refresh_raw = await services.issue_tokens(
        db, credential=credential, audience=payload.audience or ""
    )
    _set_refresh_cookie(response, refresh_raw)
    return TokenResponse(access_token=access_token, expires_in=expires_in)


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


# --- Password reset ---------------------------------------------------------
@v1.post("/password-reset/request", response_model=MessageResponse)
async def password_reset_request(
    payload: PasswordResetRequest, request: Request, db: DbDep
) -> MessageResponse:
    raw = await services.request_password_reset(
        db, email=payload.email, ip=_client_ip(request)
    )
    # Never reveal whether the email exists. In dev, surface the token to ease testing.
    if raw and settings.ENVIRONMENT != "production":
        return MessageResponse(message=f"reset_token={raw}")
    return MessageResponse(message="If that email exists, a reset link has been sent.")


@v1.post("/password-reset/confirm", response_model=MessageResponse)
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


@v1.get("/google/start", response_model=GoogleAuthStart)
async def google_start() -> GoogleAuthStart:
    _require_google()
    from mxtng_auth.google import build_authorization_url

    # NOTE: stateless CSRF nonce passthrough; a persistent state store is a follow-up.
    state = secrets.token_urlsafe(24)
    return GoogleAuthStart(authorization_url=build_authorization_url(state))


@v1.get("/google/callback")
async def google_callback(code: str, request: Request, db: DbDep, state: str | None = None):
    _require_google()
    from mxtng_auth.google import exchange_code

    google_sub, email = await exchange_code(code)
    credential = await services.upsert_google_credential(
        db, google_sub=google_sub, email=email, ip=_client_ip(request)
    )
    handoff = await services.create_oauth_exchange_code(
        db, credential=credential, audience=settings.DEFAULT_AUDIENCE
    )
    if settings.GOOGLE_POST_LOGIN_REDIRECT:
        sep = "&" if "?" in settings.GOOGLE_POST_LOGIN_REDIRECT else "?"
        return RedirectResponse(f"{settings.GOOGLE_POST_LOGIN_REDIRECT}{sep}code={handoff}")
    return {"code": handoff}


@v1.post("/google/exchange", response_model=TokenResponse)
async def google_exchange(
    payload: GoogleExchangeRequest, request: Request, response: Response, db: DbDep
) -> TokenResponse:
    access_token, expires_in, refresh_raw = await services.redeem_oauth_exchange_code(
        db, raw=payload.code, ip=_client_ip(request)
    )
    _set_refresh_cookie(response, refresh_raw)
    return TokenResponse(access_token=access_token, expires_in=expires_in)


# --- Admin (service-to-service identity mutations) --------------------------
async def _require_admin(x_admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None) -> None:
    if not x_admin_key or not secrets.compare_digest(x_admin_key, settings.ADMIN_API_KEY):
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
