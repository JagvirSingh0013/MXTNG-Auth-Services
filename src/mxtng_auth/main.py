"""FastAPI application: lifespan (signer + tables), routers, error mapping, CORS."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from mxtng_auth.api import admin, public_router, v1
from mxtng_auth.db import init_models
from mxtng_auth.services import AuthError
from mxtng_auth.settings import settings
from mxtng_auth.signer import get_signer

logger = logging.getLogger(__name__)

# Keep the production ATS web application reachable even if an older deployment
# omits it from CORS_ORIGINS. Additional product origins remain configurable via
# the environment variable.
FALLBACK_CORS_ORIGINS = ("https://ats-iota-five.vercel.app",)


class MailNotConfigured(RuntimeError):
    """Startup refusal: OTP is mandatory but nothing can deliver a Sign-in Code."""


def check_mail_configuration() -> None:
    """Fail (or complain) at boot rather than on every user's sign-in.

    A service with no mail path starts perfectly happily and then 502s every
    single sign-in attempt — the failure surfaces as far as possible from its
    cause. One line in the deploy log is cheaper than that (ADR-0011).
    """
    has_relay = bool(settings.MAIL_RELAY_URL)
    has_fallback = settings.fallback_smtp_enabled

    if not has_relay and not has_fallback:
        message = (
            "No mail path configured: set MAIL_RELAY_URL (the ATS platform-mail relay) "
            "or FALLBACK_SMTP_HOST. Without one, no Sign-in Code can be delivered."
        )
        if settings.REQUIRE_OTP:
            # Every sign-in would 502. Starting up is worse than not starting.
            raise MailNotConfigured(message)
        logger.error("%s Legacy /v1/login still works while REQUIRE_OTP is false.", message)
        return

    if not has_fallback:
        logger.warning(
            "No FALLBACK_SMTP_HOST configured. If the mail relay is unreachable or has "
            "no active SMTP configuration, sign-in fails for everyone and cannot be "
            "recovered without one (ADR-0011)."
        )

    if has_relay and settings.MAIL_RELAY_SECRET == "change-me-mail-relay-secret":
        logger.error(
            "MAIL_RELAY_SECRET is still the published default. The ATS relay will "
            "reject these requests, or worse, accept anyone else's."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load/generate the signing key up front so JWKS is available immediately.
    signer = get_signer()
    logger.info("Signing key ready (kid=%s)", getattr(signer, "kid", "?"))
    check_mail_configuration()
    # Dev/test convenience; production provisions schema via migrations.
    if settings.ENVIRONMENT != "production":
        await init_models()
    yield


def create_app() -> FastAPI:
    # Disable interactive API docs and the OpenAPI schema in production — they
    # enumerate every route/schema and must not be publicly reachable there.
    docs_enabled = settings.ENVIRONMENT.lower() != "production"
    app = FastAPI(
        title="MXTNG Auth Service",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    cors_origins = list(dict.fromkeys((*settings.CORS_ORIGINS, *FALLBACK_CORS_ORIGINS)))

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(AuthError)
    async def _auth_error_handler(_request: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": str(exc), "code": exc.code},
        )

    app.include_router(public_router)
    app.include_router(v1)
    app.include_router(admin)
    return app


app = create_app()
