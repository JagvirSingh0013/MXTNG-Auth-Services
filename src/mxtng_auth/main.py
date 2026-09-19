"""FastAPI application: lifespan (signer + tables), routers, error mapping, CORS."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from mxtng_auth.api import admin, public_router, v1
from mxtng_auth.db import init_models
from mxtng_auth.services import AuthError
from mxtng_auth.settings import reveal, settings
from mxtng_auth.signer import get_signer

logger = logging.getLogger(__name__)

# Keep the production ATS web application reachable even if an older deployment
# omits it from CORS_ORIGINS. Additional product origins remain configurable via
# the environment variable.
#
# `dashboard.mxtng.com` is the canonical product origin and is listed here, not
# only in the default, because CORSMiddleware answers an unlisted Origin with no
# `Access-Control-Allow-Origin` at all: the browser reports that as a bare CORS
# failure, so a stale `CORS_ORIGINS` on the box takes sign-in down and says
# nothing about why. Only origins this product is known to serve from belong
# here: the list is credentialed, and a name that is allow-listed but no longer
# resolves anywhere is a subdomain-takeover foothold.
FALLBACK_CORS_ORIGINS = (
    "https://dashboard.mxtng.com",
    "https://ats-iota-five.vercel.app",
)


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
        # The Sign-in Code is now the only way in (SECURITY_AUDIT C-2), so a
        # service with no mail path cannot authenticate anyone. Every sign-in
        # would 502; starting up is worse than not starting.
        raise MailNotConfigured(
            "No mail path configured: set MAIL_RELAY_URL (the ATS platform-mail relay) "
            "or FALLBACK_SMTP_HOST. Without one, no Sign-in Code can be delivered and "
            "no one can sign in."
        )

    if not has_fallback:
        logger.warning(
            "No FALLBACK_SMTP_HOST configured. If the mail relay is unreachable or has "
            "no active SMTP configuration, sign-in fails for everyone and cannot be "
            "recovered without one (ADR-0011)."
        )

    if has_relay and not reveal(settings.MAIL_RELAY_SECRET):
        logger.error(
            "MAIL_RELAY_URL is set but MAIL_RELAY_SECRET is not. The ATS relay will "
            "reject every request, so no Sign-in Code will be delivered through it."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load/generate the signing key up front so JWKS is available immediately.
    signer = get_signer()
    logger.info("Signing key ready (kid=%s)", getattr(signer, "kid", "?"))
    check_mail_configuration()
    # Dev/test convenience; staging and production provision schema via migrations.
    if settings.is_development:
        await init_models()
    yield


def create_app() -> FastAPI:
    # Disable interactive API docs and the OpenAPI schema outside development —
    # they enumerate every route/schema and must not be publicly reachable. A
    # staging deployment is as reachable as production, so it is covered too.
    docs_enabled = settings.is_development
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

    # Reject Host headers this deployment does not answer for (SECURITY_AUDIT
    # L-5). Absolute URLs built from a forged Host end up in reset emails.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.TRUSTED_HOSTS)

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        """Baseline response headers. This service answers JSON only, so the
        XSS-adjacent headers are cheap insurance rather than load-bearing; HSTS
        is the one that matters, since every token here rides over TLS."""
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Cache-Control", "no-store")
        if settings.is_production:
            response.headers.setdefault(
                "Strict-Transport-Security",
                f"max-age={settings.HSTS_MAX_AGE_SECONDS}; includeSubDomains; preload",
            )
        return response

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
