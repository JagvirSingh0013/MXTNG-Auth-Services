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


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load/generate the signing key up front so JWKS is available immediately.
    signer = get_signer()
    logger.info("Signing key ready (kid=%s)", getattr(signer, "kid", "?"))
    # Dev/test convenience; production provisions schema via migrations.
    if settings.ENVIRONMENT != "production":
        await init_models()
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="MXTNG Auth Service", version="0.1.0", lifespan=lifespan)
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
