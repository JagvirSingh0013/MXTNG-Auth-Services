"""Access-token minting. Claims are exactly what product verifiers require (ADR-0006).

The ATS verifier checks signature (RS256 via JWKS `kid`), `iss`, `aud`, `exp`,
and reads `sub` (global Auth User Id) + `email`. VMS does the same with its own
`aud`. Nothing product-specific is ever embedded here.
"""
from __future__ import annotations

import time

from mxtng_auth.settings import settings
from mxtng_auth.signer import get_signer


def mint_access_token(
    *, auth_user_id: str, email: str, audience: str, session_id: str | None = None
) -> tuple[str, int]:
    """Return (jwt, expires_in_seconds) for a short-lived access token.

    `sid` names the session this token belongs to. Verifiers that enforce a
    session policy check it against the auth service; verifiers that do not
    simply ignore it, so adding the claim breaks no existing product.
    """
    now = int(time.time())
    expires_in = settings.ACCESS_TOKEN_TTL_SECONDS
    claims = {
        "iss": settings.ISSUER,
        "sub": auth_user_id,
        "aud": [audience],
        "email": email,
        "token_use": "access",
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
    }
    if session_id:
        claims["sid"] = session_id
    return get_signer().sign(claims), expires_in


def resolve_audience(requested: str | None) -> str:
    """Clamp the requested audience to the allow-list; default to DEFAULT_AUDIENCE."""
    if requested and requested in settings.ALLOWED_AUDIENCES:
        return requested
    return settings.DEFAULT_AUDIENCE
