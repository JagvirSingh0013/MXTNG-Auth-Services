"""Sign-in-with-Google helpers (identity only — NOT mailbox/calendar connect).

ADR-0005 is explicit: Google *login* lives here; connecting a Google/Outlook
mailbox or calendar stays in the ATS as a product feature. These helpers only
establish identity (a verified Google `sub` + email).

Requires the `google` extra (`google-auth`) and GOOGLE_* settings; routes are
disabled when unconfigured.
"""
from __future__ import annotations

import urllib.parse

import httpx

from mxtng_auth.settings import reveal, settings


class UnverifiedGoogleEmail(ValueError):
    """The ID token carried an address Google has not confirmed."""


_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
_SCOPES = "openid email profile"


def build_authorization_url(state: str) -> str:
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": _SCOPES,
        "state": state,
        "access_type": "offline",
        "prompt": "select_account",
    }
    return f"{_AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"


async def exchange_code(code: str) -> tuple[str, str]:
    """Exchange an auth code for a verified (google_sub, email).

    The Google ID token's signature/issuer/audience are verified with
    `google-auth`; we never trust an unverified token.

    `email_verified` is checked as well (SECURITY_AUDIT H-2). Without it, an
    identity whose profile address merely *claims* to be a victim's is enough to
    be linked onto that victim's existing password credential — a signature-valid
    token proves Google issued it, not that Google confirmed the mailbox.
    """
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token as google_id_token
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "Google login requires the 'google' extra (pip install .[google])"
        ) from exc

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            _TOKEN_ENDPOINT,
            data={
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": reveal(settings.GOOGLE_CLIENT_SECRET),
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
        )
    resp.raise_for_status()
    raw_id_token = resp.json().get("id_token")
    if not raw_id_token:
        raise ValueError("Google token response had no id_token")

    claims = google_id_token.verify_oauth2_token(
        raw_id_token, google_requests.Request(), settings.GOOGLE_CLIENT_ID
    )
    email = claims.get("email")
    sub = claims.get("sub")
    if not email or not sub:
        raise ValueError("Google identity missing email/sub")
    _require_verified_email(claims)
    return sub, email


def _require_verified_email(claims: dict) -> None:
    """Refuse an address Google has not itself confirmed.

    A signature-valid ID token proves Google issued it, not that Google checked
    the mailbox. Without this, an identity whose profile address merely *claims*
    to be a victim's is enough to be linked onto that victim's existing password
    credential (SECURITY_AUDIT H-2).

    Google reports the claim as a bool on modern tokens and occasionally as the
    string "true" on older ones; anything else is "not confirmed".
    """
    verified = claims.get("email_verified")
    if verified is not True and str(verified).lower() != "true":
        raise UnverifiedGoogleEmail(
            "Google has not verified this account's email address, so it cannot "
            "be used to sign in or to claim an existing account."
        )
