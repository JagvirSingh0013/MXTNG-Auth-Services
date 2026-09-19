"""Runtime configuration. Token-contract fields must match each product's verifier.

Security note (SECURITY_AUDIT H-1): secrets deliberately have **no usable
defaults**. A service that boots on a published placeholder looks configured
while being wide open, so anything that protects a signature, a key, or an admin
surface is `None` until the environment supplies it, and `_enforce_secrets`
refuses to start outside development without it.
"""
from __future__ import annotations

from typing import Literal

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]

#: Placeholders that shipped in this repo's history. Rejected outside
#: development even if someone sets them explicitly — they are public knowledge.
_PUBLISHED_PLACEHOLDERS = frozenset(
    {
        "change-me-admin-key",
        "change-me-webhook-secret",
        "change-me-mail-relay-secret",
        "changeme",
        "secret",
    }
)


def reveal(value: SecretStr | None) -> str | None:
    """Unwrap a SecretStr for the one place that needs the raw bytes."""
    return value.get_secret_value() if value is not None else None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    #: Unknown values are a startup error rather than a silent downgrade to
    #: development behaviour — a typo'd "prod" must never unlock debug paths.
    ENVIRONMENT: Environment = "development"

    # --- Identity / token contract -----------------------------------------
    # ISSUER must equal the ATS backend's AUTH_ISSUER; DEFAULT_AUDIENCE its AUTH_AUDIENCE.
    ISSUER: str = "http://localhost:8100"
    DEFAULT_AUDIENCE: str = "ats"
    ALLOWED_AUDIENCES: list[str] = ["ats", "vms"]
    ACCESS_TOKEN_TTL_SECONDS: int = 5 * 60
    REFRESH_TOKEN_TTL_SECONDS: int = 30 * 24 * 3600

    # --- Signing key (RS256) -----------------------------------------------
    PRIVATE_KEY_PATH: str = "./signing_key.pem"
    PRIVATE_KEY_PEM: SecretStr | None = None
    KEY_ID: str | None = None

    # --- Database -----------------------------------------------------------
    DATABASE_URL: str = "sqlite+aiosqlite:///./auth.db"

    # --- Refresh cookie -----------------------------------------------------
    REFRESH_COOKIE_NAME: str = "mxtng_refresh"
    REFRESH_COOKIE_SECURE: bool = True
    REFRESH_COOKIE_DOMAIN: str | None = None
    REFRESH_COOKIE_PATH: str = "/v1/token"
    # "lax" only reaches the browser on a cross-origin refresh when the product and
    # this service share a registrable domain (app.mxtng.com -> auth.mxtng.com). A
    # product on an unrelated host (a *.vercel.app preview, say) is cross-site, and
    # a lax cookie is simply not sent — refresh 401s and the session dies with the
    # access token. Such a deployment must set "none", which browsers only honour
    # alongside Secure.
    REFRESH_COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"

    # --- Login hardening ----------------------------------------------------
    MAX_FAILED_LOGINS: int = 5
    LOGIN_LOCKOUT_SECONDS: int = 15 * 60
    RESET_TOKEN_TTL_SECONDS: int = 30 * 60

    # --- Request rate limiting (SECURITY_AUDIT M-1) -------------------------
    # Per-IP ceilings on the unauthenticated surface. The per-credential lockout
    # above stops one account being brute-forced; these stop one source spraying
    # every account, flooding a mailbox, or farming the introspection endpoint.
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 10
    RATE_LIMIT_SIGNUP_PER_MINUTE: int = 5
    RATE_LIMIT_RESET_PER_MINUTE: int = 3
    RATE_LIMIT_INTROSPECT_PER_MINUTE: int = 120

    # --- Session policy -----------------------------------------------------
    # One live session per credential: signing in anywhere revokes every other
    # session for that account, newest wins. Set False to allow concurrent
    # devices (the pre-existing behaviour).
    SINGLE_SESSION_PER_CREDENTIAL: bool = True

    # --- Sign-in challenge (emailed OTP, ADR-0011) --------------------------
    # The emailed code is the only proof that the person signing in controls the
    # mailbox, and mailbox control is what the ATS turns into agency membership
    # (SECURITY_AUDIT C-2). It is therefore mandatory and no longer switchable:
    # the legacy single-step /v1/login was removed rather than left behind a flag.
    OTP_CODE_LENGTH: int = 6
    OTP_TTL_SECONDS: int = 5 * 60
    # Per-challenge guesses. Deliberately equal to MAX_FAILED_LOGINS: a wrong code
    # increments the same counter, so both ceilings are one policy, not two.
    OTP_MAX_ATTEMPTS: int = 5
    OTP_RESEND_COOLDOWN_SECONDS: int = 60
    OTP_MAX_SENDS_PER_CHALLENGE: int = 3

    # --- Sign-in-with-Google (optional) ------------------------------------
    GOOGLE_CLIENT_ID: str | None = None
    GOOGLE_CLIENT_SECRET: SecretStr | None = None
    GOOGLE_REDIRECT_URI: str | None = None
    # Where the callback sends the browser with its ?challenge=; JSON in dev if unset.
    GOOGLE_POST_LOGIN_REDIRECT: str | None = None
    # How long an authorization request may stay open before its state expires
    # (SECURITY_AUDIT H-3). Single-use and server-side, so this is a ceiling on
    # how long a captured /start is worth anything, not a session length.
    OAUTH_STATE_TTL_SECONDS: int = 600

    # --- IdentityEvent webhooks --------------------------------------------
    WEBHOOK_ENDPOINTS: list[str] = []
    WEBHOOK_SECRET: SecretStr | None = None

    # --- Outbound mail ------------------------------------------------------
    # Primary path: the ATS platform-mail relay (ADR-0010's SMTP configuration).
    # Auth renders the whole message and the relay is dumb transport, so the
    # request is HMAC-signed and timestamped rather than bearing a bare key.
    MAIL_RELAY_URL: str | None = None
    MAIL_RELAY_SECRET: SecretStr | None = None
    MAIL_RELAY_TIMEOUT_SECONDS: float = 10.0

    # Break-glass path: used only when the relay is unreachable or reports no
    # active SMTP configuration. Without this a fresh environment cannot be
    # bootstrapped — configuring mail requires a login that requires mail.
    FALLBACK_SMTP_HOST: str | None = None
    FALLBACK_SMTP_PORT: int = 587
    FALLBACK_SMTP_USERNAME: str | None = None
    FALLBACK_SMTP_PASSWORD: SecretStr | None = None
    FALLBACK_SMTP_USE_TLS: bool = True
    FALLBACK_SMTP_TIMEOUT_SECONDS: float = 10.0
    MAIL_FROM_EMAIL: str = "no-reply@mxtng.local"
    MAIL_FROM_NAME: str = "MXTNG"
    # Product page that trades a reset token for a new password. Set per
    # environment (e.g. https://app.example.com/reset-password); when unset the
    # reset email falls back to showing the raw token instead of a link.
    PASSWORD_RESET_URL: str | None = None

    # Echoes a freshly minted reset token in the HTTP response so a developer can
    # complete the flow without a mailbox. Opt-in, never inferred from
    # ENVIRONMENT, and refused outright outside development (SECURITY_AUDIT M-10).
    DEBUG_ECHO_RESET_TOKENS: bool = False

    # --- Admin (service-to-service) ----------------------------------------
    ADMIN_API_KEY: SecretStr | None = None

    # --- HTTP hardening -----------------------------------------------------
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "https://ats-iota-five.vercel.app",
    ]
    #: Host header allow-list. "*" is refused in production by `_enforce_secrets`.
    TRUSTED_HOSTS: list[str] = ["*"]
    #: Only enable behind a proxy that overwrites X-Forwarded-For. Left off, the
    #: audit trail and the rate limiter key on the socket address instead of a
    #: header any client can set (SECURITY_AUDIT L-6).
    TRUST_PROXY_HEADERS: bool = False
    HSTS_MAX_AGE_SECONDS: int = 63_072_000

    # --- Derived ------------------------------------------------------------
    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_development(self) -> bool:
        """Development *or* the test harness: the two places debug paths may run."""
        return self.ENVIRONMENT in ("development", "test")

    @model_validator(mode="after")
    def _check_cookie_policy(self) -> "Settings":
        if self.REFRESH_COOKIE_SAMESITE == "none" and not self.REFRESH_COOKIE_SECURE:
            raise ValueError(
                "REFRESH_COOKIE_SAMESITE=none requires REFRESH_COOKIE_SECURE=true; "
                "browsers drop the cookie otherwise."
            )
        return self

    @model_validator(mode="after")
    def _enforce_secrets(self) -> "Settings":
        """Refuse to boot on missing or published secrets outside development.

        Starting is the dangerous option here: a service running on a placeholder
        HMAC key verifies signatures perfectly, against a secret anyone can read
        in this repository.
        """
        if self.is_development:
            return self

        missing: list[str] = []
        placeholder: list[str] = []

        def _require(name: str, value: SecretStr | None) -> None:
            raw = reveal(value)
            if not raw:
                missing.append(name)
            elif raw.strip().lower() in _PUBLISHED_PLACEHOLDERS:
                placeholder.append(name)

        _require("ADMIN_API_KEY", self.ADMIN_API_KEY)
        if self.MAIL_RELAY_URL:
            _require("MAIL_RELAY_SECRET", self.MAIL_RELAY_SECRET)
        if self.WEBHOOK_ENDPOINTS:
            _require("WEBHOOK_SECRET", self.WEBHOOK_SECRET)

        if not self.PRIVATE_KEY_PEM and not self.KEY_ID:
            # Not fatal on its own — a mounted PEM file is legitimate — but the
            # signer refuses to invent one outside development (see signer.py).
            pass

        problems: list[str] = []
        if missing:
            problems.append(f"not set: {', '.join(sorted(missing))}")
        if placeholder:
            problems.append(
                f"still set to a published placeholder: {', '.join(sorted(placeholder))}"
            )
        if self.DEBUG_ECHO_RESET_TOKENS:
            problems.append(
                "DEBUG_ECHO_RESET_TOKENS=true returns live password-reset tokens to "
                "anonymous callers and is refused outside development"
            )
        if "*" in self.TRUSTED_HOSTS:
            problems.append(
                'TRUSTED_HOSTS must name real hosts in production, not "*"'
            )
        if not self.REFRESH_COOKIE_SECURE:
            problems.append("REFRESH_COOKIE_SECURE must be true in production")

        if problems:
            raise ValueError(
                f"Refusing to start in ENVIRONMENT={self.ENVIRONMENT}: "
                + "; ".join(problems)
            )
        return self

    @property
    def google_enabled(self) -> bool:
        return bool(
            self.GOOGLE_CLIENT_ID and self.GOOGLE_CLIENT_SECRET and self.GOOGLE_REDIRECT_URI
        )

    @property
    def fallback_smtp_enabled(self) -> bool:
        return bool(self.FALLBACK_SMTP_HOST)


settings = Settings()
