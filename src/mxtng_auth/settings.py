"""Runtime configuration. Token-contract fields must match each product's verifier."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    ENVIRONMENT: str = "development"

    # --- Identity / token contract -----------------------------------------
    # ISSUER must equal the ATS backend's AUTH_ISSUER; DEFAULT_AUDIENCE its AUTH_AUDIENCE.
    ISSUER: str = "http://localhost:8100"
    DEFAULT_AUDIENCE: str = "ats"
    ALLOWED_AUDIENCES: list[str] = ["ats", "vms"]
    ACCESS_TOKEN_TTL_SECONDS: int = 5 * 60
    REFRESH_TOKEN_TTL_SECONDS: int = 30 * 24 * 3600

    # --- Signing key (RS256) -----------------------------------------------
    PRIVATE_KEY_PATH: str = "./signing_key.pem"
    PRIVATE_KEY_PEM: str | None = None
    KEY_ID: str | None = None

    # --- Database -----------------------------------------------------------
    DATABASE_URL: str = "sqlite+aiosqlite:///./auth.db"

    # --- Refresh cookie -----------------------------------------------------
    REFRESH_COOKIE_NAME: str = "mxtng_refresh"
    REFRESH_COOKIE_SECURE: bool = True
    REFRESH_COOKIE_DOMAIN: str | None = None
    REFRESH_COOKIE_PATH: str = "/v1/token"

    # --- Login hardening ----------------------------------------------------
    MAX_FAILED_LOGINS: int = 5
    LOGIN_LOCKOUT_SECONDS: int = 15 * 60
    RESET_TOKEN_TTL_SECONDS: int = 30 * 60

    # --- Session policy -----------------------------------------------------
    # One live session per credential: signing in anywhere revokes every other
    # session for that account, newest wins. Set False to allow concurrent
    # devices (the pre-existing behaviour).
    SINGLE_SESSION_PER_CREDENTIAL: bool = True

    # --- Sign-in challenge (emailed OTP, ADR-0011) --------------------------
    # False keeps legacy `/v1/login` issuing tokens directly so products can
    # migrate one at a time; flipping it to True closes that path for good.
    REQUIRE_OTP: bool = False
    OTP_CODE_LENGTH: int = 6
    OTP_TTL_SECONDS: int = 5 * 60
    # Per-challenge guesses. Deliberately equal to MAX_FAILED_LOGINS: a wrong code
    # increments the same counter, so both ceilings are one policy, not two.
    OTP_MAX_ATTEMPTS: int = 5
    OTP_RESEND_COOLDOWN_SECONDS: int = 60
    OTP_MAX_SENDS_PER_CHALLENGE: int = 3

    # --- Sign-in-with-Google (optional) ------------------------------------
    GOOGLE_CLIENT_ID: str | None = None
    GOOGLE_CLIENT_SECRET: str | None = None
    GOOGLE_REDIRECT_URI: str | None = None
    # Where the callback sends the browser with its ?challenge=; JSON in dev if unset.
    GOOGLE_POST_LOGIN_REDIRECT: str | None = None

    # --- IdentityEvent webhooks --------------------------------------------
    WEBHOOK_ENDPOINTS: list[str] = []
    WEBHOOK_SECRET: str = "change-me-webhook-secret"

    # --- Outbound mail ------------------------------------------------------
    # Primary path: the ATS platform-mail relay (ADR-0010's SMTP configuration).
    # Auth renders the whole message and the relay is dumb transport, so the
    # request is HMAC-signed and timestamped rather than bearing a bare key.
    MAIL_RELAY_URL: str | None = None
    MAIL_RELAY_SECRET: str = "change-me-mail-relay-secret"
    MAIL_RELAY_TIMEOUT_SECONDS: float = 10.0

    # Break-glass path: used only when the relay is unreachable or reports no
    # active SMTP configuration. Without this a fresh environment cannot be
    # bootstrapped — configuring mail requires a login that requires mail.
    FALLBACK_SMTP_HOST: str | None = None
    FALLBACK_SMTP_PORT: int = 587
    FALLBACK_SMTP_USERNAME: str | None = None
    FALLBACK_SMTP_PASSWORD: str | None = None
    FALLBACK_SMTP_USE_TLS: bool = True
    FALLBACK_SMTP_TIMEOUT_SECONDS: float = 10.0
    MAIL_FROM_EMAIL: str = "no-reply@mxtng.local"
    MAIL_FROM_NAME: str = "MXTNG"
    # Product page that trades a reset token for a new password.
    PASSWORD_RESET_URL: str | None = "http://localhost:3000/reset-password"

    # --- Admin (service-to-service) ----------------------------------------
    ADMIN_API_KEY: str = "change-me-admin-key"

    # --- CORS ---------------------------------------------------------------
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    @property
    def google_enabled(self) -> bool:
        return bool(
            self.GOOGLE_CLIENT_ID and self.GOOGLE_CLIENT_SECRET and self.GOOGLE_REDIRECT_URI
        )

    @property
    def fallback_smtp_enabled(self) -> bool:
        return bool(self.FALLBACK_SMTP_HOST)


settings = Settings()
