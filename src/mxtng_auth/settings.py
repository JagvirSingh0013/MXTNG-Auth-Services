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

    # --- Sign-in-with-Google (optional) ------------------------------------
    GOOGLE_CLIENT_ID: str | None = None
    GOOGLE_CLIENT_SECRET: str | None = None
    GOOGLE_REDIRECT_URI: str | None = None
    # Where the callback sends the browser with its one-time ?code=; JSON in dev if unset.
    GOOGLE_POST_LOGIN_REDIRECT: str | None = None
    OAUTH_EXCHANGE_CODE_TTL_SECONDS: int = 120

    # --- IdentityEvent webhooks --------------------------------------------
    WEBHOOK_ENDPOINTS: list[str] = []
    WEBHOOK_SECRET: str = "change-me-webhook-secret"

    # --- Admin (service-to-service) ----------------------------------------
    ADMIN_API_KEY: str = "change-me-admin-key"

    # --- ATS-Backend (service-to-service role lookup) -----------------------
    # Used at new-session login to check whether a credential is a recruiter,
    # so single-session enforcement can be role-scoped even though this
    # service is otherwise role-agnostic (ADR-0005).
    ATS_BACKEND_URL: str = "http://localhost:8000"
    INTERNAL_SERVICE_API_KEY: str = "change-me-internal-key"

    # --- CORS ---------------------------------------------------------------
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]

    @property
    def google_enabled(self) -> bool:
        return bool(
            self.GOOGLE_CLIENT_ID and self.GOOGLE_CLIENT_SECRET and self.GOOGLE_REDIRECT_URI
        )


settings = Settings()
