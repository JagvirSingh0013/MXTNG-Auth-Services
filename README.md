# MXTNG Auth Service

A standalone, **product-generic identity provider**. It proves who a human is and
issues verifiable tokens — and knows nothing about agencies, roles, or referrals.
ATS and VMS both federate to it and do their own authorization locally.

Implements the identity ADRs from the ATS repo:
- **ADR-0005** — auth is a standalone identity provider (this repo).
- **ADR-0006** — identity is a JWKS-verifiable RS256 JWT keyed on an auth-minted UUID.
- **ADR-0007** — products provision accounts just-in-time; a credential is not an account.

## What it owns

Credentials (password + Sign-in-with-Google), the global **Auth User Id** (UUID),
email, RS256 signing + JWKS publication, refresh-token rotation, password reset,
login hardening (lockout + audit log), and `IdentityEvent` webhooks. It never
performs authorization.

## Token contract (what products verify)

- **RS256** JWT; header carries `kid`.
- Claims: `iss` (this service), `aud` (e.g. `["ats"]`), `sub` (UUID Auth User Id),
  `email`, `token_use=access`, `iat`/`nbf`/`exp`.
- **15-minute** access tokens; **30-day** rotating, single-use refresh tokens in an
  httpOnly cookie. Refresh reuse revokes the whole token family.
- Verify **offline** against `GET /.well-known/jwks.json` — no shared secret.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness |
| GET | `/.well-known/jwks.json` | Public keys for offline verification |
| POST | `/v1/credentials` | Sign up (idempotent via `Idempotency-Key` header) |
| POST | `/v1/login` | Password login → access token + refresh cookie |
| POST | `/v1/token/refresh` | Rotate refresh (cookie in → new access + cookie) |
| POST | `/v1/logout` | Revoke this refresh family |
| POST | `/v1/logout-all` | Revoke every refresh family for the user |
| POST | `/v1/password-reset/request` | Begin reset (no user enumeration) |
| POST | `/v1/password-reset/confirm` | Complete reset (revokes all sessions) |
| GET | `/v1/google/start` | Sign-in-with-Google authorization URL |
| GET | `/v1/google/callback` | Google redirect → one-time handoff code |
| POST | `/v1/google/exchange` | Trade handoff code for tokens |
| POST | `/v1/admin/credentials/{auth_user_id}/email` | Change email → `email.changed` event |
| POST | `/v1/admin/credentials/{auth_user_id}/disable` | Disable → `account.disabled` event |

Login/refresh/logout responses carry **identity only**. Products fetch their own
domain data (workspace, agency, role) from their own `/users/me`, never from here.

## Run locally

```bash
uv sync --extra dev            # or: pip install -e ".[dev]"
cp .env.example .env           # ISSUER/DEFAULT_AUDIENCE must match the product verifier
uv run uvicorn mxtng_auth.main:app --port 8100 --reload
uv run pytest                  # 6 flow tests incl. JWKS/product-verifier compat
```

In dev a 2048-bit RSA keypair is generated at `PRIVATE_KEY_PATH` and tables are
created on startup. In production inject `PRIVATE_KEY_PEM` from a secret manager
and provision the schema with migrations (below).

## Migrations (Alembic)

`ENVIRONMENT=production` skips the startup `create_all`; the schema is owned by
Alembic. The connection URL comes from `DATABASE_URL` (via app settings), so no
credentials live in `alembic.ini`.

```bash
uv run alembic upgrade head           # apply migrations
uv run alembic revision --autogenerate -m "describe change"   # after editing models.py
uv run alembic check                  # CI guard: fails if models drift from migrations
uv run alembic downgrade -1           # roll back one
```

The initial revision (`migrations/versions/*_initial_schema.py`) creates all five
tables; `models.py` remains the source of truth that autogenerate diffs against.

## Connecting the ATS backend

The ATS already verifies tokens (`core/jwks.py` + `auth_dependency.py`). Point its
four settings at this service:

| ATS setting | Value |
|-------------|-------|
| `AUTH_ISSUER` | this service's `ISSUER` |
| `AUTH_JWKS_URL` | `<this-service>/.well-known/jwks.json` |
| `AUTH_AUDIENCE` | `ats` (this service's `DEFAULT_AUDIENCE`) |
| `AUTH_JWKS_CACHE_TTL_SECONDS` | e.g. 600 |

Smoke test: `POST /v1/login` here → send the `access_token` as `Bearer` to any ATS
route → expect a JIT-provisioned user, not a 401.

VMS onboards the same way: point at this `ISSUER`/JWKS with its own `aud`.

## Production notes / follow-ups

- **Migrations**: Alembic is wired (`alembic upgrade head`); dev still uses
  `create_all` for convenience. `alembic check` guards against model drift in CI.
- **Google**: install the `google` extra and set `GOOGLE_*`; the callback uses a
  stateless CSRF nonce today — add a persistent `state` store to harden.
- **Signer**: `Signer` is the KMS seam; `LocalRSASigner` is the starting point.
  Multi-key JWKS (for rotation overlap) is a natural extension of `jwks()`.
- **Rate limiting**: per-account lockout is implemented; add an edge/IP limiter
  (e.g. at the gateway) for full ADR-0005 hardening.
