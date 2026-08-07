"""End-to-end auth flow tests, plus a product-verifier compatibility check.

The headline test mints a token through /v1/login and verifies it exactly the way
the ATS backend does (jose RS256 against the published JWKS, checking iss/aud) —
proving the token contract is drop-in for the ATS.
"""
from jose import jwt

EMAIL = "rec@example.com"
PASSWORD = "correct horse battery"


async def _signup(client, email=EMAIL, password=PASSWORD, key=None):
    headers = {"Idempotency-Key": key} if key else {}
    return await client.post(
        "/v1/credentials", json={"email": email, "password": password}, headers=headers
    )


def _refresh_cookie(response):
    for key, value in response.headers.multi_items():
        if key.lower() == "set-cookie" and value.startswith("mxtng_refresh="):
            return value.split(";")[0].split("=", 1)[1]
    return None


# --- Token contract / JWKS compatibility with the ATS verifier ---------------
async def test_login_token_verifies_against_jwks_like_a_product(client):
    await _signup(client)
    login = await client.post("/v1/login", json={"email": EMAIL, "password": PASSWORD})
    assert login.status_code == 200
    token = login.json()["access_token"]

    jwks = (await client.get("/.well-known/jwks.json")).json()
    assert jwks["keys"] and jwks["keys"][0]["kid"]

    # Exactly how ATS core/jwks.py verifies: RS256, audience=ats, issuer=ISSUER.
    claims = jwt.decode(
        token,
        jwks,
        algorithms=["RS256"],
        audience="ats",
        issuer="http://localhost:8100",
    )
    assert claims["email"] == EMAIL
    assert claims["sub"]  # the global Auth User Id (a UUID)
    assert claims["token_use"] == "access"


# --- Idempotent signup (ADR-0007) -------------------------------------------
async def test_signup_is_idempotent_on_key_and_conflicts_on_email(client):
    first = await _signup(client, key="abc-123")
    assert first.status_code == 201
    uid = first.json()["auth_user_id"]

    replay = await _signup(client, key="abc-123")
    assert replay.status_code == 201
    assert replay.json()["auth_user_id"] == uid  # same UUID on retry

    conflict = await _signup(client, key="different-key")
    assert conflict.status_code == 409  # same email, new request => conflict


# --- Login hardening --------------------------------------------------------
async def test_repeated_bad_password_locks_account(client):
    await _signup(client)
    for _ in range(3):  # MAX_FAILED_LOGINS=3 in the test env
        bad = await client.post("/v1/login", json={"email": EMAIL, "password": "wrong"})
        assert bad.status_code == 401

    locked = await client.post("/v1/login", json={"email": EMAIL, "password": PASSWORD})
    assert locked.status_code == 429
    assert locked.json()["code"] == "account_locked"


# --- Refresh rotation + reuse-as-theft --------------------------------------
async def test_refresh_rotates_and_reuse_revokes_family(client):
    await _signup(client)
    login = await client.post("/v1/login", json={"email": EMAIL, "password": PASSWORD})
    old_refresh = _refresh_cookie(login)
    assert old_refresh

    client.cookies.clear()
    rotated = await client.post(
        "/v1/token/refresh", cookies={"mxtng_refresh": old_refresh}
    )
    assert rotated.status_code == 200
    new_refresh = _refresh_cookie(rotated)
    assert new_refresh and new_refresh != old_refresh

    # Replaying the consumed token is treated as theft -> 401.
    client.cookies.clear()
    reuse = await client.post("/v1/token/refresh", cookies={"mxtng_refresh": old_refresh})
    assert reuse.status_code == 401

    # ...and the whole family is now revoked, so the successor is dead too.
    client.cookies.clear()
    successor = await client.post("/v1/token/refresh", cookies={"mxtng_refresh": new_refresh})
    assert successor.status_code == 401


# --- Password reset ---------------------------------------------------------
async def test_password_reset_flow(client):
    await _signup(client)
    req = await client.post("/v1/password-reset/request", json={"email": EMAIL})
    assert req.status_code == 200
    # Dev surfaces the token as "reset_token=<raw>".
    reset_token = req.json()["message"].split("reset_token=", 1)[1]

    confirm = await client.post(
        "/v1/password-reset/confirm",
        json={"token": reset_token, "new_password": "a brand new secret"},
    )
    assert confirm.status_code == 200

    old = await client.post("/v1/login", json={"email": EMAIL, "password": PASSWORD})
    assert old.status_code == 401
    new = await client.post(
        "/v1/login", json={"email": EMAIL, "password": "a brand new secret"}
    )
    assert new.status_code == 200


# --- Health -----------------------------------------------------------------
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
