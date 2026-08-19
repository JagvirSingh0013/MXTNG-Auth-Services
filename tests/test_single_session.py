"""One session per account: newest device wins, older ones are ended.

These tests drive the real HTTP surface, because the guarantee is only worth
anything at the surface a product actually sees: the `sid` claim in the token and
the introspection endpoint that says whether it is still live.
"""
from jose import jwt

EMAIL = "solo@example.com"
PASSWORD = "correct horse battery"


async def _signup(client, email=EMAIL, password=PASSWORD):
    return await client.post("/v1/credentials", json={"email": email, "password": password})


async def _login(client, email=EMAIL, password=PASSWORD):
    response = await client.post("/v1/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response


def _refresh_cookie(response):
    for key, value in response.headers.multi_items():
        if key.lower() == "set-cookie" and value.startswith("mxtng_refresh="):
            return value.split(";")[0].split("=", 1)[1]
    return None


def _sid(token: str) -> str:
    return jwt.get_unverified_claims(token)["sid"]


async def _active(client, *session_ids) -> list[str]:
    response = await client.post(
        "/v1/sessions/introspect", json={"session_ids": list(session_ids)}
    )
    assert response.status_code == 200, response.text
    return response.json()["active"]


async def test_access_token_carries_a_session_id(client):
    await _signup(client)
    token = (await _login(client)).json()["access_token"]
    assert _sid(token)


async def test_second_sign_in_ends_the_first_session(client):
    await _signup(client)
    first = _sid((await _login(client)).json()["access_token"])
    assert await _active(client, first) == [first]

    second = _sid((await _login(client)).json()["access_token"])
    assert second != first

    # The whole point: the older device's token is still signed, unexpired and
    # perfectly valid — and no longer live.
    assert await _active(client, first, second) == [second]


async def test_evicted_session_cannot_refresh_its_way_back(client):
    await _signup(client)
    first_login = await _login(client)
    stale_refresh = _refresh_cookie(first_login)

    await _login(client)  # second device evicts the first

    replay = await client.post("/v1/token/refresh", cookies={"mxtng_refresh": stale_refresh})
    assert replay.status_code == 401


async def test_refreshing_does_not_evict_yourself(client):
    await _signup(client)
    login = await _login(client)
    session_id = _sid(login.json()["access_token"])

    refreshed = await client.post(
        "/v1/token/refresh", cookies={"mxtng_refresh": _refresh_cookie(login)}
    )
    assert refreshed.status_code == 200
    # Same session continues; a rotation is not a new sign-in.
    assert _sid(refreshed.json()["access_token"]) == session_id
    assert await _active(client, session_id) == [session_id]


async def test_sessions_are_per_account_not_global(client):
    await _signup(client)
    await _signup(client, email="other@example.com")

    mine = _sid((await _login(client)).json()["access_token"])
    theirs = _sid((await _login(client, email="other@example.com")).json()["access_token"])

    # Someone else signing in must never touch my session.
    assert sorted(await _active(client, mine, theirs)) == sorted([mine, theirs])


async def test_logout_ends_the_session(client):
    await _signup(client)
    login = await _login(client)
    session_id = _sid(login.json()["access_token"])

    logout = await client.post("/v1/logout", cookies={"mxtng_refresh": _refresh_cookie(login)})
    assert logout.status_code == 204
    assert await _active(client, session_id) == []


async def test_password_reset_ends_every_session(client):
    await _signup(client)
    session_id = _sid((await _login(client)).json()["access_token"])

    request = await client.post("/v1/password-reset/request", json={"email": EMAIL})
    assert request.status_code == 200
    # Outside production the endpoint echoes the raw token, for exactly this reason.
    message = request.json()["message"]
    assert message.startswith("reset_token="), message
    token = message.split("=", 1)[1]
    reset = await client.post(
        "/v1/password-reset/confirm",
        json={"token": token, "new_password": "a whole new passphrase"},
    )
    assert reset.status_code == 200
    assert await _active(client, session_id) == []


async def test_unknown_session_id_is_never_live(client):
    # A token minted before sessions existed carries no `sid`, and an id we never
    # issued is not ours. Both must read as dead, not as unknown-therefore-fine.
    assert await _active(client, "00000000-0000-0000-0000-000000000000") == []


async def test_a_pre_sessions_token_family_is_adopted_without_evicting_anyone(client):
    """The rollout case: refresh tokens issued before this feature have no session.

    Rotating one has to give it a session — but adopting a family is not a sign-in,
    and must not sign the user's current device out. Getting this backwards would
    log people out at the exact moment of the deploy.
    """
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select

    from mxtng_auth.db import AsyncSessionLocal
    from mxtng_auth.models import Credential, RefreshToken
    from mxtng_auth.security import hash_opaque_token

    await _signup(client)
    current = _sid((await _login(client)).json()["access_token"])

    # Forge the state a pre-upgrade deployment leaves behind: a live refresh token
    # with no session row behind it.
    legacy_raw = "legacy-refresh-token-value"
    async with AsyncSessionLocal() as db:
        credential = (
            await db.execute(select(Credential).where(Credential.email == EMAIL))
        ).scalar_one()
        db.add(
            RefreshToken(
                credential_id=credential.id,
                token_hash=hash_opaque_token(legacy_raw),
                audience="ats",
                expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            )
        )
        await db.commit()

    rotated = await client.post("/v1/token/refresh", cookies={"mxtng_refresh": legacy_raw})
    assert rotated.status_code == 200, rotated.text

    # The adopted family now has a session of its own...
    adopted = _sid(rotated.json()["access_token"])
    assert adopted != current

    # ...and the device that was already signed in is untouched.
    assert sorted(await _active(client, current, adopted)) == sorted([current, adopted])
